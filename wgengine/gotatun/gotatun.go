// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_use_gotatun && cgo

// Package gotatun provides Go bindings to the gotatun Rust WireGuard
// implementation via CGo FFI. This is used as an alternative to wireguard-go
// when built with the ts_use_gotatun build tag.
//
// The package uses callback-based I/O: gotatun calls back into Go for
// TUN device reads/writes (via tstun.Wrapper) and UDP socket operations
// (via magicsock). This allows gotatun to handle only the WireGuard
// protocol (encryption, handshakes, timers) while Tailscale retains
// control of networking and device management.
package gotatun

/*
#cgo LDFLAGS: -L${SRCDIR}/rust/target/release -lgotatun_ffi -ldl -lm -lpthread
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#include "rust/gotatun_ffi.h"
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"sync"
	"unsafe"

	"tailscale.com/types/logger"
)

// Device wraps a gotatun WireGuard device.
type Device struct {
	dev    *C.GotatunDevice
	logf   logger.Logf
	mu     sync.Mutex
	closed bool

	// waitCh is closed when the device is done.
	waitCh chan struct{}
}

// callbackRegistry maps opaque context pointers back to Go objects.
// This is necessary because CGo cannot pass Go pointers to C directly
// in all cases (cgo pointer passing rules).
var (
	callbackMu  sync.Mutex
	callbackMap = make(map[uintptr]*callbackState)
	callbackSeq uintptr
)

type callbackState struct {
	logf logger.Logf
	// tunRead/tunWrite and udpSend/udpRecv would be set when
	// integrating with tstun.Wrapper and magicsock.
}

func registerCallback(cs *callbackState) uintptr {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	callbackSeq++
	id := callbackSeq
	callbackMap[id] = cs
	return id
}

func unregisterCallback(id uintptr) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	delete(callbackMap, id)
}

func lookupCallback(id uintptr) *callbackState {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	return callbackMap[id]
}

// NewDevice creates a new gotatun WireGuard device.
//
// The mtu parameter sets the tunnel MTU. numThreads controls the number of
// async runtime threads (0 = auto, 1 recommended for iOS). queueSize
// controls packet buffer sizes (0 = default, 64 recommended for iOS).
func NewDevice(logf logger.Logf, mtu, numThreads, queueSize int) (*Device, error) {
	cs := &callbackState{logf: logf}
	cbID := registerCallback(cs)

	config := C.GotatunConfig{
		tun_read:    C.GotatunTunReadFn(C.gotatun_tun_read_cb),
		tun_write:   C.GotatunTunWriteFn(C.gotatun_tun_write_cb),
		tun_ctx:     unsafe.Pointer(cbID),
		udp_send:    C.GotatunUdpSendFn(C.gotatun_udp_send_cb),
		udp_recv:    C.GotatunUdpRecvFn(C.gotatun_udp_recv_cb),
		udp_ctx:     unsafe.Pointer(cbID),
		log_fn:      C.GotatunLogFn(C.gotatun_log_cb),
		log_ctx:     unsafe.Pointer(cbID),
		mtu:         C.int32_t(mtu),
		num_threads: C.int32_t(numThreads),
		queue_size:  C.int32_t(queueSize),
	}

	dev := C.gotatun_device_new(&config)
	if dev == nil {
		unregisterCallback(cbID)
		return nil, fmt.Errorf("gotatun: failed to create device")
	}

	d := &Device{
		dev:    dev,
		logf:   logf,
		waitCh: make(chan struct{}),
	}

	// Monitor the wait fd in a goroutine
	waitFd := C.gotatun_device_wait_fd(dev)
	if waitFd >= 0 {
		go d.monitorWaitFd(int(waitFd))
	}

	runtime.SetFinalizer(d, (*Device).Close)
	return d, nil
}

func (d *Device) monitorWaitFd(fd int) {
	// Block until the fd becomes readable (device shutdown)
	buf := make([]byte, 1)
	for {
		// Use a simple read; will return when device closes
		n, _ := readFd(fd, buf)
		if n > 0 {
			break
		}
	}
	close(d.waitCh)
}

// Up brings the WireGuard device up.
func (d *Device) Up() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return fmt.Errorf("gotatun: device closed")
	}
	ret := C.gotatun_device_up(d.dev)
	if ret != 0 {
		return fmt.Errorf("gotatun: device up failed: %d", ret)
	}
	return nil
}

// Close shuts down the WireGuard device and frees all resources.
func (d *Device) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	dev := d.dev
	d.dev = nil
	d.mu.Unlock()

	if dev != nil {
		C.gotatun_device_close(dev)
	}
	runtime.SetFinalizer(d, nil)
}

// Wait returns a channel that is closed when the device shuts down.
func (d *Device) Wait() <-chan struct{} {
	return d.waitCh
}

// IpcGetOperation writes the current device config in UAPI format to w.
func (d *Device) IpcGetOperation(w io.Writer) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return fmt.Errorf("gotatun: device closed")
	}
	dev := d.dev
	d.mu.Unlock()

	// Start with a reasonable buffer size
	bufSize := 4096
	for {
		buf := make([]byte, bufSize)
		ret := C.gotatun_ipc_get(dev, (*C.char)(unsafe.Pointer(&buf[0])), C.int32_t(bufSize))
		if ret < 0 {
			return fmt.Errorf("gotatun: ipc_get failed: %d", ret)
		}
		if int(ret) > bufSize {
			// Buffer too small, retry with the required size
			bufSize = int(ret)
			continue
		}
		_, err := w.Write(buf[:int(ret)])
		return err
	}
}

// IpcSetOperation reads UAPI configuration from r and applies it.
func (d *Device) IpcSetOperation(r io.Reader) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return fmt.Errorf("gotatun: device closed")
	}
	dev := d.dev
	d.mu.Unlock()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return fmt.Errorf("gotatun: reading config: %w", err)
	}

	config := buf.String()
	cstr := C.CString(config)
	defer C.free(unsafe.Pointer(cstr))

	ret := C.gotatun_ipc_set(dev, cstr, C.int32_t(len(config)))
	if ret != 0 {
		return fmt.Errorf("gotatun: ipc_set failed: %d", ret)
	}
	return nil
}

// PeerStats returns statistics for the given peer public key.
func (d *Device) PeerStats(pubkey [32]byte) (stats C.GotatunPeerStats, ok bool) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return stats, false
	}
	dev := d.dev
	d.mu.Unlock()

	ret := C.gotatun_peer_stats(dev, (*C.uint8_t)(unsafe.Pointer(&pubkey[0])), &stats)
	return stats, ret == 0
}

// readFd is a helper to read from a file descriptor.
func readFd(fd int, buf []byte) (int, error) {
	// Use syscall read
	n := C.read(C.int(fd), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if n < 0 {
		return 0, fmt.Errorf("read error")
	}
	return int(n), nil
}

// SetLogLevel sets the minimum log level for the Rust side.
func SetLogLevel(level int) {
	C.gotatun_set_log_level(C.int32_t(level))
}
