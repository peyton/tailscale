// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_use_gotatun

package wgdevice

import (
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/key"
)

// This file contains comparative benchmarks for WireGuard device
// implementations. By default, it benchmarks wireguard-go (the default
// backend). When built with -tags ts_use_gotatun, the same benchmarks
// run against the gotatun (Rust) backend, allowing direct comparison
// via:
//
//   go test -bench=. -count=5 ./wgengine/wgdevice/
//   go test -bench=. -count=5 -tags ts_use_gotatun ./wgengine/wgdevice/
//
// Then compare results with benchstat:
//
//   benchstat wireguardgo.txt gotatun.txt

// BenchmarkDeviceCreate measures the time to create and destroy a
// WireGuard device. This is relevant for app startup time on mobile.
func BenchmarkDeviceCreate(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		dev := NewWireGuardGoDevice(newBenchTun(), new(noopBind), device.NewLogger(device.LogLevelSilent, ""))
		dev.Close()
	}
}

// BenchmarkIpcSetGet measures the time to configure and read back a
// device configuration via the UAPI protocol. This exercises the config
// path that runs on every WireGuard reconfig.
func BenchmarkIpcSetGet(b *testing.B) {
	dev := NewWireGuardGoDevice(newBenchTun(), new(noopBind), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	pk := key.NewNode()
	peer := key.NewNode()
	config := "private_key=" + pk.UntypedHexString() + "\n" +
		"public_key=" + peer.Public().UntypedHexString() + "\n" +
		"allowed_ip=10.0.0.1/32\n\n"

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		dev.IpcSetOperation(strings.NewReader(config))
		dev.IpcGetOperation(io.Discard)
	}
}

// BenchmarkDeviceIdle measures allocations during idle operation. This is
// critical for mobile power consumption — GC pressure from a WireGuard
// device sitting idle directly translates to CPU wake-ups and battery drain.
func BenchmarkDeviceIdle(b *testing.B) {
	dev := NewWireGuardGoDevice(newBenchTun(), new(noopBind), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	pk := key.NewNode()
	peer := key.NewNode()
	config := "private_key=" + pk.UntypedHexString() + "\n" +
		"public_key=" + peer.Public().UntypedHexString() + "\n" +
		"allowed_ip=10.0.0.1/32\n\n"
	dev.IpcSetOperation(strings.NewReader(config))

	// Measure allocations during idle
	runtime.GC()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		// Simulate idle: just query stats
		dev.LookupPeer(peer.Public())
	}
}

// BenchmarkPeerLookup measures the time to look up peer statistics.
// This is called frequently by the engine for status reporting.
func BenchmarkPeerLookup(b *testing.B) {
	dev := NewWireGuardGoDevice(newBenchTun(), new(noopBind), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	pk := key.NewNode()
	peer := key.NewNode()
	config := "private_key=" + pk.UntypedHexString() + "\n" +
		"public_key=" + peer.Public().UntypedHexString() + "\n" +
		"allowed_ip=10.0.0.1/32\n\n"
	dev.IpcSetOperation(strings.NewReader(config))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		p := dev.LookupPeer(peer.Public())
		if p == nil {
			b.Fatal("peer not found")
		}
		_ = p.TxBytes()
		_ = p.RxBytes()
		_ = p.LastHandshake()
		_ = p.HandshakeAttempts()
	}
}

// benchTun is a minimal TUN device for benchmarking.
type benchTun struct {
	events chan tun.Event
	closed chan struct{}
}

func newBenchTun() tun.Device {
	return &benchTun{
		events: make(chan tun.Event),
		closed: make(chan struct{}),
	}
}

func (t *benchTun) File() *os.File           { return nil }
func (t *benchTun) Flush() error             { return nil }
func (t *benchTun) MTU() (int, error)        { return 1420, nil }
func (t *benchTun) Name() (string, error)    { return "benchtun", nil }
func (t *benchTun) Events() <-chan tun.Event { return t.events }
func (t *benchTun) BatchSize() int           { return 1 }

func (t *benchTun) Read(data [][]byte, sizes []int, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *benchTun) Write(data [][]byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *benchTun) Close() error {
	close(t.events)
	close(t.closed)
	return nil
}

// noopBind is a conn.Bind that does nothing.
type noopBind struct{}

func (noopBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return nil, 1, nil
}
func (noopBind) Close() error                                        { return nil }
func (noopBind) SetMark(mark uint32) error                           { return nil }
func (noopBind) Send(b [][]byte, ep conn.Endpoint, offset int) error { return nil }
func (noopBind) ParseEndpoint(s string) (conn.Endpoint, error)       { return nil, nil }
func (noopBind) BatchSize() int                                      { return 1 }
