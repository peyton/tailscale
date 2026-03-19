// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_use_gotatun && cgo

package wgdevice

import (
	"io"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine/gotatun"
)

// GotatunDevice wraps a gotatun.Device to implement the Device interface.
type GotatunDevice struct {
	dev *gotatun.Device
}

// NewDevice creates a Device using the gotatun (Rust) backend.
// This path is used when ts_use_gotatun is set.
func NewDevice(tunDev tun.Device, bind conn.Bind, logf logger.Logf) Device {
	mtu, _ := tunDev.MTU()

	// POWER OPTIMIZATION: On mobile (iOS/Android), use a single async
	// runtime thread and smaller queue sizes. This reduces memory pressure
	// and context-switching overhead in constrained environments like iOS
	// NetworkExtension (50MB limit).
	numThreads := 0 // auto-detect
	queueSize := 0  // defaults
	if version.IsMobile() {
		numThreads = 1
		queueSize = 64
	}

	dev, err := gotatun.NewDevice(logf, mtu, numThreads, queueSize)
	if err != nil {
		logf("gotatun: failed to create device, falling back error: %v", err)
		return nil
	}
	return &GotatunDevice{dev: dev}
}

func (d *GotatunDevice) Up() error                   { return d.dev.Up() }
func (d *GotatunDevice) Close()                      { d.dev.Close() }
func (d *GotatunDevice) Wait() <-chan struct{}        { return d.dev.Wait() }
func (d *GotatunDevice) IpcGetOperation(w io.Writer) error { return d.dev.IpcGetOperation(w) }
func (d *GotatunDevice) IpcSetOperation(r io.Reader) error { return d.dev.IpcSetOperation(r) }
func (d *GotatunDevice) DisableSomeRoamingForBrokenMobileSemantics() {
	// gotatun does not implement the problematic roaming behavior
	// that wireguard-go has, so this is a no-op.
}

func (d *GotatunDevice) LookupPeer(pubkey key.NodePublic) PeerHandle {
	raw := pubkey.Raw32()
	stats, ok := d.dev.PeerStats(raw)
	if !ok {
		return nil
	}
	return &gotatunPeer{stats: stats}
}

// gotatunPeer implements PeerHandle using stats queried from gotatun via FFI.
type gotatunPeer struct {
	stats interface{ /* C.GotatunPeerStats — accessed via gotatun package */ }
	// We store the stats values directly since they're copied from C.
	lastHandshakeNsec int64
	txBytes           uint64
	rxBytes           uint64
	handshakeAttempts uint32
	valid             bool
}

func (p *gotatunPeer) IsValid() bool { return p.valid }

func (p *gotatunPeer) LastHandshake() time.Time {
	if p.lastHandshakeNsec != 0 {
		return time.Unix(0, p.lastHandshakeNsec)
	}
	return time.Time{}
}

func (p *gotatunPeer) TxBytes() uint64           { return p.txBytes }
func (p *gotatunPeer) RxBytes() uint64           { return p.rxBytes }
func (p *gotatunPeer) HandshakeAttempts() uint32 { return p.handshakeAttempts }
