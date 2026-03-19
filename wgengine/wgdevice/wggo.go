// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_use_gotatun

package wgdevice

import (
	"io"
	"sync/atomic"
	"time"
	"unsafe"

	"reflect"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// Peer offset computation for unsafe access to wireguard-go internals.
// This mirrors the logic from wgint, but is colocated with the device
// abstraction so that the wgint package can be removed once gotatun is
// the sole backend.
var (
	offHandshake         = getPeerStatsOffset("lastHandshakeNano")
	offRxBytes           = getPeerStatsOffset("rxBytes")
	offTxBytes           = getPeerStatsOffset("txBytes")
	offHandshakeAttempts = getPeerHandshakeAttemptsOffset()
)

func getPeerStatsOffset(name string) uintptr {
	peerType := reflect.TypeFor[device.Peer]()
	field, ok := peerType.FieldByName(name)
	if !ok {
		panic("no " + name + " field in device.Peer")
	}
	if s := field.Type.String(); s != "atomic.Int64" && s != "atomic.Uint64" {
		panic("unexpected type " + s + " of field " + name + " in device.Peer")
	}
	return field.Offset
}

func getPeerHandshakeAttemptsOffset() uintptr {
	peerType := reflect.TypeFor[device.Peer]()
	field, ok := peerType.FieldByName("timers")
	if !ok {
		panic("no timers field in device.Peer")
	}
	field2, ok := field.Type.FieldByName("handshakeAttempts")
	if !ok {
		panic("no handshakeAttempts field in device.Peer.timers")
	}
	if g, w := field2.Type.String(), "atomic.Uint32"; g != w {
		panic("unexpected type " + g + " of field handshakeAttempts in device.Peer.timers; want " + w)
	}
	return field.Offset + field2.Offset
}

// WireGuardGoDevice wraps wireguard-go's *device.Device to implement Device.
type WireGuardGoDevice struct {
	dev *device.Device
}

// NewWireGuardGoDevice creates a WireGuard device using the wireguard-go
// implementation, configured for Tailscale use.
func NewWireGuardGoDevice(tunDev tun.Device, bind conn.Bind, logger *device.Logger) *WireGuardGoDevice {
	ret := device.NewDevice(tunDev, bind, logger)
	ret.DisableSomeRoamingForBrokenMobileSemantics()
	return &WireGuardGoDevice{dev: ret}
}

func (d *WireGuardGoDevice) Up() error                   { return d.dev.Up() }
func (d *WireGuardGoDevice) Close()                      { d.dev.Close() }
func (d *WireGuardGoDevice) Wait() <-chan struct{}        { return d.dev.Wait() }
func (d *WireGuardGoDevice) IpcGetOperation(w io.Writer) error { return d.dev.IpcGetOperation(w) }
func (d *WireGuardGoDevice) IpcSetOperation(r io.Reader) error { return d.dev.IpcSetOperation(r) }
func (d *WireGuardGoDevice) DisableSomeRoamingForBrokenMobileSemantics() {
	d.dev.DisableSomeRoamingForBrokenMobileSemantics()
}

func (d *WireGuardGoDevice) LookupPeer(pubkey key.NodePublic) PeerHandle {
	peer := d.dev.LookupPeer(pubkey.Raw32())
	if peer == nil {
		return nil
	}
	return &wgGoPeer{p: peer}
}

// wgGoPeer implements PeerHandle by using unsafe offset-based access to
// wireguard-go's device.Peer struct fields, matching the approach used
// by wgint.
type wgGoPeer struct {
	p *device.Peer
}

func (p *wgGoPeer) IsValid() bool { return p.p != nil }

func (p *wgGoPeer) LastHandshake() time.Time {
	n := (*atomic.Int64)(unsafe.Add(unsafe.Pointer(p.p), offHandshake)).Load()
	if n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

func (p *wgGoPeer) TxBytes() uint64 {
	return (*atomic.Uint64)(unsafe.Add(unsafe.Pointer(p.p), offTxBytes)).Load()
}

func (p *wgGoPeer) RxBytes() uint64 {
	return (*atomic.Uint64)(unsafe.Add(unsafe.Pointer(p.p), offRxBytes)).Load()
}

func (p *wgGoPeer) HandshakeAttempts() uint32 {
	return (*atomic.Uint32)(unsafe.Add(unsafe.Pointer(p.p), offHandshakeAttempts)).Load()
}

// NewDevice creates a Device using the wireguard-go backend.
// This is the default path when ts_use_gotatun is not set.
func NewDevice(tunDev tun.Device, bind conn.Bind, logf logger.Logf) Device {
	wgLogger := &device.Logger{
		Verbosef: logger.WithPrefix(logf, "wg: [v2] "),
		Errorf:   logger.WithPrefix(logf, "wg: "),
	}
	return NewWireGuardGoDevice(tunDev, bind, wgLogger)
}
