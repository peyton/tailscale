// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_use_gotatun && cgo

package wgengine

import (
	"tailscale.com/wgengine/wgdevice"
	"tailscale.com/wgengine/wglog"
)

// createWireGuardDevice creates a WireGuard device using the gotatun (Rust)
// backend. This path is used when the ts_use_gotatun build tag is set.
func createWireGuardDevice(e *userspaceEngine, wgLogger *wglog.Logger) wgdevice.Device {
	e.logf("Creating gotatun (Rust) WireGuard device...")
	return wgdevice.NewDevice(e.tundev, e.magicConn.Bind(), e.logf)
}

// setIOSQueueSizes is a no-op for gotatun; queue sizes are configured
// via GotatunConfig.queue_size in the FFI layer.
func setIOSQueueSizes() {
	// gotatun handles its own queue sizing via GotatunConfig.
}
