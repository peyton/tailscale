// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_use_gotatun

package wgengine

import (
	"github.com/tailscale/wireguard-go/device"

	"tailscale.com/wgengine/wgdevice"
	"tailscale.com/wgengine/wglog"
)

// createWireGuardDevice creates a WireGuard device using the wireguard-go
// backend. This is the default path.
func createWireGuardDevice(e *userspaceEngine, wgLogger *wglog.Logger) wgdevice.Device {
	e.logf("Creating wireguard-go WireGuard device...")
	return wgdevice.NewWireGuardGoDevice(e.tundev, e.magicConn.Bind(), wgLogger.DeviceLogger)
}

// setIOSQueueSizes applies iOS-specific queue size limits for wireguard-go.
// Called from mem_ios.go init().
func setIOSQueueSizes() {
	device.QueueStagedSize = 64
	device.QueueOutboundSize = 64
	device.QueueInboundSize = 64
	device.QueueHandshakeSize = 64
	device.PreallocatedBuffersPerPool = 64
}
