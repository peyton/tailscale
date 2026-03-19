// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"time"

	"tailscale.com/version"
)

// Power-saving constants for adaptive keepalive intervals.
//
// POWER OPTIMIZATION: Adaptive keepalive reduces unnecessary network
// wake-ups when the tunnel is idle. WireGuard uses persistent keepalive
// packets to maintain NAT mappings. On mobile devices (especially iOS),
// each keepalive packet wakes the network extension from its idle state,
// consuming CPU and radio power.
//
// The standard WireGuard keepalive interval is 25 seconds, which means
// ~2.4 wake-ups per minute even when no user traffic flows. By extending
// the interval during idle periods, we reduce wake-ups significantly:
//
//   - Active: 25s keepalive (standard, no change)
//   - Idle (>2min): 55s keepalive (~56% fewer wake-ups)
//
// The 55-second idle keepalive is chosen to stay under the typical 60-second
// NAT timeout used by most cellular carriers and home routers, while still
// providing substantial power savings. This is conservative — most NATs
// allow 60-120s, but we leave a 5-second safety margin.
const (
	// keepaliveActive is the standard WireGuard persistent keepalive interval
	// used when there is active tunnel traffic.
	keepaliveActive = 25 * time.Second

	// keepaliveIdle is the extended keepalive interval used on mobile when
	// the tunnel has been idle for longer than keepaliveIdleThreshold.
	keepaliveIdle = 55 * time.Second

	// keepaliveIdleThreshold is how long the tunnel must be idle before
	// we switch to the longer keepalive interval.
	keepaliveIdleThreshold = 2 * time.Minute
)

// adaptiveKeepalive returns the appropriate keepalive interval based on
// current tunnel activity. On non-mobile platforms, it always returns the
// standard interval.
func adaptiveKeepalive(idleDuration time.Duration) time.Duration {
	if !version.IsMobile() {
		return keepaliveActive
	}
	if idleDuration > keepaliveIdleThreshold {
		return keepaliveIdle
	}
	return keepaliveActive
}
