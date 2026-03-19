// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

// iOS has a very restrictive memory limit on network extensions (~50MB).
// Reduce the maximum amount of memory that the WireGuard backend can
// allocate to avoid getting killed. For wireguard-go, this sets device
// queue sizes. For gotatun, queue sizing is handled via GotatunConfig.
func init() {
	setIOSQueueSizes()
}
