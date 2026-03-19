// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wgdevice defines an interface that abstracts over WireGuard device
// implementations (wireguard-go and gotatun). This allows the engine to use
// either implementation, selected at build time via the ts_use_gotatun build tag.
package wgdevice

import (
	"io"
	"time"

	"tailscale.com/types/key"
)

// Device abstracts a WireGuard device implementation.
//
// Two implementations exist:
//   - WireGuardGoDevice wraps wireguard-go's *device.Device (default)
//   - GotatunDevice wraps gotatun's Rust FFI (build tag: ts_use_gotatun)
type Device interface {
	// Up brings the WireGuard device up.
	Up() error

	// Close shuts down the WireGuard device.
	Close()

	// Wait returns a channel that is closed when the device is done.
	Wait() <-chan struct{}

	// IpcGetOperation writes the current device configuration in UAPI
	// format to w.
	IpcGetOperation(w io.Writer) error

	// IpcSetOperation reads a UAPI configuration from r and applies it.
	IpcSetOperation(r io.Reader) error

	// LookupPeer returns the PeerStats for the given public key, or nil
	// if the peer is not found.
	LookupPeer(pubkey key.NodePublic) PeerHandle

	// DisableSomeRoamingForBrokenMobileSemantics disables roaming
	// behaviors that cause issues on mobile platforms.
	DisableSomeRoamingForBrokenMobileSemantics()
}

// PeerHandle provides access to peer statistics from a WireGuard device.
// For wireguard-go, this wraps the unsafe pointer access in wgint.
// For gotatun, this queries stats via the FFI.
type PeerHandle interface {
	// IsValid reports whether this handle points to a valid peer.
	IsValid() bool

	// LastHandshake returns the time of the last completed handshake.
	// Returns the zero value if no handshake has completed.
	LastHandshake() time.Time

	// TxBytes returns the number of bytes sent to this peer.
	TxBytes() uint64

	// RxBytes returns the number of bytes received from this peer.
	RxBytes() uint64

	// HandshakeAttempts returns the number of handshake attempts for the
	// current handshake. Resets to zero on success.
	HandshakeAttempts() uint32
}
