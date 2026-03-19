// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//! Transport adapters for gotatun.
//!
//! This module provides the bridge between gotatun's transport traits and
//! the Go callbacks for TUN and UDP I/O. gotatun expects implementations
//! of its DeviceTransports trait; we implement them by calling back into
//! Go via the FFI callback function pointers.

// This module will be populated when we integrate with gotatun's actual
// DeviceTransports trait. For now it serves as the placeholder for the
// transport layer that bridges Go's tstun.Wrapper and magicsock with
// gotatun's async I/O.
//
// The architecture is:
//
//   Go (tstun.Wrapper)  <--callbacks-->  Rust (CgoTunTransport)
//         |                                     |
//   Go (magicsock)      <--callbacks-->  Rust (CgoUdpTransport)
//         |                                     |
//         v                                     v
//   OS TUN device                        gotatun WireGuard engine
//
// Key considerations:
// - Callbacks cross the FFI boundary, so we minimize allocations
// - We use raw byte buffers to avoid copying
// - Error handling uses integer return codes (Go convention)
