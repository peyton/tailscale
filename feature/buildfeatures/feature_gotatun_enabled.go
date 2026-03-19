// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_use_gotatun

package buildfeatures

// HasGotatun is whether the binary was built with the gotatun (Rust) WireGuard
// implementation. Specifically, it's whether the binary was built with the
// "ts_use_gotatun" build tag. It's a const so it can be used for dead code
// elimination.
const HasGotatun = true
