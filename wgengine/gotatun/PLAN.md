# gotatun: Rust WireGuard Replacement for Tailscale

## Executive Summary

Replace wireguard-go with [gotatun](https://github.com/mullvad/gotatun), a Rust
WireGuard implementation, as the WireGuard backend for Tailscale. The primary
goals are improved power efficiency on mobile (iOS/Android), better performance
through Rust's zero-cost abstractions, and a path toward eliminating unsafe
pointer-based peer stat access in wireguard-go.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Tailscale Go code (wgengine, magicsock, tstun)          │
│                                                          │
│   userspaceEngine                                        │
│      │                                                   │
│      ├─ tundev (tstun.Wrapper) ──────┐                   │
│      │                               │  callbacks        │
│      ├─ magicConn (magicsock.Conn) ──┤  via CGo FFI      │
│      │                               │                   │
│      └─ wgDevice (wgdevice.Device) ──┘                   │
│              │                                           │
│              │ interface dispatch                         │
│              ▼                                           │
│   ┌──────────────────┐  ┌──────────────────────┐         │
│   │  WireGuardGo     │  │  GotatunDevice       │         │
│   │  (default)       │  │  (ts_use_gotatun)    │         │
│   │  wgdevice/wggo.go│  │  wgdevice/gotatun.go │         │
│   └────────┬─────────┘  └────────┬─────────────┘         │
│            │                     │                        │
└────────────│─────────────────────│────────────────────────┘
             │                     │
             ▼                     ▼
   wireguard-go (Go)     gotatun FFI (Rust → C → Go)
                              │
                              ├─ gotatun/rust/src/lib.rs  (FFI layer)
                              ├─ gotatun/rust/src/transport.rs
                              └─ gotatun/rust/vendor/gotatun/ (WG impl)
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Callback-based I/O** | Tailscale retains control of TUN (tstun.Wrapper) and UDP (magicsock). gotatun only handles WireGuard protocol logic. |
| **Build-tag selection** | `ts_use_gotatun && cgo` selects the Rust backend. Default remains wireguard-go for zero-risk rollout. |
| **UAPI text protocol** | Configuration uses the same UAPI text format as wireguard-go, so `wgcfg.ReconfigDevice()` works unchanged. |
| **wgdevice.Device interface** | Both backends implement the same interface — the engine doesn't know which is active. |
| **Static library** | Rust compiles to `libgotatun_ffi.a` (staticlib), linked via CGo LDFLAGS. No dynamic library needed. |

---

## Current State (Phase 1 — COMPLETE)

### What's Done

| Component | File(s) | Status |
|-----------|---------|--------|
| Vendored gotatun source | `gotatun/rust/vendor/gotatun/` | ✅ Done |
| Rust FFI layer | `gotatun/rust/src/lib.rs` (453 LOC) | ✅ Done |
| C header | `gotatun/rust/gotatun_ffi.h` (135 LOC) | ✅ Done |
| Go CGo bindings | `gotatun/gotatun.go` (260 LOC) | ✅ Done |
| Go callback stubs | `gotatun/callbacks.go` (64 LOC) | ✅ Done |
| Transport placeholder | `gotatun/rust/src/transport.rs` | ✅ Done |
| Build script | `gotatun/rust/build.sh` | ✅ Done |
| wgdevice.Device interface | `wgdevice/wgdevice.go` | ✅ Done |
| GotatunDevice wrapper | `wgdevice/gotatun.go` | ✅ Done |
| WireGuardGoDevice wrapper | `wgdevice/wggo.go` | ✅ Done |
| Engine build-tag dispatch | `wgdevice_create_gotatun.go` / `wgdevice_create.go` | ✅ Done |
| Rust tests (44) | `lib.rs #[cfg(test)]` | ✅ All passing |
| Go helper tests (4) | `gotatun_helpers_test.go` | ✅ Written |
| Pure Go helper extraction | `gotatun_helpers.go` | ✅ Done |

### What's NOT Done (Stubs / TODOs)

- **Callback implementations** — `callbacks.go` returns `-1` for all TUN/UDP callbacks
- **transport.rs** — Placeholder; needs `CgoTunTransport` and `CgoUdpTransport` implementing gotatun's `DeviceTransports` trait
- **gotatunPeer** — `wgdevice/gotatun.go:70` has a placeholder `stats interface{}` field; needs to actually read C struct fields
- **Actual WireGuard protocol wiring** — `ipc_set` only parses `private_key`/`public_key`; doesn't forward config to gotatun's device engine
- **No integration tests** — Can't test end-to-end without real TUN/UDP plumbing

---

## Phase 2: Connect Callbacks to tstun.Wrapper and magicsock

**Goal:** Wire the Go callback functions so gotatun can actually read/write packets.

### 2.1 TUN Callbacks (`callbacks.go`)

The TUN callbacks bridge gotatun's packet I/O to `tstun.Wrapper`:

```
gotatun (Rust) → gotatun_tun_read_cb() → tstun.Wrapper.Read()
gotatun (Rust) → gotatun_tun_write_cb() → tstun.Wrapper.Write()
```

**Tasks:**
- [ ] Add `tunDev *tstun.Wrapper` to `callbackState`
- [ ] Implement `gotatun_tun_read_cb`: call `tunDev.Read()`, copy bytes into the C buffer, return length
- [ ] Implement `gotatun_tun_write_cb`: construct a packet from the C buffer, call `tunDev.Write()`
- [ ] Handle packet offsets (tstun.Wrapper may prepend headers)
- [ ] Handle `ErrClosed` / shutdown signaling

### 2.2 UDP Callbacks (`callbacks.go`)

The UDP callbacks bridge gotatun to magicsock:

```
gotatun (Rust) → gotatun_udp_send_cb() → magicsock.Conn.Send()
gotatun (Rust) → gotatun_udp_recv_cb() → magicsock.connBind.receive*()
```

**Tasks:**
- [ ] Add `bind conn.Bind` (or `*magicsock.Conn`) to `callbackState`
- [ ] Implement `gotatun_udp_send_cb`: deserialize endpoint, call `Conn.Send()`
- [ ] Implement `gotatun_udp_recv_cb`: call `Conn.Open()` / receive functions, serialize source endpoint into the C buffer
- [ ] Design endpoint serialization format (IP:port → bytes, need to handle DERP relay addresses too)
- [ ] Handle `conn.Endpoint` interface bridging (gotatun uses raw bytes, magicsock uses `conn.Endpoint`)

### 2.3 Update callbackState Registration

- [ ] Pass `tstun.Wrapper` and `conn.Bind` into `NewDevice()` signature
- [ ] Store references in `callbackState`
- [ ] Update `wgdevice/gotatun.go` `NewDevice()` to pass these through

---

## Phase 3: Implement Rust Transport Layer

**Goal:** Implement the gotatun `DeviceTransports` trait using the FFI callbacks.

### 3.1 `CgoTunTransport` (`transport.rs`)

- [ ] Implement gotatun's TUN transport trait
- [ ] Read path: call the C `tun_read` function pointer → async channel
- [ ] Write path: call the C `tun_write` function pointer
- [ ] Buffer management: minimize copies across FFI boundary
- [ ] MTU handling from `GotatunConfig.mtu`

### 3.2 `CgoUdpTransport` (`transport.rs`)

- [ ] Implement gotatun's UDP transport trait
- [ ] Send path: serialize endpoint + payload → call C `udp_send`
- [ ] Receive path: call C `udp_recv` → deserialize endpoint + payload
- [ ] Endpoint type mapping between gotatun's internal representation and the serialized bytes

### 3.3 Wire Transports to Device

- [ ] In `GotatunDevice::new()`, create `CgoTunTransport` and `CgoUdpTransport` from the config callbacks
- [ ] Pass them to gotatun's device builder
- [ ] Start the async event loop in the tokio runtime

---

## Phase 4: Complete UAPI Config Forwarding

**Goal:** Forward full UAPI configuration to gotatun's WireGuard engine, not just our FFI-layer peer map.

### Tasks:
- [ ] Forward `private_key` to gotatun's Noise protocol layer
- [ ] Forward `public_key`, `endpoint`, `allowed_ip`, `persistent_keepalive_interval` to gotatun's peer management
- [ ] Forward `preshared_key` if needed
- [ ] Forward `remove=true` for peer removal
- [ ] Forward `replace_peers=true` / `replace_allowed_ips=true`
- [ ] Ensure `ipc_get` returns complete state from gotatun's device (not just our shadow peer map)
- [ ] Test UAPI roundtrip with realistic multi-peer configurations

---

## Phase 5: Fix gotatunPeer Stats Bridge

**Goal:** Make `wgdevice/gotatun.go` `LookupPeer()` actually return real stats from the C struct.

### Tasks:
- [ ] Fix `gotatunPeer` struct to extract fields from `C.GotatunPeerStats` (currently has placeholder `interface{}`)
- [ ] Wire `PeerStats()` return value → populate `lastHandshakeNsec`, `txBytes`, `rxBytes`, `handshakeAttempts`
- [ ] Ensure gotatun's Rust device updates `PeerState` atomics as handshakes and data transfer occur
- [ ] Verify stats match what `wgengine` expects for health checks and UI reporting

---

## Phase 6: Build System Integration

**Goal:** Make `go build -tags ts_use_gotatun` work end-to-end.

### Tasks:
- [ ] Integrate `build.sh` into the Go build process (or use `cargo` from a `go generate` step)
- [ ] Add CI job that builds with `ts_use_gotatun` tag
- [ ] Cross-compilation support: `GOOS=darwin GOARCH=arm64` (iOS), `GOOS=android`
- [ ] Ensure `libgotatun_ffi.a` is built for the correct target triple before `go build`
- [ ] Add `Cargo.lock` to version control (✅ done) for reproducible builds
- [ ] Set up Rust toolchain in CI (rustup, target installation)

---

## Phase 7: Integration Testing

**Goal:** Verify gotatun works as a drop-in replacement for wireguard-go.

### 7.1 Unit/FFI Tests (Already Done)
- [x] 44 Rust unit tests covering hex, peer state, IPC, FFI boundary, lifecycle
- [x] 4 Go helper tests covering log filtering, prefixes, version

### 7.2 Integration Tests (Needed)
- [ ] End-to-end test: create device → configure with UAPI → exchange packets through loopback TUN
- [ ] Test with `tstest` infrastructure: two nodes, gotatun on one or both sides
- [ ] Verify handshake completes and data flows
- [ ] Verify peer stats update correctly during data transfer
- [ ] Verify keepalive works
- [ ] Test reconfig (add/remove peers) while device is running
- [ ] Test graceful shutdown and cleanup

### 7.3 Compatibility Tests
- [ ] Run existing `wgengine` test suite with `ts_use_gotatun` tag
- [ ] Run `magicsock` test suite with gotatun backend
- [ ] Verify UAPI output matches wireguard-go format exactly (line-by-line comparison)

---

## Phase 8: iOS Power Optimization Validation

**Goal:** Verify the power/memory improvements that motivated this work.

### Tasks:
- [ ] Measure memory usage: gotatun (1 thread, 64-queue) vs wireguard-go on iOS
- [ ] Measure CPU wake-ups during idle keepalive traffic
- [ ] Measure handshake latency
- [ ] Measure steady-state throughput (iperf3)
- [ ] Verify NetworkExtension stays under 50MB memory limit
- [ ] Test behavior under memory pressure (jetsam)
- [ ] Battery life regression test (controlled test with standardized workload)

---

## Phase 9: Production Rollout

### Tasks:
- [ ] Feature flag: `ts_use_gotatun` build tag for opt-in
- [ ] Canary deployment on internal dogfood fleet
- [ ] A/B metrics collection: handshake success rate, throughput, battery impact
- [ ] Gradual rollout to iOS first (highest value target)
- [ ] Android rollout
- [ ] Desktop platforms (Linux, macOS, Windows)
- [ ] Eventually: make gotatun the default, deprecate wireguard-go path

---

## File Map

```
wgengine/
├── gotatun/                          # gotatun package (CGo bindings)
│   ├── gotatun.go                    # Device struct, NewDevice, lifecycle, IPC
│   ├── gotatun_helpers.go            # Pure Go helpers (no CGo dependency)
│   ├── gotatun_helpers_test.go       # Tests for helpers
│   ├── callbacks.go                  # CGo callback exports (TUN/UDP/log)
│   └── rust/
│       ├── Cargo.toml                # FFI crate config
│       ├── Cargo.lock                # Dependency lock
│       ├── build.sh                  # Build script
│       ├── gotatun_ffi.h             # C header
│       ├── .gitignore                # Ignore target/
│       └── src/
│           ├── lib.rs                # FFI implementation + 44 tests
│           └── transport.rs          # Transport adapters (TODO)
│       └── vendor/gotatun/           # Vendored WireGuard impl
│
├── wgdevice/                         # Device interface abstraction
│   ├── wgdevice.go                   # Device + PeerHandle interfaces
│   ├── wggo.go                       # wireguard-go implementation (!ts_use_gotatun)
│   └── gotatun.go                    # gotatun implementation (ts_use_gotatun)
│
├── wgdevice_create.go                # wireguard-go device factory (!ts_use_gotatun)
└── wgdevice_create_gotatun.go        # gotatun device factory (ts_use_gotatun)
```

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| CGo callback overhead on hot path | Medium | Medium | Benchmark; consider batching multiple packets per callback |
| gotatun API instability (upstream) | Low | High | Vendored copy; pin to known-good commit |
| Memory safety at FFI boundary | Medium | High | Extensive null checks (done); fuzzing planned |
| UAPI format mismatch | Low | Medium | Line-by-line comparison tests |
| iOS memory limit exceeded | Low | High | Single-thread + small queues (configured); measure before ship |
| wireguard-go parity gaps | Medium | Medium | Feature flags allow instant rollback |

---

## Success Criteria

1. **Functional parity**: All existing `wgengine` tests pass with `ts_use_gotatun`
2. **Performance**: Throughput within 5% of wireguard-go on desktop; better on mobile
3. **Power**: Measurable reduction in CPU wake-ups and memory on iOS
4. **Stability**: No crashes in 7-day canary on internal fleet
5. **Rollback**: Can switch back to wireguard-go by removing build tag, zero code changes
