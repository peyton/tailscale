# Power Optimizations for Mobile Clients

This document describes power-saving optimizations added to the Tailscale
WireGuard engine, primarily targeting iOS and Android. Each optimization
is marked with `POWER OPTIMIZATION` in the source code for easy discovery.

## Background

Tailscale on iOS runs as a Network Extension, which Apple limits to ~50 MB
of memory and penalizes for excessive CPU usage. Every CPU wake-up drains
battery — WireGuard keepalives, status polls, and GC pauses all contribute.
These optimizations reduce unnecessary wake-ups while maintaining connectivity.

## Optimizations

### 1. Adaptive Status Polling

**Files:** `wgengine/userspace.go`

**What:** On mobile, the WireGuard status poll interval extends from 1 minute
to 5 minutes when the tunnel has been idle for more than 2 minutes.

**Why:** Each status poll queries the WireGuard backend for all peer
statistics (handshake times, byte counts, etc.). This requires iterating
over all configured peers and reading atomic counters. While individually
cheap, doing this every minute when no traffic flows wastes CPU.

**Expected impact:** 80% reduction in status poll wake-ups during idle
(from 1/min to 1/5min). On a tailnet with 50+ peers, this is meaningful.

**How to verify:**
```bash
# Run with debug logging and observe "RequestStatus" log frequency
TS_DEBUG_RAW_WGLOG=1 tailscaled --tun=userspace-networking
# Compare idle CPU usage with/without the optimization
```

### 2. Adaptive Keepalive Intervals

**Files:** `wgengine/power.go`

**What:** On mobile, WireGuard persistent keepalive intervals extend from
25 seconds to 55 seconds when the tunnel has been idle for 2+ minutes.

**Why:** WireGuard sends persistent keepalive packets to maintain NAT
mappings. The standard 25-second interval results in ~2.4 packets per
minute per peer. Each packet wakes the radio (on cellular) or the WiFi
chip, consuming power. By extending to 55 seconds during idle, we reduce
keepalive packets by ~56%.

**NAT safety:** The 55-second interval is chosen conservatively:
- Most home NATs: 60-300 second timeout
- Most cellular NATs: 30-120 second timeout
- Our 55s stays under the lowest common 60s threshold with 5s margin

**Expected impact:** ~56% fewer keepalive packets during idle. For a
device with 3 active peers, this reduces from ~7.2 to ~3.3 keepalive
packets per minute.

**How to verify:**
```bash
# Capture WireGuard keepalive packets on the tunnel interface
tcpdump -i utun0 -c 100 'udp and len == 32'
# Count packets per minute during active vs idle periods
```

### 3. Single-Threaded Gotatun Runtime on Mobile

**Files:** `wgengine/gotatun/rust/src/lib.rs`, `wgengine/wgdevice/gotatun.go`

**What:** When using the gotatun (Rust) backend on mobile, the tokio async
runtime is configured with a single worker thread instead of auto-detecting
CPU count.

**Why:** Multiple runtime threads increase memory usage (each thread has its
own stack, typically 2-8 MB) and cause more context switches. In the iOS
NetworkExtension environment with a 50 MB memory limit, minimizing thread
count is critical. A single thread with async I/O is sufficient for the
typical mobile WireGuard workload (1-5 active peers, low throughput).

**Expected impact:** ~2-6 MB memory savings per avoided thread. Reduced
context switching overhead.

### 4. Reduced Queue Sizes on Mobile

**Files:** `wgengine/mem_ios.go`, `wgengine/wgdevice_create.go`,
`wgengine/wgdevice_create_gotatun.go`

**What:** Both wireguard-go and gotatun use queue size 64 (instead of
defaults) on iOS for all packet buffers.

**Why:** Default queue sizes in wireguard-go are tuned for high-throughput
server workloads. On iOS, the NetworkExtension memory limit makes large
queues dangerous — each queue entry holds a full MTU packet buffer.
Queue size 64 provides enough buffering for typical mobile use while
staying well within memory limits.

**Expected impact:** Prevents OOM kills in the NetworkExtension. Each
queue reduction from default (1024) to 64 saves ~1.4 MB per queue
(assuming 1420-byte MTU).

## Gotatun Backend (Experimental)

The gotatun Rust WireGuard implementation is available as an experimental
alternative to wireguard-go. It may offer additional power savings due to:

- **No GC pauses:** Rust's ownership model eliminates garbage collection,
  removing a source of periodic CPU wake-ups in wireguard-go
- **Lower memory overhead:** No Go runtime overhead (goroutine stacks,
  GC metadata, etc.)
- **Efficient async I/O:** tokio's event loop coalesces I/O operations
  naturally, reducing syscall overhead

To build with gotatun:
```bash
# First build the Rust FFI library
cd wgengine/gotatun/rust && ./build.sh

# Then build tailscaled with the gotatun tag
go build -tags ts_use_gotatun ./cmd/tailscaled
```

## Benchmarking

Comparative benchmarks are available to measure the impact of these
optimizations and compare wireguard-go vs gotatun:

```bash
# Benchmark wireguard-go (default)
go test -bench=. -count=5 ./wgengine/wgdevice/ > wireguardgo.txt

# Benchmark gotatun
go test -bench=. -count=5 -tags ts_use_gotatun ./wgengine/wgdevice/ > gotatun.txt

# Compare with benchstat
benchstat wireguardgo.txt gotatun.txt
```

Key benchmarks:
- `BenchmarkDeviceCreate` — startup time
- `BenchmarkIpcSetGet` — config update time (affects reconfig latency)
- `BenchmarkDeviceIdle` — GC pressure during idle (critical for battery)
- `BenchmarkPeerLookup` — stats query time (affects status poll cost)
