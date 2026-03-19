// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// C FFI header for gotatun (Rust WireGuard implementation).
// This is the interface between Go (via CGo) and the Rust library.

#ifndef GOTATUN_FFI_H
#define GOTATUN_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a gotatun WireGuard device.
typedef struct GotatunDevice GotatunDevice;

// PeerStats contains statistics for a single WireGuard peer.
typedef struct {
    int64_t  last_handshake_nsec; // nanoseconds since Unix epoch, 0 if never
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint32_t handshake_attempts;
    int32_t  valid; // 1 if peer found, 0 otherwise
} GotatunPeerStats;

// Callback function types for TUN device I/O.
// gotatun calls back into Go for TUN read/write since Tailscale
// manages the TUN device (via tstun.Wrapper).

// TunReadFn reads a packet from the TUN device into buf.
// Returns the number of bytes read, or negative on error.
// ctx is the Go-side context pointer (tstun.Wrapper).
typedef int32_t (*GotatunTunReadFn)(uint8_t *buf, int32_t buf_len, void *ctx);

// TunWriteFn writes a packet to the TUN device from buf.
// Returns 0 on success, negative on error.
typedef int32_t (*GotatunTunWriteFn)(const uint8_t *buf, int32_t buf_len, void *ctx);

// Callback function types for UDP socket I/O.
// gotatun calls back into Go for send/recv since Tailscale
// manages sockets via magicsock.

// UdpSendFn sends a UDP packet. endpoint is a serialized endpoint.
// Returns 0 on success, negative on error.
typedef int32_t (*GotatunUdpSendFn)(const uint8_t *buf, int32_t buf_len,
                                     const uint8_t *endpoint, int32_t endpoint_len,
                                     void *ctx);

// UdpRecvFn receives a UDP packet into buf.
// endpoint_buf receives the serialized source endpoint.
// Returns number of bytes received, or negative on error/timeout.
typedef int32_t (*GotatunUdpRecvFn)(uint8_t *buf, int32_t buf_len,
                                     uint8_t *endpoint_buf, int32_t endpoint_buf_len,
                                     int32_t *endpoint_len_out,
                                     void *ctx);

// LogFn is called by gotatun to log messages.
typedef void (*GotatunLogFn)(int32_t level, const char *msg, int32_t msg_len, void *ctx);

// GotatunConfig holds the configuration for creating a new device.
typedef struct {
    // Callbacks for TUN I/O
    GotatunTunReadFn  tun_read;
    GotatunTunWriteFn tun_write;
    void             *tun_ctx;

    // Callbacks for UDP I/O (magicsock)
    GotatunUdpSendFn  udp_send;
    GotatunUdpRecvFn  udp_recv;
    void             *udp_ctx;

    // Logging callback
    GotatunLogFn log_fn;
    void        *log_ctx;

    // MTU for the tunnel
    int32_t mtu;

    // Number of worker threads for the async runtime.
    // 0 = auto-detect based on CPU count.
    // On iOS, set to 1 to minimize resource usage.
    int32_t num_threads;

    // Queue sizes for packet buffers.
    // 0 = use defaults. On iOS, use smaller values (e.g. 64)
    // to stay within NetworkExtension memory limits.
    int32_t queue_size;
} GotatunConfig;

// gotatun_device_new creates a new gotatun WireGuard device.
// Returns NULL on failure.
GotatunDevice *gotatun_device_new(const GotatunConfig *config);

// gotatun_device_up brings the device up.
// Returns 0 on success, negative on error.
int32_t gotatun_device_up(GotatunDevice *dev);

// gotatun_device_close shuts down and frees the device.
void gotatun_device_close(GotatunDevice *dev);

// gotatun_device_wait returns a file descriptor that becomes readable
// when the device has stopped. Used for Wait() semantics.
// Returns -1 if not supported.
int32_t gotatun_device_wait_fd(GotatunDevice *dev);

// gotatun_ipc_set applies a UAPI configuration string to the device.
// config must be a null-terminated UAPI config string.
// Returns 0 on success, negative on error.
int32_t gotatun_ipc_set(GotatunDevice *dev, const char *config, int32_t config_len);

// gotatun_ipc_get retrieves the current device configuration in UAPI format.
// Writes to buf up to buf_len bytes. Returns the number of bytes written,
// or negative on error. If the buffer is too small, returns the required size
// as a positive number greater than buf_len.
int32_t gotatun_ipc_get(GotatunDevice *dev, char *buf, int32_t buf_len);

// gotatun_peer_stats retrieves statistics for the peer with the given
// 32-byte public key. Writes results to stats.
// Returns 0 on success (peer found), 1 if peer not found, negative on error.
int32_t gotatun_peer_stats(GotatunDevice *dev, const uint8_t *pubkey,
                            GotatunPeerStats *stats);

// gotatun_set_log_level sets the minimum log level.
// 0 = error, 1 = warn, 2 = info, 3 = debug, 4 = trace
void gotatun_set_log_level(int32_t level);

#ifdef __cplusplus
}
#endif

#endif // GOTATUN_FFI_H
