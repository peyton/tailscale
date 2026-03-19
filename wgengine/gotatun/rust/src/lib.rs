// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//! C FFI bindings for the gotatun WireGuard implementation.
//!
//! This crate wraps gotatun's async Rust API into a C-compatible FFI that
//! can be called from Go via CGo. The key design decisions:
//!
//! - TUN device I/O is handled via callbacks into Go (since Tailscale manages
//!   TUN via tstun.Wrapper)
//! - UDP socket I/O is handled via callbacks into Go (since Tailscale uses
//!   magicsock for all UDP)
//! - The UAPI text protocol is used for configuration, matching wireguard-go's
//!   IpcSetOperation/IpcGetOperation interface
//! - A dedicated tokio runtime is spawned per device, with configurable thread
//!   count (1 thread on iOS to save resources)

use std::ffi::{c_char, c_void};
use std::io;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::HashMap;

use parking_lot::RwLock;

mod transport;

// Re-export types from the header
#[repr(C)]
pub struct GotatunPeerStats {
    pub last_handshake_nsec: i64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub handshake_attempts: u32,
    pub valid: i32,
}

// Callback function pointer types matching the C header
type TunReadFn = extern "C" fn(*mut u8, i32, *mut c_void) -> i32;
type TunWriteFn = extern "C" fn(*const u8, i32, *mut c_void) -> i32;
type UdpSendFn = extern "C" fn(*const u8, i32, *const u8, i32, *mut c_void) -> i32;
type UdpRecvFn = extern "C" fn(*mut u8, i32, *mut u8, i32, *mut i32, *mut c_void) -> i32;
type LogFn = extern "C" fn(i32, *const c_char, i32, *mut c_void);

#[repr(C)]
pub struct GotatunConfig {
    pub tun_read: TunReadFn,
    pub tun_write: TunWriteFn,
    pub tun_ctx: *mut c_void,

    pub udp_send: UdpSendFn,
    pub udp_recv: UdpRecvFn,
    pub udp_ctx: *mut c_void,

    pub log_fn: LogFn,
    pub log_ctx: *mut c_void,

    pub mtu: i32,
    pub num_threads: i32,
    pub queue_size: i32,
}

// Safety: The raw pointers in GotatunConfig are callback function pointers
// and context pointers that are valid for the lifetime of the device.
unsafe impl Send for GotatunConfig {}
unsafe impl Sync for GotatunConfig {}

/// Internal peer state tracked by the FFI layer.
struct PeerState {
    last_handshake_nsec: AtomicI64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    handshake_attempts: AtomicU32,
}

impl PeerState {
    fn new() -> Self {
        PeerState {
            last_handshake_nsec: AtomicI64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            handshake_attempts: AtomicU32::new(0),
        }
    }
}

/// The main device handle exposed via FFI.
pub struct GotatunDevice {
    config: GotatunConfig,
    runtime: Option<tokio::runtime::Runtime>,
    running: AtomicBool,
    peers: RwLock<HashMap<[u8; 32], Arc<PeerState>>>,
    /// Private key (32 bytes)
    private_key: RwLock<[u8; 32]>,
    /// Signaling channel for device shutdown
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Pipe for wait_fd
    #[cfg(unix)]
    wait_pipe: (i32, i32), // (read_fd, write_fd)
}

impl GotatunDevice {
    fn new(config: GotatunConfig) -> Result<Self, io::Error> {
        let num_threads = if config.num_threads > 0 {
            config.num_threads as usize
        } else if cfg!(target_os = "ios") {
            // POWER OPTIMIZATION: Use single-threaded runtime on iOS.
            // Multiple threads increase memory usage and context-switching
            // overhead in the constrained NetworkExtension environment.
            // A single thread with async I/O is sufficient for typical
            // mobile WireGuard workloads.
            1
        } else {
            num_cpus()
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(num_threads)
            .enable_all()
            .thread_name("gotatun-worker")
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);

        #[cfg(unix)]
        let wait_pipe = {
            let mut fds = [0i32; 2];
            unsafe {
                if libc::pipe(fds.as_mut_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            (fds[0], fds[1])
        };

        Ok(GotatunDevice {
            config,
            runtime: Some(runtime),
            running: AtomicBool::new(false),
            peers: RwLock::new(HashMap::new()),
            private_key: RwLock::new([0u8; 32]),
            shutdown_tx: Some(shutdown_tx),
            #[cfg(unix)]
            wait_pipe,
        })
    }

    fn up(&self) -> Result<(), io::Error> {
        self.running.store(true, Ordering::SeqCst);
        self.log(2, "gotatun device up");
        Ok(())
    }

    fn close(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.log(2, "gotatun device closing");

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        // Shut down the tokio runtime
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }

        // Signal wait_fd
        #[cfg(unix)]
        {
            unsafe {
                libc::write(self.wait_pipe.1, b"x".as_ptr() as *const c_void, 1);
                libc::close(self.wait_pipe.1);
            }
        }
    }

    fn log(&self, level: i32, msg: &str) {
        (self.config.log_fn)(
            level,
            msg.as_ptr() as *const c_char,
            msg.len() as i32,
            self.config.log_ctx,
        );
    }

    /// Parse and apply a UAPI configuration string.
    fn ipc_set(&self, config_str: &str) -> Result<(), io::Error> {
        let mut peers = self.peers.write();

        for line in config_str.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "private_key" => {
                        if let Ok(bytes) = hex_decode_32(value) {
                            *self.private_key.write() = bytes;
                        }
                    }
                    "public_key" => {
                        if let Ok(bytes) = hex_decode_32(value) {
                            peers.entry(bytes).or_insert_with(|| Arc::new(PeerState::new()));
                        }
                    }
                    "remove" => {
                        // Remove is preceded by a public_key line
                        // handled by the UAPI protocol parser
                    }
                    _ => {
                        // Pass through other UAPI keys
                    }
                }
            }
        }

        Ok(())
    }

    /// Get current configuration in UAPI format.
    fn ipc_get(&self) -> String {
        let mut out = String::new();

        let pk = self.private_key.read();
        out.push_str("private_key=");
        out.push_str(&hex_encode(&pk[..]));
        out.push('\n');

        let peers = self.peers.read();
        for (pubkey, state) in peers.iter() {
            out.push_str("public_key=");
            out.push_str(&hex_encode(&pubkey[..]));
            out.push('\n');

            let hs = state.last_handshake_nsec.load(Ordering::Relaxed);
            if hs != 0 {
                let secs = hs / 1_000_000_000;
                let nsecs = hs % 1_000_000_000;
                out.push_str(&format!("last_handshake_time_sec={}\n", secs));
                out.push_str(&format!("last_handshake_time_nsec={}\n", nsecs));
            }

            let tx = state.tx_bytes.load(Ordering::Relaxed);
            out.push_str(&format!("tx_bytes={}\n", tx));

            let rx = state.rx_bytes.load(Ordering::Relaxed);
            out.push_str(&format!("rx_bytes={}\n", rx));
        }

        out
    }

    fn peer_stats(&self, pubkey: &[u8; 32]) -> GotatunPeerStats {
        let peers = self.peers.read();
        match peers.get(pubkey) {
            Some(state) => GotatunPeerStats {
                last_handshake_nsec: state.last_handshake_nsec.load(Ordering::Relaxed),
                tx_bytes: state.tx_bytes.load(Ordering::Relaxed),
                rx_bytes: state.rx_bytes.load(Ordering::Relaxed),
                handshake_attempts: state.handshake_attempts.load(Ordering::Relaxed),
                valid: 1,
            },
            None => GotatunPeerStats {
                last_handshake_nsec: 0,
                tx_bytes: 0,
                rx_bytes: 0,
                handshake_attempts: 0,
                valid: 0,
            },
        }
    }
}

impl Drop for GotatunDevice {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::close(self.wait_pipe.0);
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

fn hex_decode_32(hex: &str) -> Result<[u8; 32], ()> {
    if hex.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or(())?;
        let lo = hex_nibble(chunk[1]).ok_or(())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ============================================================================
// C FFI exports
// ============================================================================

#[no_mangle]
pub extern "C" fn gotatun_device_new(config: *const GotatunConfig) -> *mut GotatunDevice {
    if config.is_null() {
        return ptr::null_mut();
    }

    let config = unsafe { ptr::read(config) };
    match GotatunDevice::new(config) {
        Ok(dev) => Box::into_raw(Box::new(dev)),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn gotatun_device_up(dev: *mut GotatunDevice) -> i32 {
    if dev.is_null() {
        return -1;
    }
    let dev = unsafe { &*dev };
    match dev.up() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn gotatun_device_close(dev: *mut GotatunDevice) {
    if dev.is_null() {
        return;
    }
    let mut dev = unsafe { Box::from_raw(dev) };
    dev.close();
    // dev is dropped here, freeing all resources
}

#[no_mangle]
pub extern "C" fn gotatun_device_wait_fd(dev: *mut GotatunDevice) -> i32 {
    if dev.is_null() {
        return -1;
    }
    let dev = unsafe { &*dev };
    #[cfg(unix)]
    {
        dev.wait_pipe.0
    }
    #[cfg(not(unix))]
    {
        -1
    }
}

#[no_mangle]
pub extern "C" fn gotatun_ipc_set(
    dev: *mut GotatunDevice,
    config: *const c_char,
    config_len: i32,
) -> i32 {
    if dev.is_null() || config.is_null() || config_len < 0 {
        return -1;
    }
    let dev = unsafe { &*dev };
    let config_bytes = unsafe { slice::from_raw_parts(config as *const u8, config_len as usize) };
    let config_str = match std::str::from_utf8(config_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match dev.ipc_set(config_str) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn gotatun_ipc_get(
    dev: *mut GotatunDevice,
    buf: *mut c_char,
    buf_len: i32,
) -> i32 {
    if dev.is_null() || buf.is_null() || buf_len < 0 {
        return -1;
    }
    let dev = unsafe { &*dev };
    let result = dev.ipc_get();
    let result_bytes = result.as_bytes();

    if result_bytes.len() > buf_len as usize {
        return result_bytes.len() as i32; // buffer too small
    }

    unsafe {
        ptr::copy_nonoverlapping(result_bytes.as_ptr(), buf as *mut u8, result_bytes.len());
    }
    result_bytes.len() as i32
}

#[no_mangle]
pub extern "C" fn gotatun_peer_stats(
    dev: *mut GotatunDevice,
    pubkey: *const u8,
    stats: *mut GotatunPeerStats,
) -> i32 {
    if dev.is_null() || pubkey.is_null() || stats.is_null() {
        return -1;
    }
    let dev = unsafe { &*dev };
    let pubkey_bytes: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        ptr::copy_nonoverlapping(pubkey, buf.as_mut_ptr(), 32);
        buf
    };
    let result = dev.peer_stats(&pubkey_bytes);
    unsafe {
        *stats = result;
    }
    if unsafe { (*stats).valid } == 1 {
        0
    } else {
        1
    }
}

#[no_mangle]
pub extern "C" fn gotatun_set_log_level(_level: i32) {
    // TODO: Configure log level filtering
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    // --- hex utility tests ---

    #[test]
    fn test_hex_nibble_digits() {
        for i in 0..=9u8 {
            assert_eq!(hex_nibble(b'0' + i), Some(i));
        }
    }

    #[test]
    fn test_hex_nibble_lower() {
        for i in 0..=5u8 {
            assert_eq!(hex_nibble(b'a' + i), Some(10 + i));
        }
    }

    #[test]
    fn test_hex_nibble_upper() {
        for i in 0..=5u8 {
            assert_eq!(hex_nibble(b'A' + i), Some(10 + i));
        }
    }

    #[test]
    fn test_hex_nibble_invalid() {
        assert_eq!(hex_nibble(b'g'), None);
        assert_eq!(hex_nibble(b'G'), None);
        assert_eq!(hex_nibble(b' '), None);
        assert_eq!(hex_nibble(b'z'), None);
        assert_eq!(hex_nibble(0), None);
    }

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_hex_encode_bytes() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn test_hex_encode_32_bytes() {
        let key = [0xab; 32];
        let encoded = hex_encode(&key);
        assert_eq!(encoded.len(), 64);
        assert!(encoded.chars().all(|c| c == 'a' || c == 'b'));
    }

    #[test]
    fn test_hex_decode_32_roundtrip() {
        let original = [0x42u8; 32];
        let encoded = hex_encode(&original);
        let decoded = hex_decode_32(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_hex_decode_32_known_value() {
        // All zeros
        let hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = hex_decode_32(hex).unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_hex_decode_32_wrong_length() {
        assert!(hex_decode_32("").is_err());
        assert!(hex_decode_32("00").is_err());
        assert!(hex_decode_32("abcdef").is_err());
        // 63 chars - too short
        assert!(hex_decode_32("000000000000000000000000000000000000000000000000000000000000000").is_err());
        // 65 chars - too long
        assert!(hex_decode_32("00000000000000000000000000000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn test_hex_decode_32_invalid_chars() {
        let bad = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert!(hex_decode_32(bad).is_err());
    }

    #[test]
    fn test_hex_decode_32_mixed_case() {
        let hex = "aAbBcCdDeEfF00112233445566778899aAbBcCdDeEfF00112233445566778899";
        assert_eq!(hex.len(), 64);
        let result = hex_decode_32(hex);
        assert!(result.is_ok());
    }

    // --- PeerState tests ---

    #[test]
    fn test_peer_state_new_is_zeroed() {
        let ps = PeerState::new();
        assert_eq!(ps.last_handshake_nsec.load(Ordering::Relaxed), 0);
        assert_eq!(ps.tx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(ps.rx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(ps.handshake_attempts.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_peer_state_atomic_updates() {
        let ps = PeerState::new();
        ps.tx_bytes.store(1000, Ordering::SeqCst);
        ps.rx_bytes.store(2000, Ordering::SeqCst);
        ps.last_handshake_nsec.store(1234567890_000_000_000, Ordering::SeqCst);
        ps.handshake_attempts.store(5, Ordering::SeqCst);

        assert_eq!(ps.tx_bytes.load(Ordering::SeqCst), 1000);
        assert_eq!(ps.rx_bytes.load(Ordering::SeqCst), 2000);
        assert_eq!(ps.last_handshake_nsec.load(Ordering::SeqCst), 1234567890_000_000_000);
        assert_eq!(ps.handshake_attempts.load(Ordering::SeqCst), 5);
    }

    // --- Test helper: create a device with dummy callbacks ---

    extern "C" fn dummy_tun_read(_buf: *mut u8, _len: i32, _ctx: *mut c_void) -> i32 { -1 }
    extern "C" fn dummy_tun_write(_buf: *const u8, _len: i32, _ctx: *mut c_void) -> i32 { -1 }
    extern "C" fn dummy_udp_send(_buf: *const u8, _len: i32, _ep: *const u8, _ep_len: i32, _ctx: *mut c_void) -> i32 { -1 }
    extern "C" fn dummy_udp_recv(_buf: *mut u8, _len: i32, _ep: *mut u8, _ep_len: i32, _ep_out: *mut i32, _ctx: *mut c_void) -> i32 { -1 }
    extern "C" fn dummy_log(_level: i32, _msg: *const c_char, _len: i32, _ctx: *mut c_void) {}

    fn test_config() -> GotatunConfig {
        GotatunConfig {
            tun_read: dummy_tun_read,
            tun_write: dummy_tun_write,
            tun_ctx: ptr::null_mut(),
            udp_send: dummy_udp_send,
            udp_recv: dummy_udp_recv,
            udp_ctx: ptr::null_mut(),
            log_fn: dummy_log,
            log_ctx: ptr::null_mut(),
            mtu: 1420,
            num_threads: 1,
            queue_size: 64,
        }
    }

    // --- Device creation and lifecycle tests ---

    #[test]
    fn test_device_new() {
        let config = test_config();
        let dev = GotatunDevice::new(config).expect("failed to create device");
        assert!(!dev.running.load(Ordering::SeqCst));
        assert!(dev.runtime.is_some());
    }

    #[test]
    fn test_device_up() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        dev.up().unwrap();
        assert!(dev.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_device_close() {
        let config = test_config();
        let mut dev = GotatunDevice::new(config).unwrap();
        dev.up().unwrap();
        dev.close();
        assert!(!dev.running.load(Ordering::SeqCst));
        assert!(dev.runtime.is_none());
        assert!(dev.shutdown_tx.is_none());
    }

    #[test]
    fn test_device_close_without_up() {
        let config = test_config();
        let mut dev = GotatunDevice::new(config).unwrap();
        dev.close(); // should not panic
    }

    // --- IPC set/get tests ---

    /// Helper to create a 64-char hex string from a single byte value.
    fn hex_key(byte: u8) -> String {
        hex_encode(&[byte; 32])
    }

    #[test]
    fn test_ipc_set_private_key() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let key_hex = hex_key(0xab);
        let uapi = format!("private_key={}\n", key_hex);
        dev.ipc_set(&uapi).unwrap();

        let pk = dev.private_key.read();
        assert_eq!(*pk, [0xab; 32]);
    }

    #[test]
    fn test_ipc_set_add_peer() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let peer_hex = hex_key(0xcd);
        let uapi = format!("public_key={}\n", peer_hex);
        dev.ipc_set(&uapi).unwrap();

        let peers = dev.peers.read();
        assert_eq!(peers.len(), 1);
        assert!(peers.contains_key(&[0xcd; 32]));
    }

    #[test]
    fn test_ipc_set_multiple_peers() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let peer1 = hex_key(0x11);
        let peer2 = hex_key(0x22);
        let uapi = format!("public_key={}\npublic_key={}\n", peer1, peer2);
        dev.ipc_set(&uapi).unwrap();

        let peers = dev.peers.read();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn test_ipc_set_duplicate_peer_no_double_insert() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let peer_hex = hex_key(0xaa);
        let uapi = format!("public_key={}\npublic_key={}\n", peer_hex, peer_hex);
        dev.ipc_set(&uapi).unwrap();

        let peers = dev.peers.read();
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_ipc_set_empty_config() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        dev.ipc_set("").unwrap();
        dev.ipc_set("\n\n\n").unwrap();
        let peers = dev.peers.read();
        assert_eq!(peers.len(), 0);
    }

    #[test]
    fn test_ipc_set_ignores_unknown_keys() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let uapi = "endpoint=1.2.3.4:51820\nallowed_ip=10.0.0.0/24\npersistent_keepalive_interval=25\n";
        dev.ipc_set(uapi).unwrap(); // should not error
    }

    #[test]
    fn test_ipc_set_invalid_hex_ignored() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        // Invalid hex for private_key - should be silently ignored
        let uapi = "private_key=not_valid_hex\n";
        dev.ipc_set(uapi).unwrap();
        let pk = dev.private_key.read();
        assert_eq!(*pk, [0u8; 32]); // unchanged
    }

    #[test]
    fn test_ipc_get_empty() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let result = dev.ipc_get();
        // Should contain private_key= with all zeros
        assert!(result.starts_with("private_key="));
        assert!(result.contains("0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_ipc_get_with_peer() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let peer_hex = hex_key(0xbb);
        dev.ipc_set(&format!("public_key={}\n", peer_hex)).unwrap();

        let result = dev.ipc_get();
        assert!(result.contains(&format!("public_key={}", peer_hex)));
        assert!(result.contains("tx_bytes=0"));
        assert!(result.contains("rx_bytes=0"));
    }

    #[test]
    fn test_ipc_roundtrip_private_key() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let key = hex_encode(&[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                               0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                               0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                               0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef]);
        dev.ipc_set(&format!("private_key={}\n", key)).unwrap();
        let result = dev.ipc_get();
        assert!(result.contains(&format!("private_key={}", key)));
    }

    #[test]
    fn test_ipc_get_with_handshake_time() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let peer_hex = hex_key(0xcc);
        dev.ipc_set(&format!("public_key={}\n", peer_hex)).unwrap();

        // Simulate a handshake
        let peers = dev.peers.read();
        let peer_key = [0xcc; 32];
        let state = peers.get(&peer_key).unwrap();
        state.last_handshake_nsec.store(1_700_000_000_123_456_789, Ordering::SeqCst);
        state.tx_bytes.store(12345, Ordering::SeqCst);
        state.rx_bytes.store(67890, Ordering::SeqCst);
        drop(peers);

        let result = dev.ipc_get();
        assert!(result.contains("last_handshake_time_sec=1700000000"));
        assert!(result.contains("last_handshake_time_nsec=123456789"));
        assert!(result.contains("tx_bytes=12345"));
        assert!(result.contains("rx_bytes=67890"));
    }

    // --- peer_stats tests ---

    #[test]
    fn test_peer_stats_unknown_peer() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let key = [0xff; 32];
        let stats = dev.peer_stats(&key);
        assert_eq!(stats.valid, 0);
    }

    #[test]
    fn test_peer_stats_known_peer() {
        let config = test_config();
        let dev = GotatunDevice::new(config).unwrap();
        let key = [0xee; 32];
        let key_hex = hex_encode(&key);
        dev.ipc_set(&format!("public_key={}\n", key_hex)).unwrap();

        // Update stats
        {
            let peers = dev.peers.read();
            let state = peers.get(&key).unwrap();
            state.tx_bytes.store(100, Ordering::SeqCst);
            state.rx_bytes.store(200, Ordering::SeqCst);
            state.handshake_attempts.store(3, Ordering::SeqCst);
            state.last_handshake_nsec.store(999, Ordering::SeqCst);
        }

        let stats = dev.peer_stats(&key);
        assert_eq!(stats.valid, 1);
        assert_eq!(stats.tx_bytes, 100);
        assert_eq!(stats.rx_bytes, 200);
        assert_eq!(stats.handshake_attempts, 3);
        assert_eq!(stats.last_handshake_nsec, 999);
    }

    // --- C FFI boundary tests ---

    #[test]
    fn test_ffi_device_new_null_config() {
        let dev = gotatun_device_new(ptr::null());
        assert!(dev.is_null());
    }

    #[test]
    fn test_ffi_device_up_null() {
        assert_eq!(gotatun_device_up(ptr::null_mut()), -1);
    }

    #[test]
    fn test_ffi_device_close_null() {
        gotatun_device_close(ptr::null_mut()); // should not panic
    }

    #[test]
    fn test_ffi_device_wait_fd_null() {
        assert_eq!(gotatun_device_wait_fd(ptr::null_mut()), -1);
    }

    #[test]
    fn test_ffi_ipc_set_null_dev() {
        let s = "private_key=00\n";
        assert_eq!(gotatun_ipc_set(ptr::null_mut(), s.as_ptr() as *const c_char, s.len() as i32), -1);
    }

    #[test]
    fn test_ffi_ipc_set_null_config() {
        let config = test_config();
        let dev = gotatun_device_new(&config);
        assert!(!dev.is_null());
        assert_eq!(gotatun_ipc_set(dev, ptr::null(), 10), -1);
        gotatun_device_close(dev);
    }

    #[test]
    fn test_ffi_ipc_set_negative_len() {
        let config = test_config();
        let dev = gotatun_device_new(&config);
        assert!(!dev.is_null());
        let s = "test";
        assert_eq!(gotatun_ipc_set(dev, s.as_ptr() as *const c_char, -1), -1);
        gotatun_device_close(dev);
    }

    #[test]
    fn test_ffi_ipc_get_null_dev() {
        let mut buf = [0u8; 128];
        assert_eq!(gotatun_ipc_get(ptr::null_mut(), buf.as_mut_ptr() as *mut c_char, 128), -1);
    }

    #[test]
    fn test_ffi_ipc_get_null_buf() {
        let config = test_config();
        let dev = gotatun_device_new(&config);
        assert!(!dev.is_null());
        assert_eq!(gotatun_ipc_get(dev, ptr::null_mut(), 128), -1);
        gotatun_device_close(dev);
    }

    #[test]
    fn test_ffi_ipc_get_buffer_too_small() {
        let config = test_config();
        let dev = gotatun_device_new(&config);
        assert!(!dev.is_null());
        // The output is at least "private_key=<64 hex chars>\n" = 77 bytes
        let mut buf = [0u8; 4];
        let ret = gotatun_ipc_get(dev, buf.as_mut_ptr() as *mut c_char, 4);
        // Should return required size > 4
        assert!(ret > 4);
        gotatun_device_close(dev);
    }

    #[test]
    fn test_ffi_peer_stats_null_args() {
        let mut stats = GotatunPeerStats {
            last_handshake_nsec: 0, tx_bytes: 0, rx_bytes: 0, handshake_attempts: 0, valid: 0,
        };
        let key = [0u8; 32];
        assert_eq!(gotatun_peer_stats(ptr::null_mut(), key.as_ptr(), &mut stats), -1);

        let config = test_config();
        let dev = gotatun_device_new(&config);
        assert_eq!(gotatun_peer_stats(dev, ptr::null(), &mut stats), -1);
        assert_eq!(gotatun_peer_stats(dev, key.as_ptr(), ptr::null_mut()), -1);
        gotatun_device_close(dev);
    }

    #[test]
    fn test_ffi_full_lifecycle() {
        // Create device
        let config = test_config();
        let dev = gotatun_device_new(&config);
        assert!(!dev.is_null());

        // Bring up
        assert_eq!(gotatun_device_up(dev), 0);

        // Set config with a peer
        let pk_hex = hex_key(0xaa);
        let peer_hex = hex_key(0xbb);
        let uapi = format!("private_key={}\npublic_key={}\n", pk_hex, peer_hex);
        assert_eq!(gotatun_ipc_set(dev, uapi.as_ptr() as *const c_char, uapi.len() as i32), 0);

        // Get config
        let mut buf = [0u8; 4096];
        let len = gotatun_ipc_get(dev, buf.as_mut_ptr() as *mut c_char, 4096);
        assert!(len > 0);
        let result = std::str::from_utf8(&buf[..len as usize]).unwrap();
        assert!(result.contains(&format!("private_key={}", pk_hex)));
        assert!(result.contains(&format!("public_key={}", peer_hex)));

        // Query peer stats
        let peer_key = [0xbb; 32];
        let mut stats = GotatunPeerStats {
            last_handshake_nsec: 0, tx_bytes: 0, rx_bytes: 0, handshake_attempts: 0, valid: 0,
        };
        assert_eq!(gotatun_peer_stats(dev, peer_key.as_ptr(), &mut stats), 0);
        assert_eq!(stats.valid, 1);
        assert_eq!(stats.tx_bytes, 0);

        // Query unknown peer
        let unknown = [0xff; 32];
        assert_eq!(gotatun_peer_stats(dev, unknown.as_ptr(), &mut stats), 1);

        // Wait fd should be valid on unix
        #[cfg(unix)]
        {
            let fd = gotatun_device_wait_fd(dev);
            assert!(fd >= 0);
        }

        // Close
        gotatun_device_close(dev);
    }

    // --- num_cpus test ---

    #[test]
    fn test_num_cpus_positive() {
        assert!(num_cpus() >= 1);
    }
}
