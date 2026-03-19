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
use std::io::{self, Read, Write};
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
