//! Event fan-out types shared between the loader's ring buffer drain
//! tasks and the WebSocket `/events/stream` endpoint.
//!
//! The kernel-side `agl_health_common::events::*` structs are
//! deliberately low-level: fixed-size `comm`/`filename` byte arrays, raw
//! `kind` discriminants, IPv6-sized address fields padded for IPv4. They
//! exist to round-trip through a BPF ring buffer with zero serialization.
//!
//! `WireEvent` is what the daemon actually publishes over the wire. It:
//!
//!   * replaces the `[u8; 16]` / `[u8; 256]` byte arrays with UTF-8
//!     Strings trimmed at the first NUL, producing clean JSON;
//!   * maps numeric `kind` discriminants to `&'static str` names so
//!     clients don't need to know the enum layout;
//!   * flattens the `subsystem` tag to the top level to match §6.2 of
//!     the implementation plan:
//!
//!     ```json
//!     {
//!       "subsystem": "process",
//!       "kind":      "Exec",
//!       "timestamp_ns": 1714000000000000,
//!       "pid": 1234,
//!       ...
//!     }
//!     ```

use agl_health_common::events::{NetEvent, ProcessEvent, SecurityEvent};
use serde::Serialize;
use tokio::sync::broadcast;

/// Broadcast channel sender shared across every ring buffer drain task
/// and handed to each WebSocket subscriber via `state.events.subscribe()`.
pub type EventBus = broadcast::Sender<WireEvent>;

/// Broadcast channel capacity. Slow clients that fall behind will receive
/// `RecvError::Lagged(n)` and resume at the channel head, losing the `n`
/// oldest messages. 1024 is enough to absorb a ~10ms hiccup under a
/// sustained 100k events/s, which is well above expected IVI rates.
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// A single event ready for wire transmission.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "subsystem", rename_all = "snake_case")]
pub enum WireEvent {
    Process {
        kind: &'static str,
        timestamp_ns: u64,
        pid: u32,
        ppid: u32,
        uid: u32,
        exit_code: i32,
        comm: String,
        filename: String,
    },
    Network {
        kind: &'static str,
        timestamp_ns: u64,
        family: u16,
        sport: u16,
        dport: u16,
        drop_reason: u16,
        old_state: u8,
        new_state: u8,
        saddr: [u8; 16],
        daddr: [u8; 16],
    },
    Security {
        kind: &'static str,
        severity: &'static str,
        timestamp_ns: u64,
        pid: u32,
        ppid: u32,
        uid: u32,
        /// Raw syscall argument associated with the event - for
        /// `ptrace` this is the `request`, for `setuid` it's the new
        /// uid, for `prctl` the option number, etc.
        arg: u64,
        comm: String,
        filename: String,
    },
}

impl WireEvent {
    // Called only from the cfg(feature = "ebpf") ring buffer drainers.
    #[allow(dead_code)]
    pub fn from_process(ev: &ProcessEvent) -> Self {
        WireEvent::Process {
            kind: process_kind_name(ev.kind),
            timestamp_ns: ev.timestamp_ns,
            pid: ev.pid,
            ppid: ev.ppid,
            uid: ev.uid,
            exit_code: ev.exit_code,
            comm: trim_cstr(&ev.comm),
            filename: trim_cstr(&ev.filename),
        }
    }

    #[allow(dead_code)]
    pub fn from_net(ev: &NetEvent) -> Self {
        WireEvent::Network {
            kind: net_kind_name(ev.kind),
            timestamp_ns: ev.timestamp_ns,
            family: ev.family,
            sport: ev.sport,
            dport: ev.dport,
            drop_reason: ev.drop_reason,
            old_state: ev.old_state,
            new_state: ev.new_state,
            saddr: ev.saddr,
            daddr: ev.daddr,
        }
    }

    #[allow(dead_code)]
    pub fn from_security(ev: &SecurityEvent) -> Self {
        WireEvent::Security {
            kind: security_kind_name(ev.kind),
            severity: severity_name(ev.severity),
            timestamp_ns: ev.timestamp_ns,
            pid: ev.pid,
            ppid: ev.ppid,
            uid: ev.uid,
            arg: ev.arg,
            comm: trim_cstr(&ev.comm),
            filename: trim_cstr(&ev.filename),
        }
    }

    /// Wire-format subsystem tag, also used for server-side filtering.
    pub fn subsystem(&self) -> &'static str {
        match self {
            WireEvent::Process { .. } => "process",
            WireEvent::Network { .. } => "network",
            WireEvent::Security { .. } => "security",
        }
    }

    /// Returns the pid this event is associated with, if any. Used by the
    /// `?pid=` query filter on `/events/stream`. Network events currently
    /// carry no pid (would require correlating skb -> socket -> task).
    pub fn pid(&self) -> Option<u32> {
        match self {
            WireEvent::Process { pid, .. } => Some(*pid),
            WireEvent::Network { .. } => None,
            WireEvent::Security { pid, .. } => Some(*pid),
        }
    }
}

#[allow(dead_code)]
fn process_kind_name(k: u32) -> &'static str {
    // Matches agl_health_common::events::ProcessEventKind.
    match k {
        0 => "Exec",
        1 => "Exit",
        2 => "Fork",
        _ => "Unknown",
    }
}

#[allow(dead_code)]
fn net_kind_name(k: u32) -> &'static str {
    // Matches agl_health_common::events::NetEventKind.
    match k {
        0 => "SkbDrop",
        1 => "TcpRetransmit",
        2 => "TcpReset",
        3 => "TcpStateChange",
        _ => "Unknown",
    }
}

#[allow(dead_code)]
fn security_kind_name(k: u32) -> &'static str {
    // Matches agl_health_common::events::SecurityEventKind.
    match k {
        0 => "Ptrace",
        1 => "MemfdCreate",
        2 => "Prctl",
        3 => "Setuid",
        4 => "ExecAnomaly",
        5 => "CapabilityUse",
        _ => "Unknown",
    }
}

#[allow(dead_code)]
fn severity_name(s: u8) -> &'static str {
    // Matches agl_health_common::events::SecuritySeverity.
    match s {
        0 => "info",
        1 => "warn",
        2 => "critical",
        _ => "unknown",
    }
}

/// Trim a zero-padded kernel string at the first NUL byte and convert to
/// `String`, lossy on invalid UTF-8 (common for `comm` under exotic locales).
#[allow(dead_code)]
fn trim_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
