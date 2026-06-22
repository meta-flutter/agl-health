// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Event types streamed from kernel-side eBPF programs through `bpf_ringbuf`
//! to the userspace daemon.
//!
//! Every type is `#[repr(C)]` and contains only fixed-size fields so it can be
//! written directly into a ring buffer from BPF and read back in userspace
//! without serialization.

use crate::{COMM_LEN, FILENAME_LEN};

#[cfg(feature = "user")]
use serde::Serialize;
#[cfg(feature = "user")]
use serde_big_array::BigArray;

/// Process lifecycle event kind.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub enum ProcessEventKind {
    Exec = 0,
    Exit = 1,
    Fork = 2,
}

/// `sched:sched_process_{exec,exit,fork}` event.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct ProcessEvent {
    pub kind: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exit_code: i32,
    /// C-ABI alignment padding. Excluded from the JSON wire format.
    #[cfg_attr(feature = "user", serde(skip))]
    pub _pad: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_LEN],
    #[cfg_attr(feature = "user", serde(with = "BigArray"))]
    pub filename: [u8; FILENAME_LEN],
}

/// Network event kind.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub enum NetEventKind {
    SkbDrop = 0,
    TcpRetransmit = 1,
    TcpReset = 2,
    TcpStateChange = 3,
}

/// Network event from `skb:kfree_skb`, `tcp:tcp_retransmit_skb`,
/// `sock:inet_sock_set_state`, etc.
///
/// Addresses are stored as 16-byte fields to accommodate both IPv4
/// (in the low 4 bytes) and IPv6.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct NetEvent {
    pub kind: u32,
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    pub drop_reason: u16,
    pub old_state: u8,
    pub new_state: u8,
    /// C-ABI alignment padding. Excluded from the JSON wire format.
    #[cfg_attr(feature = "user", serde(skip))]
    pub _pad: [u8; 2],
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub timestamp_ns: u64,
}

/// Scheduler event kind.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub enum SchedEventKind {
    Wakeup = 0,
    Switch = 1,
    Migrate = 2,
    ThrottleWait = 3,
}

/// Low-frequency scheduler events (high-frequency data goes through the
/// `SchedHistogram` BPF map, not this event stream).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct SchedEvent {
    pub kind: u32,
    pub pid: u32,
    pub prio: i32,
    pub cpu: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_LEN],
}

/// File I/O event kind.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub enum FileEventKind {
    Open = 0,
    Read = 1,
    Write = 2,
    Fsync = 3,
    Unlink = 4,
    Rename = 5,
}

/// File I/O event from the `fileio.rs` eBPF program.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct FileEvent {
    pub kind: u32,
    pub pid: u32,
    pub bytes: i64,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_LEN],
    #[cfg_attr(feature = "user", serde(with = "BigArray"))]
    pub filename: [u8; FILENAME_LEN],
}

/// Security event kind (see §5.7 of the implementation plan).
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub enum SecurityEventKind {
    Ptrace = 0,
    MemfdCreate = 1,
    Prctl = 2,
    Setuid = 3,
    ExecAnomaly = 4,
    CapabilityUse = 5,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub enum SecuritySeverity {
    Info = 0,
    Warn = 1,
    Critical = 2,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct SecurityEvent {
    pub kind: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub severity: u8,
    /// C-ABI alignment padding. Excluded from the JSON wire format.
    #[cfg_attr(feature = "user", serde(skip))]
    pub _pad: [u8; 7],
    pub arg: u64,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_LEN],
    #[cfg_attr(feature = "user", serde(with = "BigArray"))]
    pub filename: [u8; FILENAME_LEN],
}
