//! Security-relevant syscall tracepoints.
//!
//! Four `syscalls:sys_enter_*` tracepoints. For each event we both:
//!
//!   * bump the corresponding field in `SECURITY_COUNTS` (a per-CPU
//!     `SecurityEventCounts` that the aggregator sums once per second); and
//!   * emit a `SecurityEvent` on `SECURITY_EVENTS` so the Flutter
//!     Security tab can show a discrete anomaly feed.
//!
//! `prctl` is special: it counts every call but only *emits* an event
//! when the specific "`PR_SET_DUMPABLE` = 0" pattern is used, which is
//! the classic "hide from core dump" anti-forensics trick. Every other
//! prctl use (thread naming, seccomp setup, etc.) is noise for this
//! dashboard.
//!
//! Tracepoint format (`syscalls:sys_enter_*`): after the 8-byte common
//! header and the `__syscall_nr` field, syscall arguments begin at
//! offset 16 as 8-byte values (`long` regardless of the userspace
//! argument width).

use agl_health_common::{
    events::{SecurityEvent, SecurityEventKind, SecuritySeverity},
    metrics::SecurityEventCounts,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};

/// Ring buffer for security events. Smaller than the process ring
/// because sustained rates are expected to be in the single digits
/// per second even on a busy system.
#[map]
pub static SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Per-CPU cumulative counters, merged by the userspace aggregator.
#[map]
pub static SECURITY_COUNTS: PerCpuArray<SecurityEventCounts> =
    PerCpuArray::with_max_entries(1, 0);

// Argument offsets for syscalls:sys_enter_* tracepoints.
const ARG0: usize = 16;
const ARG1: usize = 24;

// prctl PR_SET_DUMPABLE option number (from <sys/prctl.h>).
const PR_SET_DUMPABLE: u64 = 4;

/// `syscalls:sys_enter_ptrace`.
#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    let request: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
    bump(|c| c.ptrace = c.ptrace.wrapping_add(1));
    let _ = emit(SecurityEventKind::Ptrace, SecuritySeverity::Warn, request);
    0
}

/// `syscalls:sys_enter_memfd_create`.
#[tracepoint]
pub fn sys_enter_memfd_create(_ctx: TracePointContext) -> u32 {
    bump(|c| c.memfd_create = c.memfd_create.wrapping_add(1));
    let _ = emit(SecurityEventKind::MemfdCreate, SecuritySeverity::Warn, 0);
    0
}

/// `syscalls:sys_enter_setuid`.
#[tracepoint]
pub fn sys_enter_setuid(ctx: TracePointContext) -> u32 {
    let new_uid: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
    bump(|c| c.setuid = c.setuid.wrapping_add(1));
    let _ = emit(SecurityEventKind::Setuid, SecuritySeverity::Warn, new_uid);
    0
}

/// `syscalls:sys_enter_prctl` - counts every call; only emits events
/// for the `PR_SET_DUMPABLE=0` pattern to avoid flooding the ring.
#[tracepoint]
pub fn sys_enter_prctl(ctx: TracePointContext) -> u32 {
    let option: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
    let arg2: u64 = unsafe { ctx.read_at::<u64>(ARG1) }.unwrap_or(0);
    bump(|c| c.prctl = c.prctl.wrapping_add(1));
    if option == PR_SET_DUMPABLE && arg2 == 0 {
        let _ = emit(SecurityEventKind::Prctl, SecuritySeverity::Warn, option);
    }
    0
}

// ----- helpers ---------------------------------------------------------

fn bump(f: impl FnOnce(&mut SecurityEventCounts)) {
    let Some(ptr) = SECURITY_COUNTS.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: valid per-CPU slot; BPF preemption disabled.
    unsafe {
        f(&mut *ptr);
    }
}

fn emit(kind: SecurityEventKind, severity: SecuritySeverity, arg: u64) -> Result<(), ()> {
    let mut entry = SECURITY_EVENTS.reserve::<SecurityEvent>(0).ok_or(())?;
    let ptr = entry.as_mut_ptr();
    // SAFETY: ptr is valid, aligned, reserved ring buffer memory.
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<SecurityEvent>());
        let ts = bpf_ktime_get_ns();
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let uid = bpf_get_current_uid_gid() as u32;
        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        let ppid = crate::stats::fetch_ppid(pid);
        (*ptr).kind = kind as u32;
        (*ptr).pid = pid;
        (*ptr).ppid = ppid;
        (*ptr).uid = uid;
        (*ptr).severity = severity as u8;
        (*ptr).arg = arg;
        (*ptr).timestamp_ns = ts;
        (*ptr).comm = comm;
    }
    entry.submit(0);
    Ok(())
}
