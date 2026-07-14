// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Security-relevant syscall tracepoints.
//!
//! On kernels with `CONFIG_FTRACE_SYSCALLS=y` (and where the BSP exposes
//! the per-syscall tracepoints), four `syscalls:sys_enter_*` tracepoints
//! are used. On kernels that only expose `raw_syscalls:sys_enter` (e.g.
//! the Qualcomm AGL BSP kernel which strips per-syscall tracepoints), a
//! single `raw_syscalls:sys_enter` dispatcher is used instead.
//!
//! Both paths:
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
//!
//! Tracepoint format (`raw_syscalls:sys_enter`):
//!   offset 8:  long id      -- syscall number
//!   offset 16: long args[6] -- syscall arguments

use agl_health_common::{
    events::{SecurityEvent, SecurityEventKind, SecuritySeverity},
    metrics::SecurityEventCounts,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};

// ----- map declarations -----

#[cfg(not(feature = "kernel-5-4"))]
use aya_ebpf::maps::RingBuf;

/// Ring buffer for security events. Smaller than the process ring
/// because sustained rates are expected to be in the single digits
/// per second even on a busy system.
#[cfg(not(feature = "kernel-5-4"))]
#[map]
pub static SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[cfg(feature = "kernel-5-4")]
use aya_ebpf::maps::PerfEventArray;
#[cfg(feature = "kernel-5-4")]
#[map]
pub static SECURITY_EVENTS: PerfEventArray<SecurityEvent> = PerfEventArray::new(0);
#[cfg(feature = "kernel-5-4")]
#[map]
static SEC_EVENT_SCRATCH: PerCpuArray<SecurityEvent> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU cumulative counters, merged by the userspace aggregator.
#[map]
pub static SECURITY_COUNTS: PerCpuArray<SecurityEventCounts> =
    PerCpuArray::with_max_entries(1, 0);

// Use named constants from the shared offsets module.
use crate::offsets::{SYSCALL_ARG0 as ARG0, SYSCALL_ARG1 as ARG1};

// prctl PR_SET_DUMPABLE option number (from <sys/prctl.h>).
const PR_SET_DUMPABLE: u64 = 4;

// ARM64 syscall numbers (from arch/arm64/include/asm/unistd.h via uapi).
// Used by the raw_syscalls:sys_enter fallback path.
#[cfg(feature = "kernel-5-4")]
const SYS_PTRACE: u64 = 117;
#[cfg(feature = "kernel-5-4")]
const SYS_PRCTL: u64 = 167;
#[cfg(feature = "kernel-5-4")]
const SYS_SETUID: u64 = 146;
#[cfg(feature = "kernel-5-4")]
const SYS_MEMFD_CREATE: u64 = 279;

/// Minimum spacing between discrete `SecurityEvent` emissions of the same
/// kind on a given CPU. The exact per-call counts are still accumulated in
/// `SECURITY_COUNTS` regardless; this only throttles the discrete anomaly
/// feed so a syscall storm (debuggers, container runtimes) can't overflow
/// the 64 KiB ring and starve genuinely rare events. 50 ms ⇒ ≤20
/// emits/sec/kind/CPU.
const EMIT_MIN_INTERVAL_NS: u64 = 50_000_000;

/// Per-CPU last-emit timestamp for each gated kind, indexed by the `slot`
/// passed to `emit` (Ptrace=0, MemfdCreate=1, Setuid=2, Prctl=3).
#[repr(C)]
#[derive(Clone, Copy)]
struct EmitGate {
    last_ns: [u64; 4],
}

#[map]
static SEC_EMIT_GATE: PerCpuArray<EmitGate> = PerCpuArray::with_max_entries(1, 0);

/// Returns true if an emit for `slot` should be suppressed because the
/// previous one was too recent. Records `now` as the new last-emit time
/// when it allows the emit through.
fn rate_limited(slot: usize, now: u64) -> bool {
    // Mask keeps the index provably in-bounds for the BPF verifier.
    let slot = slot & 3;
    let Some(g) = SEC_EMIT_GATE.get_ptr_mut(0) else {
        return false;
    };
    // SAFETY: valid per-CPU slot; BPF preemption disabled.
    unsafe {
        if now.saturating_sub((*g).last_ns[slot]) < EMIT_MIN_INTERVAL_NS {
            return true;
        }
        (*g).last_ns[slot] = now;
    }
    false
}

/// `syscalls:sys_enter_ptrace` — per-syscall tracepoint path (non-5-4 kernels).
#[cfg(not(feature = "kernel-5-4"))]
#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    let request: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
    bump(|c| c.ptrace = c.ptrace.wrapping_add(1));
    let _ = emit(&ctx, SecurityEventKind::Ptrace, SecuritySeverity::Warn, request, 0);
    0
}

/// `syscalls:sys_enter_memfd_create` — per-syscall tracepoint path (non-5-4 kernels).
#[cfg(not(feature = "kernel-5-4"))]
#[tracepoint]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    bump(|c| c.memfd_create = c.memfd_create.wrapping_add(1));
    let _ = emit(&ctx, SecurityEventKind::MemfdCreate, SecuritySeverity::Warn, 0, 1);
    0
}

/// `syscalls:sys_enter_setuid` — per-syscall tracepoint path (non-5-4 kernels).
#[cfg(not(feature = "kernel-5-4"))]
#[tracepoint]
pub fn sys_enter_setuid(ctx: TracePointContext) -> u32 {
    let new_uid: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
    bump(|c| c.setuid = c.setuid.wrapping_add(1));
    let _ = emit(&ctx, SecurityEventKind::Setuid, SecuritySeverity::Warn, new_uid, 2);
    0
}

/// `syscalls:sys_enter_prctl` — per-syscall tracepoint path (non-5-4 kernels).
/// Counts every call; only emits events for the `PR_SET_DUMPABLE=0` pattern.
#[cfg(not(feature = "kernel-5-4"))]
#[tracepoint]
pub fn sys_enter_prctl(ctx: TracePointContext) -> u32 {
    let option: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
    let arg2: u64 = unsafe { ctx.read_at::<u64>(ARG1) }.unwrap_or(0);
    bump(|c| c.prctl = c.prctl.wrapping_add(1));
    if option == PR_SET_DUMPABLE && arg2 == 0 {
        let _ = emit(&ctx, SecurityEventKind::Prctl, SecuritySeverity::Warn, option, 3);
    }
    0
}

/// `raw_syscalls:sys_enter` — single dispatcher for kernels that expose only
/// the raw tracepoint (e.g. Qualcomm BSP 5.4 kernels with per-syscall
/// tracepoints stripped). Dispatches on the syscall number to the same
/// per-syscall logic as the non-5-4 path.
#[cfg(feature = "kernel-5-4")]
#[tracepoint]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    use crate::offsets::RAW_SYSCALL_NR;
    let nr: u64 = unsafe { ctx.read_at::<u64>(RAW_SYSCALL_NR) }.unwrap_or(u64::MAX);
    match nr {
        SYS_PTRACE => {
            let request: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
            bump(|c| c.ptrace = c.ptrace.wrapping_add(1));
            let _ = emit(&ctx, SecurityEventKind::Ptrace, SecuritySeverity::Warn, request, 0);
        }
        SYS_MEMFD_CREATE => {
            bump(|c| c.memfd_create = c.memfd_create.wrapping_add(1));
            let _ = emit(&ctx, SecurityEventKind::MemfdCreate, SecuritySeverity::Warn, 0, 1);
        }
        SYS_SETUID => {
            let new_uid: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
            bump(|c| c.setuid = c.setuid.wrapping_add(1));
            let _ = emit(&ctx, SecurityEventKind::Setuid, SecuritySeverity::Warn, new_uid, 2);
        }
        SYS_PRCTL => {
            let option: u64 = unsafe { ctx.read_at::<u64>(ARG0) }.unwrap_or(0);
            let arg2: u64 = unsafe { ctx.read_at::<u64>(ARG1) }.unwrap_or(0);
            bump(|c| c.prctl = c.prctl.wrapping_add(1));
            if option == PR_SET_DUMPABLE && arg2 == 0 {
                let _ = emit(&ctx, SecurityEventKind::Prctl, SecuritySeverity::Warn, option, 3);
            }
        }
        _ => {}
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

#[cfg(not(feature = "kernel-5-4"))]
fn emit(
    _ctx: &TracePointContext,
    kind: SecurityEventKind,
    severity: SecuritySeverity,
    arg: u64,
    slot: usize,
) -> Result<(), ()> {
    let ts = unsafe { bpf_ktime_get_ns() };
    if rate_limited(slot, ts) {
        return Ok(());
    }
    let mut entry = match SECURITY_EVENTS.reserve::<SecurityEvent>(0) {
        Some(e) => e,
        None => {
            crate::stats::drop_security();
            return Err(());
        }
    };
    let ptr = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<SecurityEvent>());
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

#[cfg(feature = "kernel-5-4")]
fn emit(
    ctx: &TracePointContext,
    kind: SecurityEventKind,
    severity: SecuritySeverity,
    arg: u64,
    slot: usize,
) -> Result<(), ()> {
    let ts = unsafe { bpf_ktime_get_ns() };
    if rate_limited(slot, ts) {
        return Ok(());
    }
    let Some(scratch) = SEC_EVENT_SCRATCH.get_ptr_mut(0) else {
        crate::stats::drop_security();
        return Err(());
    };
    unsafe {
        core::ptr::write_bytes(scratch as *mut u8, 0, core::mem::size_of::<SecurityEvent>());
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let uid = bpf_get_current_uid_gid() as u32;
        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        let ppid = crate::stats::fetch_ppid(pid);
        (*scratch).kind = kind as u32;
        (*scratch).pid = pid;
        (*scratch).ppid = ppid;
        (*scratch).uid = uid;
        (*scratch).severity = severity as u8;
        (*scratch).arg = arg;
        (*scratch).timestamp_ns = ts;
        (*scratch).comm = comm;
    }
    SECURITY_EVENTS.output(ctx, unsafe { &*scratch }, 0);
    Ok(())
}
