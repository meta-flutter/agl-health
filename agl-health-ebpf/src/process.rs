// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process lifecycle probes.
//!
//! Default (5.5+): `#[btf_tracepoint]` with `vmlinux::task_struct` for
//! type-safe access and `bpf_probe_read_kernel`.
//!
//! kernel-5-4: `#[tracepoint]` with raw format-struct args read via
//! `ctx.read_at`; parent/child PIDs come directly from the tracepoint
//! args, eliminating the need for `bpf_probe_read_kernel` in fork.

use core::mem;

use agl_health_common::events::{ProcessEvent, ProcessEventKind};
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    programs::ProbeContext,
};

// ----- map declarations -----

#[cfg(not(feature = "kernel-5-4"))]
use aya_ebpf::maps::RingBuf;
#[cfg(not(feature = "kernel-5-4"))]
#[map]
static PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[cfg(feature = "kernel-5-4")]
use aya_ebpf::maps::{PerCpuArray, PerfEventArray};
#[cfg(feature = "kernel-5-4")]
#[map]
static PROCESS_EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);
#[cfg(feature = "kernel-5-4")]
#[map]
static PROCESS_EVENT_SCRATCH: PerCpuArray<ProcessEvent> = PerCpuArray::with_max_entries(1, 0);

// ----- 5.5+ imports and programs -----

#[cfg(not(feature = "kernel-5-4"))]
use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::btf_tracepoint,
    programs::BtfTracePointContext,
};
#[cfg(not(feature = "kernel-5-4"))]
use crate::vmlinux::task_struct;

#[cfg(not(feature = "kernel-5-4"))]
#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(_ctx: BtfTracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    crate::stats::record_exec(pid, uid);
    let ppid = crate::stats::fetch_ppid(pid);
    let _ = emit_basic(ProcessEventKind::Exec, pid, ppid, uid, 0);
    0
}

#[cfg(not(feature = "kernel-5-4"))]
#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(_ctx: BtfTracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ppid = crate::stats::fetch_ppid(pid);
    let exit_code = crate::stats::take_exit_code(pid);
    if tid == pid {
        let _ = emit_basic(ProcessEventKind::Exit, pid, ppid, uid, exit_code);
        crate::stats::record_exit(pid);
    }
    crate::stats::record_thread_exit(tid);
    0
}

#[cfg(not(feature = "kernel-5-4"))]
#[btf_tracepoint(function = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> u32 {
    let parent: *const task_struct = unsafe { ctx.arg(0) };
    let child: *const task_struct = unsafe { ctx.arg(1) };

    let parent_tgid: i32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*parent).tgid))
    }
    .unwrap_or(0);
    let child_tgid: i32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*child).tgid))
    }
    .unwrap_or(0);

    let parent_pid = parent_tgid as u32;
    let child_pid = child_tgid as u32;

    let uid = bpf_get_current_uid_gid() as u32;
    let _ = emit_basic(ProcessEventKind::Fork, child_pid, parent_pid, uid, 0);
    crate::stats::record_exec(child_pid, uid);
    crate::stats::set_ppid(child_pid, parent_pid);
    0
}

// ----- kernel-5-4 tracepoint programs -----

// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
#[cfg(feature = "kernel-5-4")]
#[repr(C)]
struct SchedProcessExecArgs {
    _pad: [u8; 8],
    filename_off: u32,
    pid: u32,
    old_pid: u32,
}

// /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
#[cfg(feature = "kernel-5-4")]
#[repr(C)]
struct SchedProcessForkArgs {
    _pad: [u8; 8],
    parent_comm: [u8; 16],
    parent_pid: u32,
    child_comm: [u8; 16],
    child_pid: u32,
}

#[cfg(feature = "kernel-5-4")]
use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[cfg(feature = "kernel-5-4")]
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let args = match unsafe { ctx.read_at::<SchedProcessExecArgs>(0) } {
        Ok(a) => a,
        Err(_) => return 1,
    };
    let pid = args.pid;
    let uid = bpf_get_current_uid_gid() as u32;
    crate::stats::record_exec(pid, uid);
    let ppid = crate::stats::fetch_ppid(pid);
    let _ = emit_basic_perf(&ctx, ProcessEventKind::Exec, pid, ppid, uid, 0);
    0
}

#[cfg(feature = "kernel-5-4")]
#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ppid = crate::stats::fetch_ppid(pid);
    let exit_code = crate::stats::take_exit_code(pid);
    if tid == pid {
        let _ = emit_basic_perf(&ctx, ProcessEventKind::Exit, pid, ppid, uid, exit_code);
        crate::stats::record_exit(pid);
    }
    crate::stats::record_thread_exit(tid);
    0
}

/// `sched_process_fork` — 5.4 path.
/// Parent and child PIDs are direct fields; no probe read needed.
#[cfg(feature = "kernel-5-4")]
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let args = match unsafe { ctx.read_at::<SchedProcessForkArgs>(0) } {
        Ok(a) => a,
        Err(_) => return 1,
    };
    let parent_pid = args.parent_pid;
    let child_pid = args.child_pid;
    let uid = bpf_get_current_uid_gid() as u32;
    let _ = emit_basic_perf(&ctx, ProcessEventKind::Fork, child_pid, parent_pid, uid, 0);
    crate::stats::record_exec(child_pid, uid);
    crate::stats::set_ppid(child_pid, parent_pid);
    0
}

/// `kprobe:do_exit` — capture exit code before sched_process_exit.
#[kprobe]
pub fn do_exit(ctx: ProbeContext) -> u32 {
    let code: u64 = ctx.arg(0).unwrap_or(0);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    crate::stats::stash_exit_code(pid, code as i32);
    0
}

// ----- emit helpers -----

#[cfg(not(feature = "kernel-5-4"))]
fn emit_basic(
    kind: ProcessEventKind,
    pid: u32,
    ppid: u32,
    uid: u32,
    exit_code: i32,
) -> Result<(), ()> {
    let mut entry = match PROCESS_EVENTS.reserve::<ProcessEvent>(0) {
        Some(e) => e,
        None => {
            crate::stats::drop_process();
            return Err(());
        }
    };
    let ptr = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, mem::size_of::<ProcessEvent>());
        let ts = bpf_ktime_get_ns();
        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        (*ptr).kind = kind as u32;
        (*ptr).pid = pid;
        (*ptr).ppid = ppid;
        (*ptr).uid = uid;
        (*ptr).exit_code = exit_code;
        (*ptr).timestamp_ns = ts;
        (*ptr).comm = comm;
    }
    entry.submit(0);
    Ok(())
}

#[cfg(feature = "kernel-5-4")]
fn emit_basic_perf(
    ctx: &TracePointContext,
    kind: ProcessEventKind,
    pid: u32,
    ppid: u32,
    uid: u32,
    exit_code: i32,
) -> Result<(), ()> {
    let Some(scratch) = PROCESS_EVENT_SCRATCH.get_ptr_mut(0) else {
        crate::stats::drop_process();
        return Err(());
    };
    unsafe {
        core::ptr::write_bytes(scratch as *mut u8, 0, mem::size_of::<ProcessEvent>());
        (*scratch).kind = kind as u32;
        (*scratch).pid = pid;
        (*scratch).ppid = ppid;
        (*scratch).uid = uid;
        (*scratch).exit_code = exit_code;
        (*scratch).timestamp_ns = bpf_ktime_get_ns();
        (*scratch).comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    }
    PROCESS_EVENTS.output(ctx, unsafe { &*scratch }, 0);
    Ok(())
}
