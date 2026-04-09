//! Process lifecycle probes.
//!
//! Hooks the sched tracepoints that fire on every `execve`, task exit,
//! and process fork, plus a kprobe on `do_exit` that captures the
//! exit code argument before `sched_process_exit` fires.
//!
//! Each tracepoint reserves a `ProcessEvent` from the shared
//! `PROCESS_EVENTS` ring buffer, populates every field it can, and
//! submits. Values sourced at this level (no CO-RE task_struct access
//! required):
//!
//!   * `pid`       - `bpf_get_current_pid_tgid() >> 32`
//!   * `uid`       - `bpf_get_current_uid_gid()`
//!   * `comm`      - `bpf_get_current_comm()`
//!   * `ppid`      - For fork: `parent_pid` at tracepoint offset 24.
//!                   For exec/exit: `PROCESS_STATS[pid].ppid` written
//!                   by an earlier fork.
//!   * `filename`  - For exec: `__data_loc` header at tracepoint offset 8
//!                   pointing into the ring buffer's variable section;
//!                   copied via `bpf_probe_read_kernel_str_bytes`.
//!   * `exit_code` - For exit: drained from `EXIT_CODES`, which is
//!                   populated by the `do_exit` kprobe.

use core::mem;

use agl_health_common::{
    events::{ProcessEvent, ProcessEventKind},
    FILENAME_LEN,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};

/// Ring buffer carrying process lifecycle events to userspace.
/// 256 KiB absorbs bursts; the userspace consumer drains it via AsyncFd.
#[map]
static PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// `sched:sched_process_exec` - every successful `execve`.
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    // Update per-process stats first so the aggregator sees the new
    // comm on its next poll even if the ring buffer is full.
    crate::stats::record_exec(pid, uid);

    let ppid = crate::stats::fetch_ppid(pid);
    let _ = emit_exec(&ctx, pid, ppid, uid);
    0
}

/// `sched:sched_process_exit` - task removed from the tree.
#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ppid = crate::stats::fetch_ppid(pid);
    let exit_code = crate::stats::take_exit_code(pid);

    let _ = emit_basic(ProcessEventKind::Exit, pid, ppid, uid, exit_code);
    crate::stats::record_exit(pid);
    0
}

/// `sched:sched_process_fork` - new child `task_struct` installed.
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    // Offsets from /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
    //   parent_pid @ 24
    //   child_pid  @ 44
    let parent_pid: u32 = unsafe { ctx.read_at::<u32>(24) }.unwrap_or(0);
    let child_pid: u32 = match unsafe { ctx.read_at::<u32>(44) } {
        Ok(v) => v,
        Err(_) => return 1,
    };

    // Emit the Fork event with the child's pid and a correct ppid -
    // this is the one lifecycle event where ppid is free.
    let uid = bpf_get_current_uid_gid() as u32;
    let _ = emit_basic(ProcessEventKind::Fork, child_pid, parent_pid, uid, 0);

    // Remember the relationship so later Exec/Exit events for this pid
    // can report ppid without a CO-RE `task->real_parent->tgid` read.
    crate::stats::record_exec(child_pid, uid);
    crate::stats::set_ppid(child_pid, parent_pid);
    0
}

/// `kprobe:do_exit` - capture the raw `long code` argument before the
/// sched tracepoint fires. do_exit fires for every thread; the
/// last-write-wins semantics give us the tgid leader's code by the
/// time sched_process_exit drains it.
#[kprobe]
pub fn do_exit(ctx: ProbeContext) -> u32 {
    // On every supported arch the first argument is in the first
    // register (RDI on x86_64, X0 on aarch64). aya hides that behind
    // ProbeContext::arg(0).
    let code: u64 = ctx.arg(0).unwrap_or(0);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    crate::stats::stash_exit_code(pid, code as i32);
    0
}

// ----- helpers ---------------------------------------------------------

/// Emit a process event with no filename. Used for Exit, Fork, and as
/// the fallback path for Exec when the data_loc read fails.
fn emit_basic(
    kind: ProcessEventKind,
    pid: u32,
    ppid: u32,
    uid: u32,
    exit_code: i32,
) -> Result<(), ()> {
    let mut entry = PROCESS_EVENTS.reserve::<ProcessEvent>(0).ok_or(())?;
    let ptr = entry.as_mut_ptr();
    // SAFETY: ptr is a valid, aligned pointer to uninitialized ring
    // buffer memory reserved by the kernel. write_bytes zeros it.
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, mem::size_of::<ProcessEvent>());
        fill_common(ptr, kind, pid, ppid, uid, exit_code);
    }
    entry.submit(0);
    Ok(())
}

/// Emit an `Exec` event, also copying the executable filename from the
/// `__data_loc` tracepoint header into the `filename` field.
///
/// Tracepoint format for `sched:sched_process_exec`:
///
/// ```text
/// field:__data_loc char[] filename;  offset:8;  size:4
/// field:pid_t pid;                   offset:12; size:4
/// ```
///
/// The `__data_loc` u32 value packs `(offset << 16) | length`, where
/// the offset is relative to the start of the tracepoint payload.
fn emit_exec(ctx: &TracePointContext, pid: u32, ppid: u32, uid: u32) -> Result<(), ()> {
    let mut entry = PROCESS_EVENTS.reserve::<ProcessEvent>(0).ok_or(())?;
    let ptr = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, mem::size_of::<ProcessEvent>());
        fill_common(ptr, ProcessEventKind::Exec, pid, ppid, uid, 0);
    }

    // Read the __data_loc header. Failure here is non-fatal - we still
    // submit the event, just with an empty filename.
    let data_loc: u32 = unsafe { ctx.read_at::<u32>(8) }.unwrap_or(0);
    if data_loc != 0 {
        let name_off = (data_loc & 0xffff) as usize;
        // Use a stack buffer so we don't hold a raw slice into ring
        // buffer memory across an unsafe helper call. 256 bytes is
        // within the BPF 512-byte stack limit.
        let mut buf = [0u8; FILENAME_LEN];
        let base = ctx.as_ptr() as *const u8;
        // SAFETY: `base.add(name_off)` is kernel memory populated by
        // the tracepoint infrastructure. The helper performs a bounded
        // read and null-terminates `buf` on success. Errors leave buf
        // unchanged (still zero-initialized).
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(base.add(name_off), &mut buf)
        };
        unsafe {
            (*ptr).filename = buf;
        }
    }

    entry.submit(0);
    Ok(())
}

/// Fill the per-event fields every kind shares. `ptr` must point at a
/// zeroed `ProcessEvent`.
///
/// SAFETY: caller guarantees `ptr` is valid, aligned, and zeroed.
unsafe fn fill_common(
    ptr: *mut ProcessEvent,
    kind: ProcessEventKind,
    pid: u32,
    ppid: u32,
    uid: u32,
    exit_code: i32,
) {
    let ts = unsafe { bpf_ktime_get_ns() };
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    unsafe {
        (*ptr).kind = kind as u32;
        (*ptr).pid = pid;
        (*ptr).ppid = ppid;
        (*ptr).uid = uid;
        (*ptr).exit_code = exit_code;
        (*ptr).timestamp_ns = ts;
        (*ptr).comm = comm;
    }
}
