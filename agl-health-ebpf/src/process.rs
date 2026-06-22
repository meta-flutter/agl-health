//! Process lifecycle probes — btf_tracepoint versions.
//!
//! Uses `#[btf_tracepoint]` with `vmlinux::task_struct` for type-safe
//! access to parent/child task pointers. Eliminates all hardcoded
//! tracepoint format offsets.

use core::mem;

use agl_health_common::events::{ProcessEvent, ProcessEventKind};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::{btf_tracepoint, kprobe, map},
    maps::RingBuf,
    programs::{BtfTracePointContext, ProbeContext},
};

use crate::vmlinux::task_struct;

#[map]
static PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// `sched_process_exec(struct task_struct *p, pid_t old_pid,
///                     struct linux_binprm *bprm)`
#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(_ctx: BtfTracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    crate::stats::record_exec(pid, uid);
    let ppid = crate::stats::fetch_ppid(pid);
    // Note: filename extraction from `bprm` would require
    // bpf_probe_read_kernel on bprm->filename — deferred.
    let _ = emit_basic(ProcessEventKind::Exec, pid, ppid, uid, 0);
    0
}

/// `sched_process_exit(struct task_struct *p)`
#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(_ctx: BtfTracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ppid = crate::stats::fetch_ppid(pid);
    let exit_code = crate::stats::take_exit_code(pid);
    // Only the thread-group leader's exit is a real process exit worth
    // emitting; per-thread exits still need their transient scheduler
    // entries reclaimed (see record_thread_exit).
    if tid == pid {
        let _ = emit_basic(ProcessEventKind::Exit, pid, ppid, uid, exit_code);
        crate::stats::record_exit(pid);
    }
    crate::stats::record_thread_exit(tid);
    0
}

/// `sched_process_fork(struct task_struct *parent,
///                     struct task_struct *child)`
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

/// `kprobe:do_exit` — capture exit code before sched_process_exit.
#[kprobe]
pub fn do_exit(ctx: ProbeContext) -> u32 {
    let code: u64 = ctx.arg(0).unwrap_or(0);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    crate::stats::stash_exit_code(pid, code as i32);
    0
}

// ----- helpers -----

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
