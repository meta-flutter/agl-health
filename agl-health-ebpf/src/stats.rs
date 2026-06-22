//! Per-process accounting map + helpers, shared between `process.rs`
//! (lifecycle probes) and `scheduler.rs` (on-CPU slice accounting).
//!
//! Two maps live here:
//!
//! * `PROCESS_STATS` - `HashMap<u32, ProcessStats>` keyed by pid. The
//!   userspace aggregator polls this every second, sorts by
//!   `cpu_user_ns`, and publishes the top-N via `/metrics/process`.
//!
//! * `ONCPU_SINCE` - `HashMap<u32, u64>` keyed by pid, holding the
//!   `bpf_ktime_get_ns()` timestamp at which the task was placed on a
//!   CPU. `sched_switch` reads this when the task goes off-CPU to
//!   compute the slice duration.
//!
//! Lifecycle:
//!
//!   exec        -> record_exec: set pid/uid/start_time_ns/comm
//!   fork        -> record_exec for the child (inherits parent uid)
//!   on-CPU      -> sched_switch inserts into ONCPU_SINCE
//!   off-CPU     -> sched_switch computes slice, removes ONCPU_SINCE entry,
//!                  accumulates cpu_user_ns and ctx_switch counters
//!   exit        -> record_exit: remove from both maps

use agl_health_common::metrics::{EventDropCounts, ProcessStats};
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_ktime_get_ns},
    macros::map,
    maps::{HashMap, PerCpuArray},
};

/// Per-pid accumulated process stats. 4096 entries comfortably covers an
/// IVI workload (hundreds of processes at most) with headroom for bursts.
#[map]
pub static PROCESS_STATS: HashMap<u32, ProcessStats> =
    HashMap::<u32, ProcessStats>::with_max_entries(4096, 0);

/// Per-pid on-CPU timestamp. Transient - entries are removed the moment
/// the task goes off-CPU, so steady-state population == number of
/// currently-running tasks == one per online CPU.
#[map]
pub static ONCPU_SINCE: HashMap<u32, u64> =
    HashMap::<u32, u64>::with_max_entries(4096, 0);

/// Per-pid exit code stashed by the `do_exit` kprobe and drained by the
/// `sched_process_exit` tracepoint when it emits the `Exit` event.
/// `do_exit` fires for every thread; the last write for a tgid wins,
/// which matches what userspace actually wants (the leader's code).
#[map]
pub static EXIT_CODES: HashMap<u32, i32> =
    HashMap::<u32, i32>::with_max_entries(4096, 0);

/// Per-CPU counters for ring-buffer events that had to be dropped because
/// the buffer was full at reserve time. The userspace aggregator sums and
/// logs these so silent event loss becomes observable.
#[map]
pub static EVENT_DROPS: PerCpuArray<EventDropCounts> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn bump_drop(f: impl FnOnce(&mut EventDropCounts)) {
    if let Some(p) = EVENT_DROPS.get_ptr_mut(0) {
        // SAFETY: valid per-CPU slot; BPF preemption disabled.
        unsafe { f(&mut *p) }
    }
}

/// Record a dropped `PROCESS_EVENTS` ring entry.
pub fn drop_process() {
    bump_drop(|d| d.process = d.process.wrapping_add(1));
}

/// Record a dropped `SECURITY_EVENTS` ring entry.
pub fn drop_security() {
    bump_drop(|d| d.security = d.security.wrapping_add(1));
}

/// Record a dropped `NET_EVENTS` ring entry.
pub fn drop_network() {
    bump_drop(|d| d.network = d.network.wrapping_add(1));
}

/// Ensure a `PROCESS_STATS` entry exists for `pid`. Returns a mutable
/// pointer into the map slot, or `None` if the insert failed (map full).
///
/// Callers that already have a populated pointer should avoid this helper
/// to skip a second map lookup.
pub fn upsert(pid: u32) -> Option<*mut ProcessStats> {
    if let Some(p) = PROCESS_STATS.get_ptr_mut(&pid) {
        return Some(p);
    }
    // SAFETY: ProcessStats is #[repr(C)] POD of integers + a byte array;
    // an all-zero bit pattern is a valid instance.
    let fresh: ProcessStats = unsafe { core::mem::zeroed() };
    if PROCESS_STATS.insert(&pid, &fresh, 0).is_ok() {
        PROCESS_STATS.get_ptr_mut(&pid)
    } else {
        None
    }
}

/// Record an `exec` (or `fork`, for the child) by writing identity fields
/// into `PROCESS_STATS[pid]`. Leaves accumulators (cpu, ctx switches)
/// untouched so repeated execs by the same pid don't reset counters.
pub fn record_exec(pid: u32, uid: u32) {
    let Some(ptr) = upsert(pid) else {
        return;
    };
    let ts = unsafe { bpf_ktime_get_ns() };
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    // SAFETY: `ptr` is a valid, aligned pointer into a HashMap slot.
    unsafe {
        (*ptr).pid = pid;
        (*ptr).uid = uid;
        (*ptr).start_time_ns = ts;
        (*ptr).comm = comm;
    }
}

/// Remove a tgid's process-level entries. Called from `sched_process_exit`
/// with the thread-group id so the map size stays bounded by the
/// live-process count.
pub fn record_exit(pid: u32) {
    let _ = PROCESS_STATS.remove(&pid);
    let _ = ONCPU_SINCE.remove(&pid);
    let _ = EXIT_CODES.remove(&pid);
}

/// Remove a thread's transient scheduler entries. `ONCPU_SINCE` and
/// `WAKEUP_TIMES` are keyed by the per-thread pid (`task_struct.pid`),
/// not the tgid, so they must be cleaned with the thread id on every
/// thread exit — otherwise a task woken but never scheduled (or whose
/// off-CPU switch is missed) leaks an entry until the map fills and all
/// further scheduler accounting silently stops.
pub fn record_thread_exit(tid: u32) {
    let _ = ONCPU_SINCE.remove(&tid);
    let _ = crate::scheduler::WAKEUP_TIMES.remove(&tid);
}

/// Set `ProcessStats.ppid` for a pid, creating the entry if needed.
/// Called from `sched_process_fork` so every later `Exec`/`Exit` event
/// for this pid can report the right parent tgid.
pub fn set_ppid(pid: u32, ppid: u32) {
    let Some(ptr) = upsert(pid) else {
        return;
    };
    // SAFETY: upsert returns a valid pointer into a HashMap slot.
    unsafe {
        (*ptr).pid = pid;
        (*ptr).ppid = ppid;
    }
}

/// Look up a pid's ppid without creating an entry. Returns 0 for pids
/// we haven't seen exec/fork for (typically pre-existing processes).
pub fn fetch_ppid(pid: u32) -> u32 {
    // SAFETY: HashMap::get returns a pointer into the map that is valid
    // for the duration of this program.
    unsafe { PROCESS_STATS.get(&pid).map(|s| s.ppid).unwrap_or(0) }
}

/// Called from the `do_exit` kprobe with the raw `long code` argument.
/// Stores the low 32 bits (sufficient for both normal exits and signal
/// codes) keyed by the current tgid.
pub fn stash_exit_code(pid: u32, code: i32) {
    let _ = EXIT_CODES.insert(&pid, &code, 0);
}

/// Drain the stashed exit code for a pid. Returns 0 and a no-op remove
/// when no stash exists.
pub fn take_exit_code(pid: u32) -> i32 {
    // SAFETY: same as fetch_ppid.
    let code = unsafe { EXIT_CODES.get(&pid).copied().unwrap_or(0) };
    let _ = EXIT_CODES.remove(&pid);
    code
}
