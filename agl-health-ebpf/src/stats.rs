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

use agl_health_common::metrics::ProcessStats;
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_ktime_get_ns},
    macros::map,
    maps::HashMap,
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

/// Remove a pid from both maps. Called from `sched_process_exit` so the
/// map size stays bounded by the live-process count.
pub fn record_exit(pid: u32) {
    let _ = PROCESS_STATS.remove(&pid);
    let _ = ONCPU_SINCE.remove(&pid);
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
