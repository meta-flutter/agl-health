//! Scheduler probes.
//!
//! High-frequency scheduler tracepoints (wakeup, switch) fire hundreds of
//! thousands of times per second on a busy system. Streaming individual
//! events to userspace is infeasible, so we compute runqueue-wait latency
//! entirely in the kernel and keep the result in a per-CPU histogram:
//!
//!   1. `sched:sched_wakeup` stores `bpf_ktime_get_ns()` keyed by the
//!      newly-runnable task's pid in `WAKEUP_TIMES`.
//!   2. `sched:sched_switch` looks up `next_pid`, computes
//!      `now - wakeup_ts`, and buckets the delta into the per-CPU
//!      `SCHED_HISTOGRAM` entry using 8 log-spaced buckets
//!      (<10us .. >=10s).
//!
//! The userspace aggregator polls `SCHED_HISTOGRAM` once per second,
//! reduces across CPUs, and derives p50/p95/p99/max percentiles.

use agl_health_common::{metrics::SchedHistogram, SCHED_HIST_BUCKETS};
use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray},
    programs::TracePointContext,
};

/// Per-pid map of the most recent `sched_wakeup` timestamp. Entries are
/// consumed (read, used, left in place for the next wakeup) by sched_switch.
#[map]
static WAKEUP_TIMES: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(10240, 0);

/// One `SchedHistogram` per CPU. Slot 0 is the only index - PerCpuArray
/// already gives us per-CPU semantics "for free".
#[map]
static SCHED_HISTOGRAM: PerCpuArray<SchedHistogram> = PerCpuArray::with_max_entries(1, 0);

/// `sched:sched_wakeup` - task becomes runnable.
///
/// Tracepoint format:
///   field:pid_t pid; offset:24; size:4
#[tracepoint]
pub fn sched_wakeup(ctx: TracePointContext) -> u32 {
    match try_wakeup(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn try_wakeup(ctx: &TracePointContext) -> Result<(), ()> {
    let pid: u32 = unsafe { ctx.read_at::<u32>(24) }.map_err(|_| ())?;
    let ts = unsafe { bpf_ktime_get_ns() };
    // BPF_ANY (0): insert or overwrite. A rapid re-wakeup is perfectly fine;
    // we always want the most recent timestamp.
    let _ = WAKEUP_TIMES.insert(&pid, &ts, 0);
    Ok(())
}

/// `sched:sched_switch` - scheduler picks a new task to run.
///
/// Tracepoint format (x86-64, representative):
///   field:pid_t next_pid; offset:56; size:4
#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_switch(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn try_switch(ctx: &TracePointContext) -> Result<(), ()> {
    // Tracepoint format offsets:
    //   prev_comm  [16]  @ 8
    //   prev_pid         @ 24
    //   prev_state long  @ 32  (i64 on 64-bit; TASK_RUNNING == 0 means
    //                           the task was still runnable i.e. preempted)
    //   next_comm  [16]  @ 40
    //   next_pid         @ 56
    let prev_pid: u32 = unsafe { ctx.read_at::<u32>(24) }.unwrap_or(0);
    let prev_state: i64 = unsafe { ctx.read_at::<i64>(32) }.unwrap_or(-1);
    let prev_comm: [u8; 16] = unsafe { ctx.read_at::<[u8; 16]>(8) }.unwrap_or([0u8; 16]);
    let next_pid: u32 = unsafe { ctx.read_at::<u32>(56) }.map_err(|_| ())?;
    let next_comm: [u8; 16] = unsafe { ctx.read_at::<[u8; 16]>(40) }.unwrap_or([0u8; 16]);
    let now = unsafe { bpf_ktime_get_ns() };

    // (1) Runqueue-wait histogram for next_pid. PID 0 is the idle task -
    //     no meaningful wait to measure.
    if next_pid != 0 {
        if let Some(wakeup_ts) = unsafe { WAKEUP_TIMES.get(&next_pid) } {
            let delta = now.saturating_sub(*wakeup_ts);
            let _ = WAKEUP_TIMES.remove(&next_pid);
            update_histogram(delta);
        }
    }

    // (2) Per-process on-CPU slice accounting for prev_pid. If we had
    //     recorded prev_pid going on-CPU earlier, charge (now - ts)
    //     nanoseconds to its cpu_user_ns and bump the appropriate
    //     context-switch counter.
    if prev_pid != 0 {
        if let Some(on_ts_ref) = unsafe { crate::stats::ONCPU_SINCE.get(&prev_pid) } {
            let slice = now.saturating_sub(*on_ts_ref);
            let _ = crate::stats::ONCPU_SINCE.remove(&prev_pid);
            if let Some(p) = crate::stats::upsert(prev_pid) {
                // SAFETY: upsert returns a valid pointer into the map slot.
                unsafe {
                    (*p).pid = prev_pid;
                    (*p).comm = prev_comm;
                    // TODO: split user vs system by checking prev_state's
                    // PF_KTHREAD bit via CO-RE task_struct access.
                    (*p).cpu_user_ns = (*p).cpu_user_ns.wrapping_add(slice);
                    if prev_state == 0 {
                        (*p).involuntary_ctx_sw =
                            (*p).involuntary_ctx_sw.wrapping_add(1);
                    } else {
                        (*p).voluntary_ctx_sw =
                            (*p).voluntary_ctx_sw.wrapping_add(1);
                    }
                }
            }
        }
    }

    // (3) Mark next_pid as on-CPU so the next sched_switch can close the
    //     slice. Also populate its comm so pre-existing processes (which
    //     never fired sched_process_exec on this daemon run) still show
    //     a name in /metrics/process.
    if next_pid != 0 {
        if let Some(p) = crate::stats::upsert(next_pid) {
            unsafe {
                (*p).pid = next_pid;
                (*p).comm = next_comm;
            }
        }
        let _ = crate::stats::ONCPU_SINCE.insert(&next_pid, &now, 0);
    }

    Ok(())
}

/// Bucket a runqueue-wait delta into the per-CPU histogram.
#[inline(always)]
fn update_histogram(delta: u64) {
    let idx = bucket_of(delta);
    let Some(hist_ptr) = SCHED_HISTOGRAM.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: valid, aligned pointer to the current CPU's histogram slot.
    unsafe {
        if idx < SCHED_HIST_BUCKETS {
            (*hist_ptr).buckets[idx] = (*hist_ptr).buckets[idx].wrapping_add(1);
        }
        (*hist_ptr).total_count = (*hist_ptr).total_count.wrapping_add(1);
        (*hist_ptr).total_latency_ns = (*hist_ptr).total_latency_ns.wrapping_add(delta);
        if delta > (*hist_ptr).max_latency_ns {
            (*hist_ptr).max_latency_ns = delta;
        }
    }
}

/// Map a runqueue-wait duration (nanoseconds) to a log-spaced bucket index.
/// Buckets: <10us, <100us, <1ms, <10ms, <100ms, <1s, <10s, >=10s.
#[inline(always)]
fn bucket_of(ns: u64) -> usize {
    if ns < 10_000 {
        0
    } else if ns < 100_000 {
        1
    } else if ns < 1_000_000 {
        2
    } else if ns < 10_000_000 {
        3
    } else if ns < 100_000_000 {
        4
    } else if ns < 1_000_000_000 {
        5
    } else if ns < 10_000_000_000 {
        6
    } else {
        7
    }
}
