//! CPU scheduling class accounting.
//!
//! Tracks per-CPU time spent in hardware IRQ handlers and software
//! interrupts via entry/exit tracepoint pairs:
//!
//!   * `irq:irq_handler_entry`  -> stash `bpf_ktime_get_ns()`
//!   * `irq:irq_handler_exit`   -> compute delta, add to `CpuStats.irq_ns`
//!   * `irq:softirq_entry`      -> stash timestamp
//!   * `irq:softirq_exit`       -> compute delta, add to `softirq_ns`
//!
//! The entry-timestamp maps are `PerCpuArray` with a single slot. A
//! single slot is sufficient because hardware IRQ handlers run with
//! IRQs disabled on both x86_64 and aarch64, so nesting on the same
//! CPU doesn't happen; softirqs do not nest either (the softirq
//! machinery guards against re-entry on the same CPU). If the timing
//! is ever observed to be negative after a context change, the entry
//! slot is treated as stale and ignored - see the `entry == 0` check
//! in each exit handler.
//!
//! The `CpuStats.cpu_id` field is filled by the userspace aggregator
//! from the `PerCpuValues` iteration index, not by the kernel programs.
//! Other fields on `CpuStats` (user_ns, system_ns, iowait_ns, idle_ns,
//! ctx_switches) are not yet populated and remain zero.

use agl_health_common::metrics::CpuStats;
use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};

/// Per-CPU scheduling-class time accumulator, one logical entry per
/// CPU (slot 0). The userspace aggregator reads this via
/// `PerCpuValues` and produces one wire-format `CpuStats` per core.
#[map]
pub static CPU_STATS: PerCpuArray<CpuStats> = PerCpuArray::with_max_entries(1, 0);

/// Entry timestamp for the currently-executing hardware IRQ, per CPU.
#[map]
static IRQ_ENTRY_TS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Entry timestamp for the currently-executing softirq, per CPU.
#[map]
static SOFTIRQ_ENTRY_TS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// `irq:irq_handler_entry` - a hardware IRQ handler is about to run.
#[tracepoint]
pub fn irq_handler_entry(_ctx: TracePointContext) -> u32 {
    let Some(ts_ptr) = IRQ_ENTRY_TS.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: pointer into the current CPU's slot; BPF preemption off.
    unsafe {
        *ts_ptr = bpf_ktime_get_ns();
    }
    0
}

/// `irq:irq_handler_exit` - IRQ handler finished, charge its duration.
#[tracepoint]
pub fn irq_handler_exit(_ctx: TracePointContext) -> u32 {
    let now = unsafe { bpf_ktime_get_ns() };
    let Some(ts_ptr) = IRQ_ENTRY_TS.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: same as above.
    let entry = unsafe { *ts_ptr };
    if entry == 0 {
        // No matching entry recorded - program started mid-IRQ or
        // we already consumed this slot.
        return 0;
    }
    unsafe {
        *ts_ptr = 0;
    }
    let delta = now.saturating_sub(entry);
    let Some(cpu) = CPU_STATS.get_ptr_mut(0) else {
        return 0;
    };
    unsafe {
        (*cpu).irq_ns = (*cpu).irq_ns.wrapping_add(delta);
    }
    0
}

/// `irq:softirq_entry` - a softirq vector is about to run.
#[tracepoint]
pub fn softirq_entry(_ctx: TracePointContext) -> u32 {
    let Some(ts_ptr) = SOFTIRQ_ENTRY_TS.get_ptr_mut(0) else {
        return 0;
    };
    unsafe {
        *ts_ptr = bpf_ktime_get_ns();
    }
    0
}

/// `irq:softirq_exit` - softirq finished, charge its duration.
#[tracepoint]
pub fn softirq_exit(_ctx: TracePointContext) -> u32 {
    let now = unsafe { bpf_ktime_get_ns() };
    let Some(ts_ptr) = SOFTIRQ_ENTRY_TS.get_ptr_mut(0) else {
        return 0;
    };
    let entry = unsafe { *ts_ptr };
    if entry == 0 {
        return 0;
    }
    unsafe {
        *ts_ptr = 0;
    }
    let delta = now.saturating_sub(entry);
    let Some(cpu) = CPU_STATS.get_ptr_mut(0) else {
        return 0;
    };
    unsafe {
        (*cpu).softirq_ns = (*cpu).softirq_ns.wrapping_add(delta);
    }
    0
}
