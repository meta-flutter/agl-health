//! Memory probes.
//!
//! Two probes:
//!
//! * `exceptions:page_fault_user` fires on every userspace page fault.
//!   We bump `MemorySnapshot.page_faults_minor`. Distinguishing minor vs
//!   major faults requires inspecting the `FAULT_FLAG_*` bits inside
//!   `handle_mm_fault`, which a later kprobe pass will add; for now the
//!   overwhelming majority (page cache hits, COW, demand zero) are minor
//!   so the count is a useful approximation of userspace fault pressure.
//!
//! * A kprobe on `oom_kill_process` fires every time the OOM killer selects
//!   a victim. We bump `MemorySnapshot.oom_kills_total`. Exact counting,
//!   no sampling, with the victim pid available as an argument once we
//!   extend this to emit an event.
//!
//! Static memory facts (total RAM, cached, buffers, PSI) are collected by
//! the userspace aggregator from `/proc/meminfo` and `/proc/pressure/memory`
//! - see §5.2 of the implementation plan (the "proc" tier).
//!
//! The `exceptions:page_fault_user` tracepoint exists on x86_64 and arm64
//! (with slightly different formats); payload fields are not used here so
//! the probe is architecture-portable.

use agl_health_common::metrics::MemorySnapshot;
use aya_ebpf::{
    macros::{kprobe, map, tracepoint},
    maps::PerCpuArray,
    programs::{ProbeContext, TracePointContext},
};

/// Single-slot per-CPU accumulator. Userspace sums across CPUs when
/// building the published snapshot.
#[map]
static MEMORY_STATS: PerCpuArray<MemorySnapshot> = PerCpuArray::with_max_entries(1, 0);

/// `exceptions:page_fault_user` - any userspace page fault.
#[tracepoint]
pub fn page_fault_user(_ctx: TracePointContext) -> u32 {
    let Some(mem) = MEMORY_STATS.get_ptr_mut(0) else {
        return 1;
    };
    // SAFETY: valid per-CPU slot pointer; BPF preemption is disabled.
    unsafe {
        (*mem).page_faults_minor = (*mem).page_faults_minor.wrapping_add(1);
    }
    0
}

/// kprobe on `oom_kill_process` - one call per OOM victim selection.
///
/// Attaching by function name at load time (`program.attach("oom_kill_process", 0)`
/// in the daemon) means this probe auto-skips on kernels where the symbol
/// has been renamed; the loader should treat that as a non-fatal warning.
#[kprobe]
pub fn oom_kill_process(_ctx: ProbeContext) -> u32 {
    let Some(mem) = MEMORY_STATS.get_ptr_mut(0) else {
        return 1;
    };
    unsafe {
        (*mem).oom_kills_total = (*mem).oom_kills_total.wrapping_add(1);
    }
    0
}
