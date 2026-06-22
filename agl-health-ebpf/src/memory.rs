// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory probes.
//!
//! Two kprobes:
//!
//! * `handle_mm_fault` fires on every page fault (user and kernel).
//!   We filter on `FAULT_FLAG_USER` (bit 6 of the `flags` argument)
//!   to count only userspace faults, matching the semantics of the
//!   x86-only `exceptions:page_fault_user` tracepoint this replaces.
//!   All counted faults go into `page_faults_minor` — distinguishing
//!   minor vs major requires inspecting the return value via
//!   kretprobe, which is a future enhancement.
//!
//!   This kprobe is architecture-portable: `handle_mm_fault` is a
//!   generic kernel function that exists on x86_64, arm64, and
//!   riscv64. The previous `exceptions:page_fault_user` tracepoint
//!   was defined only in `arch/x86/mm/fault.c` and silently failed
//!   to attach on non-x86 hosts.
//!
//! * `oom_kill_process` fires every time the OOM killer selects a
//!   victim. Bumps `MemorySnapshot.oom_kills_total`.
//!
//! Static memory facts (total RAM, cached, buffers, PSI) are
//! collected by the userspace aggregator from `/proc/meminfo` and
//! `/proc/pressure/memory` — see §5.2 of the implementation plan.

use agl_health_common::metrics::MemorySnapshot;
use aya_ebpf::{
    macros::{kprobe, map},
    maps::PerCpuArray,
    programs::ProbeContext,
};

/// Single-slot per-CPU accumulator. Userspace sums across CPUs when
/// building the published snapshot.
#[map]
static MEMORY_STATS: PerCpuArray<MemorySnapshot> = PerCpuArray::with_max_entries(1, 0);

/// `FAULT_FLAG_USER` from `include/linux/mm_types.h`. Set when the
/// fault originated from userspace. Stable since Linux 4.14.
const FAULT_FLAG_USER: u32 = 0x40;

/// `kprobe:handle_mm_fault` — generic page fault handler.
///
/// Signature (all arches):
/// ```c
/// vm_fault_t handle_mm_fault(struct vm_area_struct *vma,
///                            unsigned long address,
///                            unsigned int flags,
///                            struct pt_regs *regs);
/// ```
///
/// `flags` is arg index 2. We check `FAULT_FLAG_USER` to count
/// only userspace faults.
#[kprobe]
pub fn handle_mm_fault(ctx: ProbeContext) -> u32 {
    let flags: u32 = ctx.arg(2).unwrap_or(0);
    if flags & FAULT_FLAG_USER == 0 {
        return 0; // Kernel fault — skip.
    }
    let Some(mem) = MEMORY_STATS.get_ptr_mut(0) else {
        return 1;
    };
    // SAFETY: valid per-CPU slot pointer; BPF preemption is disabled.
    unsafe {
        (*mem).page_faults_minor = (*mem).page_faults_minor.wrapping_add(1);
    }
    0
}

/// `kprobe:oom_kill_process` — one call per OOM victim selection.
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
