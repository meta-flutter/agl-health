// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler probes — btf_tracepoint versions.
//!
//! Uses `#[btf_tracepoint]` for type-safe access to function
//! arguments via BTF. `task_struct` field reads use
//! `bpf_probe_read_kernel` with pointers derived from the
//! generated `vmlinux::task_struct`. This eliminates all hardcoded
//! tracepoint format offsets from the scheduler module.
//!
//! Requires kernel 5.5+ with `CONFIG_DEBUG_INFO_BTF=y`.

use agl_health_common::{metrics::SchedHistogram, SCHED_HIST_BUCKETS};
use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{btf_tracepoint, map},
    maps::{HashMap, PerCpuArray},
    programs::BtfTracePointContext,
};

use crate::vmlinux::task_struct;

#[map]
pub static WAKEUP_TIMES: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(10240, 0);

#[map]
static SCHED_HISTOGRAM: PerCpuArray<SchedHistogram> = PerCpuArray::with_max_entries(1, 0);

/// `sched_wakeup(struct task_struct *p)` — task becomes runnable.
#[btf_tracepoint(function = "sched_wakeup")]
pub fn sched_wakeup(ctx: BtfTracePointContext) -> u32 {
    match try_wakeup(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn try_wakeup(ctx: &BtfTracePointContext) -> Result<(), ()> {
    let task: *const task_struct = unsafe { ctx.arg(0) };
    let pid: i32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*task).pid))
    }
    .map_err(|_| ())?;
    let ts = unsafe { bpf_ktime_get_ns() };
    let pid = pid as u32;
    let _ = WAKEUP_TIMES.insert(&pid, &ts, 0);
    Ok(())
}

/// `sched_switch(bool preempt, struct task_struct *prev,
///               struct task_struct *next, unsigned int prev_state)`
#[btf_tracepoint(function = "sched_switch")]
pub fn sched_switch(ctx: BtfTracePointContext) -> u32 {
    match try_switch(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn try_switch(ctx: &BtfTracePointContext) -> Result<(), ()> {
    let prev: *const task_struct = unsafe { ctx.arg(1) };
    let next: *const task_struct = unsafe { ctx.arg(2) };
    let prev_state: u32 = unsafe { ctx.arg(3) };

    let prev_pid: i32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*prev).pid))
    }
    .map_err(|_| ())?;
    let next_pid: i32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*next).pid))
    }
    .map_err(|_| ())?;
    let prev_comm: [i8; 16] = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*prev).comm))
    }
    .map_err(|_| ())?;
    let next_comm: [i8; 16] = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*next).comm))
    }
    .map_err(|_| ())?;

    let prev_pid = prev_pid as u32;
    let next_pid = next_pid as u32;
    // Cast [i8; 16] → [u8; 16] for comm. Safe: same layout.
    let prev_comm: [u8; 16] = unsafe { core::mem::transmute(prev_comm) };
    let next_comm: [u8; 16] = unsafe { core::mem::transmute(next_comm) };

    let now = unsafe { bpf_ktime_get_ns() };

    // (1) Runqueue-wait histogram for next_pid.
    if next_pid != 0 {
        if let Some(wakeup_ts) = unsafe { WAKEUP_TIMES.get(&next_pid) } {
            let delta = now.saturating_sub(*wakeup_ts);
            let _ = WAKEUP_TIMES.remove(&next_pid);
            update_histogram(delta);
        }
    }

    // (2) Per-process CPU slice accounting for prev_pid.
    if prev_pid != 0 {
        if let Some(on_ts_ref) = unsafe { crate::stats::ONCPU_SINCE.get(&prev_pid) } {
            let slice = now.saturating_sub(*on_ts_ref);
            let _ = crate::stats::ONCPU_SINCE.remove(&prev_pid);
            if let Some(p) = crate::stats::upsert(prev_pid) {
                unsafe {
                    (*p).pid = prev_pid;
                    (*p).comm = prev_comm;
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

    // (3) Mark next_pid as on-CPU.
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

#[inline(always)]
fn update_histogram(delta: u64) {
    let idx = bucket_of(delta);
    let Some(hist_ptr) = SCHED_HISTOGRAM.get_ptr_mut(0) else {
        return;
    };
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

#[inline(always)]
fn bucket_of(ns: u64) -> usize {
    if ns < 10_000 { 0 }
    else if ns < 100_000 { 1 }
    else if ns < 1_000_000 { 2 }
    else if ns < 10_000_000 { 3 }
    else if ns < 100_000_000 { 4 }
    else if ns < 1_000_000_000 { 5 }
    else if ns < 10_000_000_000 { 6 }
    else { 7 }
}
