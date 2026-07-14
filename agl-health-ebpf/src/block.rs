// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block I/O probes.
//!
//! Default (5.5+): `#[btf_tracepoint]` — `nr_bytes` as arg(2) directly
//! and the `request` pointer as arg(0), from which we read `cmd_flags`
//! and `rq->rq_disk->major/first_minor` via `bpf_probe_read_kernel`.
//! Note: `request_queue->disk` was added in 5.12; we use `request->rq_disk`
//! which is present from the start through at least 5.17.
//!
//! kernel-5-4: `#[tracepoint]` — `dev` and `rwbs` are direct fields in
//! the tracepoint format, eliminating the CO-RE chain entirely. Major and
//! minor are derived from the encoded `dev` value using standard bit shifts.

use agl_health_common::metrics::BlockStats;
use aya_ebpf::{macros::map, maps::HashMap};

#[map]
static BLOCK_STATS: HashMap<u64, BlockStats> = HashMap::<u64, BlockStats>::with_max_entries(32, 0);

#[cfg(not(feature = "kernel-5-4"))]
const REQ_OP_MASK: u32 = 0xFF;
#[cfg(not(feature = "kernel-5-4"))]
const REQ_OP_READ: u32 = 0;
#[cfg(not(feature = "kernel-5-4"))]
const REQ_OP_WRITE: u32 = 1;

// ----- 5.5+ btf_tracepoint program -----

#[cfg(not(feature = "kernel-5-4"))]
use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::btf_tracepoint,
    programs::BtfTracePointContext,
};
#[cfg(not(feature = "kernel-5-4"))]
use crate::vmlinux::{gendisk, request, request_queue};

#[cfg(not(feature = "kernel-5-4"))]
#[btf_tracepoint(function = "block_rq_complete")]
pub fn block_rq_complete(ctx: BtfTracePointContext) -> u32 {
    match try_complete_btf(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

#[cfg(not(feature = "kernel-5-4"))]
fn try_complete_btf(ctx: &BtfTracePointContext) -> Result<(), ()> {
    let rq: *const request = unsafe { ctx.arg(0) };
    let nr_bytes: u32 = unsafe { ctx.arg(2) };

    let cmd_flags: u32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*rq).cmd_flags))
    }
    .map_err(|_| ())?;
    let op = cmd_flags & REQ_OP_MASK;
    let is_read = op == REQ_OP_READ;
    let is_write = op == REQ_OP_WRITE;
    if !is_read && !is_write {
        return Ok(());
    }

    let q: *const request_queue = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*rq).q))
    }
    .map_err(|_| ())?;
    let disk: *const gendisk = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*q).disk))
    }
    .map_err(|_| ())?;
    if disk.is_null() {
        return Ok(());
    }
    let major: i32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*disk).major))
    }
    .map_err(|_| ())?;
    let minor: i32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*disk).first_minor))
    }
    .map_err(|_| ())?;

    // Encode major:minor losslessly into a u64 key.
    let dev_key = ((major as u64) << 32) | (minor as u64 & 0xFFFF_FFFF);
    update_block_stats(dev_key, major as u32, minor as u32, is_read, nr_bytes);
    Ok(())
}

// ----- kernel-5-4 tracepoint program -----

// /sys/kernel/debug/tracing/events/block/block_rq_complete/format
// Layout (from trace_event_raw_block_rq_complete in the BTF header):
//   offset 0:  trace_entry (struct, 8 bytes — common header)
//   offset 8:  dev         (dev_t = u32, 4 bytes)
//   offset 12: _pad        (4 bytes natural alignment padding before sector_t)
//   offset 16: sector      (sector_t = u64, 8 bytes)
//   offset 24: nr_sector   (unsigned int = u32, 4 bytes)
//   offset 28: error       (int = i32, 4 bytes)
//   offset 32: rwbs        ([u8; 8])
// dev encodes major:minor as MKDEV(major, minor) = (major << 20 | minor).
#[cfg(feature = "kernel-5-4")]
#[repr(C)]
struct BlockRqCompleteArgs {
    _pad: [u8; 8],
    dev: u32,
    _align: u32,
    sector: u64,
    nr_sector: u32,
    errors: i32,
    rwbs: [u8; 8],
}

#[cfg(feature = "kernel-5-4")]
use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

/// `block_rq_complete` — 5.4 path.
///
/// Derives major/minor from the encoded `dev` field using standard Linux
/// MKDEV bit shifts (`major = dev >> 20`, `minor = dev & 0xFFFFF`).
/// The `rwbs` field encodes the operation as an ASCII string ('R'=read,
/// 'W'=write). This eliminates all `bpf_probe_read_kernel` calls.
#[cfg(feature = "kernel-5-4")]
#[tracepoint]
pub fn block_rq_complete(ctx: TracePointContext) -> u32 {
    let args = match unsafe { ctx.read_at::<BlockRqCompleteArgs>(0) } {
        Ok(a) => a,
        Err(_) => return 1,
    };

    let major = args.dev >> 20;
    let minor = args.dev & 0xF_FFFF;

    let is_read = args.rwbs[0] == b'R';
    let is_write = args.rwbs[0] == b'W';
    if !is_read && !is_write {
        return 0;
    }

    // nr_sector * 512 gives bytes. Saturate to u32::MAX rather than wrap —
    // requests exceeding ~4 GB are pathological but should not zero the counter.
    let nr_bytes = ((args.nr_sector as u64) * 512).min(u32::MAX as u64) as u32;

    // Encode using the same key scheme as the 5.5+ path for map compatibility.
    let dev_key = ((major as u64) << 32) | (minor as u64);
    update_block_stats(dev_key, major, minor, is_read, nr_bytes);
    0
}

// ----- shared stats update -----

fn update_block_stats(dev_key: u64, major: u32, minor: u32, is_read: bool, nr_bytes: u32) {
    if let Some(stats) = BLOCK_STATS.get_ptr_mut(&dev_key) {
        unsafe {
            if is_read {
                (*stats).reads_completed = (*stats).reads_completed.wrapping_add(1);
                (*stats).read_bytes = (*stats).read_bytes.wrapping_add(nr_bytes as u64);
            } else {
                (*stats).writes_completed = (*stats).writes_completed.wrapping_add(1);
                (*stats).write_bytes = (*stats).write_bytes.wrapping_add(nr_bytes as u64);
            }
        }
        return;
    }

    let mut fresh: BlockStats = unsafe { core::mem::zeroed() };
    fresh.device_major = major;
    fresh.device_minor = minor;
    if is_read {
        fresh.reads_completed = 1;
        fresh.read_bytes = nr_bytes as u64;
    } else {
        fresh.writes_completed = 1;
        fresh.write_bytes = nr_bytes as u64;
    }
    let _ = BLOCK_STATS.insert(&dev_key, &fresh, 0);
}
