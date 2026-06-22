// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block I/O probes — btf_tracepoint version.
//!
//! `block_rq_complete(struct request *rq, blk_status_t error,
//!                    unsigned int nr_bytes)` — BTF gives us
//! `nr_bytes` as arg(2) directly and the `request` pointer as
//! arg(0) from which we read `cmd_flags` (for read/write) and
//! `q->disk->major/first_minor` (for device identification)
//! via `bpf_probe_read_kernel` + vmlinux types.

use agl_health_common::metrics::BlockStats;
use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{btf_tracepoint, map},
    maps::HashMap,
    programs::BtfTracePointContext,
};

use crate::vmlinux::{gendisk, request, request_queue};

#[map]
static BLOCK_STATS: HashMap<u64, BlockStats> = HashMap::<u64, BlockStats>::with_max_entries(32, 0);

/// REQ_OP_READ = 0, REQ_OP_WRITE = 1. The operation is in the
/// low bits of `cmd_flags` (blk_opf_t). Mask with 0xFF to get
/// the op.
const REQ_OP_MASK: u32 = 0xFF;
const REQ_OP_READ: u32 = 0;
const REQ_OP_WRITE: u32 = 1;

#[btf_tracepoint(function = "block_rq_complete")]
pub fn block_rq_complete(ctx: BtfTracePointContext) -> u32 {
    match try_complete(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn try_complete(ctx: &BtfTracePointContext) -> Result<(), ()> {
    let rq: *const request = unsafe { ctx.arg(0) };
    let nr_bytes: u32 = unsafe { ctx.arg(2) };

    // Read cmd_flags to determine read vs write.
    let cmd_flags: u32 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*rq).cmd_flags))
    }
    .map_err(|_| ())?;
    let op = cmd_flags & REQ_OP_MASK;
    let is_read = op == REQ_OP_READ;
    let is_write = op == REQ_OP_WRITE;
    if !is_read && !is_write {
        return Ok(()); // Discard/flush/other.
    }

    // Read device major:minor via rq->q->disk->major/first_minor.
    let q: *const request_queue = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*rq).q))
    }
    .map_err(|_| ())?;
    let disk: *const gendisk = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*q).disk))
    }
    .map_err(|_| ())?;
    // `q->disk` is NULL for some request_queues (e.g. certain stacked or
    // passthrough devices). Dereferencing a NULL base would otherwise
    // misattribute to dev_key 0; drop the sample instead.
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

    // Encode major:minor losslessly into a u64 key so large major numbers
    // (Linux majors can exceed the 12 bits a packed u32 scheme leaves)
    // can never collide or alias.
    let dev_key = ((major as u64) << 32) | (minor as u64 & 0xFFFF_FFFF);

    // Fast path: entry exists.
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
        return Ok(());
    }

    // Slow path: first time we see this device.
    let mut fresh: BlockStats = unsafe { core::mem::zeroed() };
    fresh.device_major = major as u32;
    fresh.device_minor = minor as u32;
    if is_read {
        fresh.reads_completed = 1;
        fresh.read_bytes = nr_bytes as u64;
    } else {
        fresh.writes_completed = 1;
        fresh.write_bytes = nr_bytes as u64;
    }
    BLOCK_STATS.insert(&dev_key, &fresh, 0).map_err(|_| ())?;
    Ok(())
}
