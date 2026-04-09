//! Block I/O probes.
//!
//! Hooks `block:block_rq_complete` once per completed request and updates a
//! per-device `BlockStats` entry in `BLOCK_STATS`. We split reads from
//! writes by inspecting the first byte of the `rwbs` field which the
//! block layer fills with 'R' for reads and 'W' for writes.
//!
//! Per-request latency (`read_latency_ns` / `write_latency_ns`) requires
//! correlating `block_rq_issue` and `block_rq_complete` via `struct request *`,
//! which the block tracepoints don't directly expose. A kprobe on
//! `blk_account_io_start` / `blk_account_io_done` will land that data in a
//! later pass; for now those fields stay zero.

use agl_health_common::metrics::BlockStats;
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

/// Keyed by encoded `dev_t` (major<<20 | minor). 32 devices is ample for IVI.
#[map]
static BLOCK_STATS: HashMap<u32, BlockStats> = HashMap::<u32, BlockStats>::with_max_entries(32, 0);

/// `block:block_rq_complete` format (stable since 4.15):
///   field:dev_t dev;            offset:8;  size:4
///   field:unsigned int bytes;   offset:28; size:4
///   field:char rwbs[8];         offset:32; size:8
#[tracepoint]
pub fn block_rq_complete(ctx: TracePointContext) -> u32 {
    match try_complete(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn try_complete(ctx: &TracePointContext) -> Result<(), ()> {
    let dev: u32 = unsafe { ctx.read_at::<u32>(8) }.map_err(|_| ())?;
    let bytes: u32 = unsafe { ctx.read_at::<u32>(28) }.map_err(|_| ())?;
    let rwbs: [u8; 8] = unsafe { ctx.read_at::<[u8; 8]>(32) }.map_err(|_| ())?;
    let is_read = rwbs[0] == b'R';
    let is_write = rwbs[0] == b'W';
    if !is_read && !is_write {
        // Discard/flush/other - not accounted as read or write bytes.
        return Ok(());
    }

    // Fast path: entry already exists for this device.
    if let Some(stats) = BLOCK_STATS.get_ptr_mut(&dev) {
        // SAFETY: pointer comes from get_ptr_mut into a HashMap slot that
        // lives for the duration of this program; preemption is disabled.
        unsafe {
            if is_read {
                (*stats).reads_completed = (*stats).reads_completed.wrapping_add(1);
                (*stats).read_bytes = (*stats).read_bytes.wrapping_add(bytes as u64);
            } else {
                (*stats).writes_completed = (*stats).writes_completed.wrapping_add(1);
                (*stats).write_bytes = (*stats).write_bytes.wrapping_add(bytes as u64);
            }
        }
        return Ok(());
    }

    // Slow path: first time we see this device. Insert a zeroed entry with
    // the initial sample applied. `mem::zeroed` is safe for a #[repr(C)] POD
    // of integer fields.
    let mut fresh: BlockStats = unsafe { core::mem::zeroed() };
    // Decode dev_t: major = dev >> 20, minor = dev & 0xFFFFF (MKDEV layout).
    fresh.device_major = dev >> 20;
    fresh.device_minor = dev & 0xF_FFFF;
    if is_read {
        fresh.reads_completed = 1;
        fresh.read_bytes = bytes as u64;
    } else {
        fresh.writes_completed = 1;
        fresh.write_bytes = bytes as u64;
    }
    BLOCK_STATS.insert(&dev, &fresh, 0).map_err(|_| ())?;
    Ok(())
}
