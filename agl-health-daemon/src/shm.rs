// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX shared memory publisher for the v3 [`MetricSnapshotV3`]
//! layout.
//!
//! This module owns a single `MmapMut` over
//! `/dev/shm/agl-health-metrics` and exposes two things:
//!
//! * [`ShmPublisher`] — the low-level writer. Owns the mmap, tracks a
//!   local sequence counter, and exposes `publish(&MetricSnapshotV3)`
//!   which performs a seqlock write of the snapshot.
//! * [`spawn_writer`] — the high-level entry point. Starts a
//!   dedicated tokio task that ticks at 1 Hz, reads the existing v1
//!   `SharedSnapshot` + `PidFactsCache`, converts the data into a
//!   `MetricSnapshotV3`, and calls `publish`.
//!
//! # Single-writer discipline
//!
//! The seqlock protocol only permits one writer. We guarantee this by
//! having **exactly one task** (the one spawned here) ever touch the
//! shm segment. Both the aggregator (BPF pipeline) and `proc_tier`
//! write into the shared v1 snapshot via its `tokio::sync::RwLock`;
//! the shm writer then reads that snapshot and copies the data into
//! shm. Neither aggregator nor proc_tier holds the shm mmap.
//!
//! That means the shm publisher works uniformly with and without the
//! `ebpf` cargo feature. Without the feature, aggregator is idle and
//! only `proc_tier` writes into the shared snapshot (memory + load),
//! but the shm writer still runs and the consumer still sees
//! wall-clock timestamps, real memory facts, and real load averages.
//!
//! # Seqlock protocol
//!
//! ```text
//!   writer:                              reader:
//!     seq = load; seq += 1                do {
//!     atomic store seq (odd, Release)       s1 = atomic load seq (Acquire)
//!     memcpy body into shm                  if s1 & 1 != 0 continue
//!     seq += 1                              copy shm into local buf
//!     atomic store seq (even, Release)      s2 = atomic load seq (Acquire)
//!                                         } while s1 != s2
//! ```
//!
//! The body memcpy is split into two `copy_nonoverlapping` calls
//! around the `sequence` field so the sequence is never clobbered by
//! the body write — the field stays under exclusive control of the
//! atomic stores. Offsets come from `offset_of!` at compile time so
//! any future layout change fails the build rather than silently
//! corrupting the seqlock.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{fence, AtomicU64, Ordering};
use std::time::Duration;

use agl_health_common::metrics_v3::{
    LoadSnapshotFixed, MetricSnapshotV3, SchedSnapshotFixed, ShmHeader, SHM_MAGIC, SHM_VERSION,
};
use agl_health_common::{
    V3_MAX_BLOCK_DEVS, V3_MAX_CPU_CORES, V3_MAX_NET_IFACES, V3_MAX_PROCESSES,
};
use anyhow::{Context, Result};
use memmap2::{MmapMut, MmapOptions};
use tokio::time::interval;
use tracing::{debug, info};

use crate::metrics::{MetricSnapshot, SharedSnapshot};
use crate::proc_tier::{CpuUtilCache, CpuUtilDelta, PidFactsCache, PidStatusFacts};
use crate::time_base::TimeBase;

/// Default path of the shm segment. Mirrors §5 of the v3
/// implementation plan.
pub const DEFAULT_SHM_PATH: &str = "/dev/shm/agl-health-metrics";

/// Byte offset of `ShmHeader.sequence` inside `MetricSnapshotV3`.
/// Computed at compile time so a layout change that moves the field
/// fails the build rather than corrupting the seqlock at runtime.
const SEQ_OFFSET: usize = core::mem::offset_of!(MetricSnapshotV3, header)
    + core::mem::offset_of!(ShmHeader, sequence);
const SEQ_SIZE: usize = core::mem::size_of::<u64>();
const POST_SEQ_OFFSET: usize = SEQ_OFFSET + SEQ_SIZE;

// Sanity: the sequence field must be 8-byte aligned for
// `AtomicU64::from_ptr`. The absolute address of the mmap is page
// aligned, so this is equivalent to requiring SEQ_OFFSET to be a
// multiple of 8.
const _: () = assert!(SEQ_OFFSET % 8 == 0, "sequence field must be 8-byte aligned");

/// Owns the mmap over `/dev/shm/agl-health-metrics` and performs
/// seqlock writes of [`MetricSnapshotV3`].
pub struct ShmPublisher {
    path: PathBuf,
    mmap: MmapMut,
    /// Last sequence value written. Tracked outside the mmap so the
    /// writer never has to *read back* from shm (that would race
    /// against a prior writer on a stale segment).
    local_seq: u64,
}

impl ShmPublisher {
    /// Open or create the shm segment, `ftruncate` it to
    /// `MetricSnapshotV3::SIZE`, mmap it writable, and initialize the
    /// header with `magic`, `version`, `snapshot_size`, and a
    /// `sequence` of 0 (stable empty state).
    ///
    /// The file mode is 0o644 so unprivileged readers (the Flutter
    /// app via the C++ plugin) can `mmap` it read-only.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        // Remove any stale segment first, then create exclusively
        // (`create_new` = O_CREAT|O_EXCL). This guarantees we own a fresh
        // inode of exactly the right size: we never adopt a file an
        // unprivileged user pre-created in the world-writable /dev/shm,
        // and we never inherit a short/corrupt file left by a crash. If
        // someone races us to create the path after the unlink, the
        // exclusive open fails loudly instead of trusting their inode.
        let _ = std::fs::remove_file(&path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        file.set_len(MetricSnapshotV3::SIZE as u64)
            .with_context(|| format!("ftruncate {} to {}", path.display(), MetricSnapshotV3::SIZE))?;

        // SAFETY: We just created or truncated the file to the right
        // size; no other process should be writing to it (single
        // writer discipline). The lifetime of the mmap is tied to
        // `self`, so the mapping lives as long as the `File` handle
        // we dropped above — on Linux that's fine because `mmap`
        // keeps the inode alive via its own reference.
        let mmap = unsafe {
            MmapOptions::new()
                .len(MetricSnapshotV3::SIZE)
                .map_mut(&file)
                .with_context(|| format!("mmap {}", path.display()))?
        };

        let mut publisher = Self {
            path,
            mmap,
            local_seq: 0,
        };
        publisher.init_empty();
        Ok(publisher)
    }

    fn init_empty(&mut self) {
        // SAFETY: the mmap is `MetricSnapshotV3::SIZE` bytes and we
        // just allocated it; writing zero bytes across the whole
        // range is sound. We then set header fields via normal store
        // through the mmap.
        let dst = self.mmap.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(dst, 0, MetricSnapshotV3::SIZE);
            let snap = dst as *mut MetricSnapshotV3;
            (*snap).header.magic = SHM_MAGIC;
            (*snap).header.version = SHM_VERSION;
            (*snap).header.snapshot_size = MetricSnapshotV3::SIZE as u32;
            // sequence stays 0 — that's the "stable empty" state.
        }
    }

    /// Publish a new snapshot under the seqlock protocol. The
    /// sequence counter is bumped to odd before the body memcpy and
    /// to even after, using `Release` ordering on both stores. The
    /// body memcpy is split around the sequence field so the
    /// sequence is only ever touched by the atomic stores.
    pub fn publish(&mut self, snapshot: &MetricSnapshotV3) {
        let dst = self.mmap.as_mut_ptr();

        // SAFETY: `seq_ptr` points at the sequence field inside our
        // own mmap, which is 8-byte aligned by construction (see the
        // compile-time assertion on `SEQ_OFFSET`). We use
        // `AtomicU64::from_ptr` (stable since 1.75) to get a properly
        // atomic reference without taking a `&mut AtomicU64`, which
        // would alias with the body memcpy that follows.
        unsafe {
            let seq_ptr = dst.add(SEQ_OFFSET) as *mut AtomicU64;
            let seq_atomic = &*seq_ptr;

            // Phase 1: mark "write in progress" (odd).
            self.local_seq = self.local_seq.wrapping_add(1);
            debug_assert!(self.local_seq & 1 == 1, "odd sequence expected");
            seq_atomic.store(self.local_seq, Ordering::Release);
            fence(Ordering::Release);

            // Phase 2: copy the body. Two nonoverlapping copies, one
            // for everything before `sequence`, one for everything
            // after. The sequence field is skipped entirely.
            let src_bytes = snapshot as *const MetricSnapshotV3 as *const u8;
            core::ptr::copy_nonoverlapping(src_bytes, dst, SEQ_OFFSET);
            core::ptr::copy_nonoverlapping(
                src_bytes.add(POST_SEQ_OFFSET),
                dst.add(POST_SEQ_OFFSET),
                MetricSnapshotV3::SIZE - POST_SEQ_OFFSET,
            );

            // Phase 3: mark "stable" (even).
            fence(Ordering::Release);
            self.local_seq = self.local_seq.wrapping_add(1);
            debug_assert!(self.local_seq & 1 == 0, "even sequence expected");
            seq_atomic.store(self.local_seq, Ordering::Release);
        }
    }

    /// Expose the shm path for logging / diagnostics.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ShmPublisher {
    fn drop(&mut self) {
        // Best-effort cleanup. If the process is crashing and we
        // can't unlink, the next daemon startup will truncate the
        // file to size and overwrite the header anyway.
        if let Err(e) = std::fs::remove_file(&self.path) {
            debug!(path = %self.path.display(), error = %e, "shm unlink failed");
        } else {
            debug!(path = %self.path.display(), "shm segment unlinked");
        }
    }
}

// ----- writer task -----

/// Spawn the dedicated shm writer task. Returns immediately; the task
/// runs for the lifetime of the daemon.
///
/// On failure to create the publisher (e.g. `/dev/shm` is not
/// writable) the task logs an error and exits without spawning.
/// The rest of the daemon keeps running — the shm channel is
/// optional, not load-bearing for the existing REST/WebSocket path.
pub fn spawn_writer(
    path: PathBuf,
    shared: SharedSnapshot,
    pid_facts: PidFactsCache,
    cpu_util: CpuUtilCache,
    time_base: TimeBase,
) -> Result<()> {
    let publisher = ShmPublisher::create(&path)?;
    info!(
        path = %publisher.path().display(),
        size = MetricSnapshotV3::SIZE,
        "shm publisher ready"
    );
    tokio::spawn(writer_loop(publisher, shared, pid_facts, cpu_util, time_base));
    Ok(())
}

async fn writer_loop(
    mut publisher: ShmPublisher,
    shared: SharedSnapshot,
    pid_facts: PidFactsCache,
    cpu_util: CpuUtilCache,
    time_base: TimeBase,
) {
    let mut ticker = interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        let v3 = {
            let snap = shared.read().await;
            let facts = pid_facts.read().await;
            let cpu = cpu_util.read().await;
            build_v3(&snap, &facts, &cpu, &time_base)
        };
        publisher.publish(&v3);
    }
    // Unreachable under normal operation; if we ever add a shutdown
    // channel, drop-cleanup will unlink the segment.
    #[allow(unreachable_code)]
    {
        let _ = publisher;
    }
}

/// Convert the v1 `MetricSnapshot` (the async-lock-protected
/// aggregator state) into a fixed-size `MetricSnapshotV3` suitable
/// for mmapped publication. Applies the `PidFactsCache` overlay to
/// each process row so the Flutter consumer sees `VmRSS`, `VmSize`,
/// and `thread_count` that the BPF pipeline doesn't track.
fn build_v3(
    v1: &MetricSnapshot,
    facts: &HashMap<u32, PidStatusFacts>,
    cpu_util: &[CpuUtilDelta],
    time_base: &TimeBase,
) -> MetricSnapshotV3 {
    let mut v3 = MetricSnapshotV3::zeroed();

    // Header. The writer's `publish` will overwrite `sequence`; we
    // leave it at 0 here. Everything else goes through as-is.
    v3.header.magic = SHM_MAGIC;
    v3.header.version = SHM_VERSION;
    v3.header.snapshot_size = MetricSnapshotV3::SIZE as u32;
    v3.header.timestamp_ns_wall = time_base.now_wall_ns();

    // System-wide gauges — direct copies.
    v3.memory = v1.memory;
    v3.load = LoadSnapshotFixed {
        load_1: v1.load.load_1,
        load_5: v1.load.load_5,
        load_15: v1.load.load_15,
    };
    v3.sched = SchedSnapshotFixed {
        histogram: v1.sched.histogram,
        p50_ns: v1.sched.p50_ns,
        p95_ns: v1.sched.p95_ns,
        p99_ns: v1.sched.p99_ns,
    };
    v3.tcp = v1.tcp;
    v3.security = v1.security;

    // Fixed-size collections. Each `min(cap)` silently drops any
    // overflow — the v3 plan explicitly accepts this trade-off (top-N
    // wins; the rest are invisible to the Flutter path).
    // CPU cores: start with the eBPF-sourced irq/softirq times,
    // then overlay /proc/stat-sourced user/system/iowait/idle deltas.
    let n_cpu = v1.cpu_cores.len().min(V3_MAX_CPU_CORES);
    v3.cpu_core_count = n_cpu as u32;
    v3.cpu_cores[..n_cpu].copy_from_slice(&v1.cpu_cores[..n_cpu]);
    // If no eBPF data, use /proc/stat as the primary source.
    let cpu_count = if n_cpu > 0 { n_cpu } else { cpu_util.len().min(V3_MAX_CPU_CORES) };
    if n_cpu == 0 {
        v3.cpu_core_count = cpu_count as u32;
    }
    for (i, cu) in cpu_util.iter().enumerate() {
        if i >= cpu_count { break; }
        v3.cpu_cores[i].cpu_id = cu.cpu_id;
        v3.cpu_cores[i].user_ns = cu.user_ns;
        v3.cpu_cores[i].system_ns = cu.system_ns;
        v3.cpu_cores[i].iowait_ns = cu.iowait_ns;
        v3.cpu_cores[i].idle_ns = cu.idle_ns;
    }

    let n_net = v1.net_ifaces.len().min(V3_MAX_NET_IFACES);
    v3.net_iface_count = n_net as u32;
    v3.net_ifaces[..n_net].copy_from_slice(&v1.net_ifaces[..n_net]);

    let n_blk = v1.block.len().min(V3_MAX_BLOCK_DEVS);
    v3.block_dev_count = n_blk as u32;
    v3.block_devs[..n_blk].copy_from_slice(&v1.block[..n_blk]);

    // Top processes: copy the BPF-sourced rows and overlay
    // `/proc`-sourced supplements from the pid_facts cache.
    let n_proc = v1.top_processes.len().min(V3_MAX_PROCESSES);
    v3.process_count = n_proc as u32;
    for (i, src) in v1.top_processes[..n_proc].iter().enumerate() {
        let mut row = *src;
        if let Some(f) = facts.get(&src.pid) {
            row.mem_rss_bytes = f.mem_rss_bytes;
            row.mem_vms_bytes = f.mem_vms_bytes;
            row.thread_count = f.thread_count;
        }
        v3.top_processes[i] = row;
    }

    // Per-CPU scheduler histograms.
    let n_sched = v1.sched_per_cpu.len().min(V3_MAX_CPU_CORES);
    v3.sched_cpu_count = n_sched as u32;
    for (i, s) in v1.sched_per_cpu[..n_sched].iter().enumerate() {
        v3.sched_per_cpu[i] = agl_health_common::metrics_v3::SchedSnapshotFixed {
            histogram: s.histogram,
            p50_ns: s.p50_ns,
            p95_ns: s.p95_ns,
            p99_ns: s.p99_ns,
        };
    }

    v3
}
