// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! `agl-health-shm-dump` — standalone validation tool for the v3 shm
//! channel.
//!
//! mmaps `/dev/shm/agl-health-metrics` read-only, performs a seqlock
//! read of the current [`MetricSnapshotV3`], validates the magic and
//! version fields, and pretty-prints every populated section.
//!
//! Runs as an unprivileged user — exercising exactly the
//! consumer-side path the C++ Flutter plugin and the EdgeX bridge
//! will use later. No `ebpf` feature required.
//!
//! Usage:
//!
//! ```text
//! cargo run --bin agl-health-shm-dump
//! cargo run --bin agl-health-shm-dump /path/to/custom/shm
//! ```

use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use agl_health_common::metrics_v3::{MetricSnapshotV3, ShmHeader, SHM_MAGIC, SHM_VERSION};
use anyhow::{bail, Context, Result};
use memmap2::{Mmap, MmapOptions};

const DEFAULT_PATH: &str = "/dev/shm/agl-health-metrics";

/// Byte offset of `ShmHeader.sequence` inside the snapshot. Matches
/// the daemon's writer-side offset — see `shm.rs`.
const SEQ_OFFSET: usize = core::mem::offset_of!(MetricSnapshotV3, header)
    + core::mem::offset_of!(ShmHeader, sequence);

fn main() -> Result<()> {
    let path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PATH));

    let file = File::open(&path)
        .with_context(|| format!("open {} (is the daemon running?)", path.display()))?;
    let file_len = file.metadata()?.len() as usize;
    if file_len < MetricSnapshotV3::SIZE {
        bail!(
            "{} is {} bytes, expected at least {}",
            path.display(),
            file_len,
            MetricSnapshotV3::SIZE
        );
    }

    // SAFETY: file is open read-only; we don't mutate through the
    // mmap. If the daemon concurrently writes, the seqlock protocol
    // below guarantees we retry until we see a stable snapshot.
    let mmap: Mmap = unsafe {
        MmapOptions::new()
            .len(MetricSnapshotV3::SIZE)
            .map(&file)
            .context("mmap shm segment")?
    };

    let snap = seqlock_read(&mmap)
        .context("seqlock read failed after retry budget exhausted")?;

    if snap.header.magic != SHM_MAGIC {
        bail!(
            "magic mismatch: expected 0x{:016x}, got 0x{:016x}",
            SHM_MAGIC,
            snap.header.magic
        );
    }
    if snap.header.version != SHM_VERSION {
        bail!(
            "version mismatch: expected {}, got {}",
            SHM_VERSION,
            snap.header.version
        );
    }
    if snap.header.snapshot_size as usize != MetricSnapshotV3::SIZE {
        bail!(
            "snapshot_size mismatch: expected {}, got {}",
            MetricSnapshotV3::SIZE,
            snap.header.snapshot_size
        );
    }

    pretty_print(&path, &snap);
    Ok(())
}

/// Perform a seqlock read into a stack-allocated snapshot. Retries up
/// to `RETRY_BUDGET` times before giving up — a well-behaved daemon
/// should never take more than a handful of retries even under load.
fn seqlock_read(mmap: &Mmap) -> Result<MetricSnapshotV3> {
    const RETRY_BUDGET: usize = 1024;
    let base = mmap.as_ptr();
    // SAFETY: `seq_ptr` lands on the 8-byte-aligned `sequence` field
    // inside the mmap; the mmap base is page aligned and `SEQ_OFFSET`
    // is a multiple of 8 (asserted on the writer side).
    let seq_ptr = unsafe { base.add(SEQ_OFFSET) } as *const AtomicU64;
    let seq_atomic = unsafe { &*seq_ptr };

    let mut out = MetricSnapshotV3::zeroed();
    for attempt in 0..RETRY_BUDGET {
        let seq1 = seq_atomic.load(Ordering::Acquire);
        if seq1 & 1 != 0 {
            // Writer in progress — retry immediately.
            continue;
        }
        // SAFETY: copying `MetricSnapshotV3::SIZE` bytes out of the
        // mmap into an owned stack buffer. Alignment is fine because
        // we're copying bytes, not performing a typed load.
        unsafe {
            core::ptr::copy_nonoverlapping(
                base,
                &mut out as *mut MetricSnapshotV3 as *mut u8,
                MetricSnapshotV3::SIZE,
            );
        }
        let seq2 = seq_atomic.load(Ordering::Acquire);
        if seq1 == seq2 && seq1 != 0 {
            return Ok(out);
        }
        // seq1 == 0 means the daemon has never published; we allow
        // returning the zeroed snapshot after the first few retries
        // so callers hitting a just-started daemon get a valid
        // header read instead of a spin.
        if seq1 == 0 && attempt > 4 {
            return Ok(out);
        }
        // Otherwise the writer changed mid-copy; retry.
    }
    bail!("seqlock retry budget ({}) exhausted", RETRY_BUDGET);
}

fn pretty_print(path: &std::path::Path, snap: &MetricSnapshotV3) {
    println!("=== agl-health shm snapshot ===");
    println!("path:              {}", path.display());
    println!("magic:             0x{:016x}", snap.header.magic);
    println!("version:           {}", snap.header.version);
    println!("sequence:          {}", snap.header.sequence);
    println!("snapshot_size:     {} bytes", snap.header.snapshot_size);
    println!(
        "timestamp_ns_wall: {} ({})",
        snap.header.timestamp_ns_wall,
        format_wall_ns(snap.header.timestamp_ns_wall)
    );
    println!();

    println!("--- Memory ---");
    println!(
        "total:             {}",
        format_bytes(snap.memory.total_bytes)
    );
    println!(
        "free:              {}",
        format_bytes(snap.memory.free_bytes)
    );
    println!(
        "cached:            {}",
        format_bytes(snap.memory.cached_bytes)
    );
    println!(
        "buffered:          {}",
        format_bytes(snap.memory.buffered_bytes)
    );
    println!(
        "slab:              {}",
        format_bytes(snap.memory.slab_bytes)
    );
    println!(
        "swap used/free:    {} / {}",
        format_bytes(snap.memory.swap_used_bytes),
        format_bytes(snap.memory.swap_free_bytes)
    );
    println!(
        "page faults minor: {}",
        snap.memory.page_faults_minor
    );
    println!(
        "page faults major: {}",
        snap.memory.page_faults_major
    );
    println!("oom kills total:   {}", snap.memory.oom_kills_total);
    println!(
        "psi some/full:     {:.2}% / {:.2}%",
        snap.memory.psi_some_pct_x100 as f64 / 100.0,
        snap.memory.psi_full_pct_x100 as f64 / 100.0
    );
    println!();

    println!("--- Load ---");
    println!(
        "1 / 5 / 15 min:    {:.2} / {:.2} / {:.2}",
        snap.load.load_1, snap.load.load_5, snap.load.load_15
    );
    println!();

    println!("--- Scheduler ---");
    println!("p50 / p95 / p99:   {} / {} / {} ns",
        snap.sched.p50_ns, snap.sched.p95_ns, snap.sched.p99_ns);
    println!("total count:       {}", snap.sched.histogram.total_count);
    println!("max latency:       {} ns", snap.sched.histogram.max_latency_ns);
    println!();

    println!("--- TCP ---");
    println!("established:       {}", snap.tcp.established);
    println!("time_wait:         {}", snap.tcp.time_wait);
    println!("close_wait:        {}", snap.tcp.close_wait);
    println!("listen:            {}", snap.tcp.listen);
    println!("retransmits:       {}", snap.tcp.retransmits);
    println!();

    println!("--- CPU cores ({}/{}) ---",
        snap.cpu_core_count, snap.cpu_cores.len());
    let n_cpu = (snap.cpu_core_count as usize).min(snap.cpu_cores.len());
    for i in 0..n_cpu {
        let c = &snap.cpu_cores[i];
        println!(
            "  [{:2}] user={}ns sys={}ns irq={}ns softirq={}ns ctx={}",
            c.cpu_id, c.user_ns, c.system_ns, c.irq_ns, c.softirq_ns, c.ctx_switches
        );
    }
    println!();

    println!("--- Network interfaces ({}/{}) ---",
        snap.net_iface_count, snap.net_ifaces.len());
    let n_net = (snap.net_iface_count as usize).min(snap.net_ifaces.len());
    for i in 0..n_net {
        let n = &snap.net_ifaces[i];
        println!(
            "  [idx={}] rx={} ({} pkt) tx={} ({} pkt) drops rx/tx={}/{}",
            n.iface_idx,
            format_bytes(n.rx_bytes),
            n.rx_packets,
            format_bytes(n.tx_bytes),
            n.tx_packets,
            n.rx_drops,
            n.tx_drops
        );
    }
    println!();

    println!("--- Block devices ({}/{}) ---",
        snap.block_dev_count, snap.block_devs.len());
    let n_blk = (snap.block_dev_count as usize).min(snap.block_devs.len());
    for i in 0..n_blk {
        let b = &snap.block_devs[i];
        println!(
            "  [{}:{}] read={} write={} ({} reads, {} writes)",
            b.device_major,
            b.device_minor,
            format_bytes(b.read_bytes),
            format_bytes(b.write_bytes),
            b.reads_completed,
            b.writes_completed
        );
    }
    println!();

    println!("--- Top processes ({}/{}) ---",
        snap.process_count, snap.top_processes.len());
    let n_proc = (snap.process_count as usize).min(snap.top_processes.len());
    // Cap the display at the first 20 rows so the output is usable.
    let show = n_proc.min(20);
    for i in 0..show {
        let p = &snap.top_processes[i];
        let comm = trim_cstr(&p.comm);
        println!(
            "  [{:5}] ppid={:5} uid={:5} cpu={}ns rss={} threads={} {}",
            p.pid,
            p.ppid,
            p.uid,
            p.cpu_user_ns,
            format_bytes(p.mem_rss_bytes),
            p.thread_count,
            comm
        );
    }
    if n_proc > show {
        println!("  ... {} more", n_proc - show);
    }
    println!();

    println!("--- Security ---");
    println!("ptrace:            {}", snap.security.ptrace);
    println!("memfd_create:      {}", snap.security.memfd_create);
    println!("prctl:             {}", snap.security.prctl);
    println!("setuid:            {}", snap.security.setuid);
    println!("exec_anomaly:      {}", snap.security.exec_anomaly);
    println!("capability_use:    {}", snap.security.capability_use);
}

fn format_bytes(b: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if b >= GIB {
        format!("{:.2} GiB", b as f64 / GIB as f64)
    } else if b >= MIB {
        format!("{:.1} MiB", b as f64 / MIB as f64)
    } else if b >= KIB {
        format!("{:.1} KiB", b as f64 / KIB as f64)
    } else {
        format!("{} B", b)
    }
}

fn format_wall_ns(ns: u64) -> String {
    // Quick human-readable form without pulling in chrono: seconds
    // since epoch + subsecond nanos.
    let secs = ns / 1_000_000_000;
    let subsec = ns % 1_000_000_000;
    format!("{}s + {:09}ns since epoch", secs, subsec)
}

fn trim_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
