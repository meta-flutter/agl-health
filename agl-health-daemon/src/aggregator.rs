//! BPF map aggregator task.
//!
//! Runs under `cfg(feature = "ebpf")` only. Owns the polled-map handles
//! taken out of the loaded `Ebpf` struct and, once per second, merges each
//! map into a fresh `MetricSnapshot` which is published through the
//! `SharedSnapshot` for the HTTP API to read.
//!
//! All wrapper newtypes here exist because aya's `Pod` trait is foreign
//! and our metric structs live in the foreign `agl-health-common` crate:
//! the orphan rule forbids `unsafe impl aya::Pod for SchedHistogram {}`
//! in this crate directly. Wrapping in `#[repr(transparent)]` is sound
//! because the inner types are all `#[repr(C)]` plain-old-data.

#![cfg(feature = "ebpf")]

use std::time::Duration;

use agl_health_common::{
    metrics::{
        BlockStats, CgroupNetBytes, CpuStats, MemorySnapshot, NetIfaceStats, ProcessStats,
        SchedHistogram, SecurityEventCounts, TcpStateSnapshot,
    },
    SCHED_HIST_BUCKETS,
};
use anyhow::{Context, Result};
use aya::{
    maps::{HashMap as AyaHash, MapData, PerCpuArray, PerCpuValues},
    Pod,
};
use tokio::time::interval;
use tracing::{debug, warn};

use crate::metrics::{percentile_ns, SchedSnapshot, SharedSnapshot};

macro_rules! pod_wrap {
    ($(#[$m:meta])* $name:ident, $inner:ty) => {
        $(#[$m])*
        #[repr(transparent)]
        #[derive(Copy, Clone, Default)]
        pub struct $name(pub $inner);

        // SAFETY: `$inner` is `#[repr(C)]` with only integer / fixed-array
        // fields (see agl_health_common::metrics). `#[repr(transparent)]`
        // guarantees identical layout. All bit patterns are valid.
        unsafe impl Pod for $name {}
    };
}

pod_wrap!(PodSchedHistogram, SchedHistogram);
pod_wrap!(PodNetIfaceStats, NetIfaceStats);
pod_wrap!(PodTcpStateSnapshot, TcpStateSnapshot);
pod_wrap!(PodMemorySnapshot, MemorySnapshot);
pod_wrap!(PodBlockStats, BlockStats);
pod_wrap!(PodProcessStats, ProcessStats);
pod_wrap!(PodCpuStats, CpuStats);
pod_wrap!(PodSecurityEventCounts, SecurityEventCounts);
pod_wrap!(PodCgroupNetBytes, CgroupNetBytes);

/// Owned BPF map handles handed to the aggregator task by the loader.
pub struct PolledMaps {
    pub sched: PerCpuArray<MapData, PodSchedHistogram>,
    pub net_iface: PerCpuArray<MapData, PodNetIfaceStats>,
    pub tcp_state: PerCpuArray<MapData, PodTcpStateSnapshot>,
    pub memory: PerCpuArray<MapData, PodMemorySnapshot>,
    pub block: AyaHash<MapData, u32, PodBlockStats>,
    pub process: AyaHash<MapData, u32, PodProcessStats>,
    pub cpu: PerCpuArray<MapData, PodCpuStats>,
    pub security: PerCpuArray<MapData, PodSecurityEventCounts>,
    pub net_cgroup: AyaHash<MapData, u64, PodCgroupNetBytes>,
}

/// Cap on the number of cgroups kept in each sorted snapshot. Same
/// rationale as `TOP_PROCESS_CAP`: larger than the expected
/// `?limit=N` so API clients can page within a single tick's window.
const TOP_CGROUP_CAP: usize = 128;

/// Maximum number of processes kept in the snapshot after sorting by CPU
/// time. Larger than the typical `?limit=` query so clients can page
/// client-side without the aggregator having to re-sort.
const TOP_PROCESS_CAP: usize = 256;

/// BPF-sourced portion of a metric snapshot. Fields the aggregator owns
/// end-to-end; fields sourced from `/proc` (memory totals, PSI, swap) are
/// deliberately absent so the partial merge in `start()` can leave
/// `proc_tier`'s writes alone.
struct BpfSample {
    timestamp_ns: u64,
    sched: SchedSnapshot,
    tcp: TcpStateSnapshot,
    net_ifaces: Vec<NetIfaceStats>,
    block: Vec<BlockStats>,
    top_processes: Vec<ProcessStats>,
    cpu_cores: Vec<CpuStats>,
    security: SecurityEventCounts,
    cgroup_net_top: Vec<CgroupNetBytes>,
    /// Three memory fields the BPF pipeline is authoritative for - see
    /// §5.2 of the implementation plan's tier table.
    page_faults_minor: u64,
    page_faults_major: u64,
    oom_kills_total: u64,
}

/// Spawn the aggregator loop. Returns immediately; the task lives as long
/// as the daemon process. If a single poll fails the task logs the error
/// and keeps going — transient `MapError::KeyNotFound` on a cold map is
/// common until kernel probes start firing.
pub fn start(
    maps: PolledMaps,
    shared: SharedSnapshot,
    time_base: crate::time_base::TimeBase,
    bw_window: crate::bandwidth::SharedBandwidthWindow,
) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            match collect(&maps, &time_base) {
                Ok(sample) => {
                    // Push into rolling bandwidth window before writing
                    // the shared snapshot, so the window always has the
                    // freshest data.
                    {
                        let mut bw = bw_window.write().await;
                        bw.push(sample.timestamp_ns, sample.cgroup_net_top.clone());
                    }

                    // Partial merge: overwrite BPF-owned fields only.
                    let mut snap = shared.write().await;
                    snap.timestamp_ns = sample.timestamp_ns;
                    snap.sched = sample.sched;
                    snap.tcp = sample.tcp;
                    snap.net_ifaces = sample.net_ifaces;
                    snap.block = sample.block;
                    snap.top_processes = sample.top_processes;
                    snap.cpu_cores = sample.cpu_cores;
                    snap.security = sample.security;
                    snap.cgroup_net_top = sample.cgroup_net_top;
                    snap.memory.page_faults_minor = sample.page_faults_minor;
                    snap.memory.page_faults_major = sample.page_faults_major;
                    snap.memory.oom_kills_total = sample.oom_kills_total;
                    debug!("metric snapshot refreshed");
                }
                Err(e) => warn!(error = %e, "aggregator collect failed"),
            }
        }
    });
}

fn collect(maps: &PolledMaps, time_base: &crate::time_base::TimeBase) -> Result<BpfSample> {
    let sched_hist: SchedHistogram =
        sum_percpu(&maps.sched, merge_sched).context("sched histogram")?;
    let tcp: TcpStateSnapshot = sum_percpu(&maps.tcp_state, merge_tcp).context("tcp state")?;
    let net_iface: NetIfaceStats =
        sum_percpu(&maps.net_iface, merge_iface).context("net iface stats")?;
    let memory: MemorySnapshot =
        sum_percpu(&maps.memory, merge_mem).context("memory snapshot")?;
    let block: Vec<BlockStats> = collect_block(&maps.block).context("block stats")?;
    let top_processes: Vec<ProcessStats> =
        collect_top_processes(&maps.process).context("process stats")?;
    let cpu_cores: Vec<CpuStats> = collect_per_cpu_cores(&maps.cpu).context("cpu cores")?;
    let security: SecurityEventCounts =
        sum_percpu(&maps.security, merge_security).context("security counts")?;
    let cgroup_net_top: Vec<CgroupNetBytes> =
        collect_cgroup_net(&maps.net_cgroup).context("cgroup net stats")?;

    let sched = SchedSnapshot {
        p50_ns: percentile_ns(&sched_hist, 0.50),
        p95_ns: percentile_ns(&sched_hist, 0.95),
        p99_ns: percentile_ns(&sched_hist, 0.99),
        histogram: sched_hist,
    };

    Ok(BpfSample {
        timestamp_ns: time_base.now_wall_ns(),
        sched,
        tcp,
        net_ifaces: vec![net_iface],
        block,
        top_processes,
        cpu_cores,
        security,
        cgroup_net_top,
        page_faults_minor: memory.page_faults_minor,
        page_faults_major: memory.page_faults_major,
        oom_kills_total: memory.oom_kills_total,
    })
}

/// Read slot 0 of a `PerCpuArray<_, PodCpuStats>` and produce one
/// wire-format `CpuStats` per online CPU. The `cpu_id` field is
/// assigned from the iteration index since the kernel programs don't
/// stamp it (per-CPU maps already carry CPU identity implicitly).
fn collect_per_cpu_cores(map: &PerCpuArray<MapData, PodCpuStats>) -> Result<Vec<CpuStats>> {
    let values: PerCpuValues<PodCpuStats> = map
        .get(&0u32, 0)
        .context("PerCpuArray::get(slot 0) for CPU_STATS")?;
    let mut out: Vec<CpuStats> = Vec::with_capacity(values.iter().len());
    for (idx, v) in values.iter().enumerate() {
        let mut s = v.0;
        s.cpu_id = idx as u32;
        out.push(s);
    }
    Ok(out)
}

/// Read the per-cgroup `NET_CGROUP_STATS` hashmap, sort by total
/// `rx_bytes + tx_bytes` descending, and cap at `TOP_CGROUP_CAP`.
/// The resulting `Vec` is what `/metrics/network/cgroup` serves.
fn collect_cgroup_net(
    map: &AyaHash<MapData, u64, PodCgroupNetBytes>,
) -> Result<Vec<CgroupNetBytes>> {
    let mut out: Vec<CgroupNetBytes> = Vec::new();
    for res in map.iter() {
        let (_cgid, v) = res.context("NET_CGROUP_STATS iter")?;
        out.push(v.0);
    }
    out.sort_by(|a, b| {
        let a_total = a.rx_bytes.saturating_add(a.tx_bytes);
        let b_total = b.rx_bytes.saturating_add(b.tx_bytes);
        b_total.cmp(&a_total)
    });
    out.truncate(TOP_CGROUP_CAP);
    Ok(out)
}

fn collect_top_processes(
    map: &AyaHash<MapData, u32, PodProcessStats>,
) -> Result<Vec<ProcessStats>> {
    let mut out: Vec<ProcessStats> = Vec::new();
    for res in map.iter() {
        let (_pid, v) = res.context("PROCESS_STATS iter")?;
        out.push(v.0);
    }
    // Partial sort would suffice since we truncate, but the map is bounded
    // at ~4096 entries (see stats.rs) so a full sort is cheap and simpler.
    out.sort_by(|a, b| b.cpu_user_ns.cmp(&a.cpu_user_ns));
    out.truncate(TOP_PROCESS_CAP);
    Ok(out)
}

/// Read slot 0 of a `PerCpuArray<_, P>` and fold every per-CPU sample into
/// an accumulator `T` via `merge`. The array is expected to have exactly
/// one logical entry that the kernel programs update in place.
fn sum_percpu<P, T, F>(map: &PerCpuArray<MapData, P>, merge: F) -> Result<T>
where
    P: Pod,
    T: Default,
    F: Fn(&mut T, &P),
{
    let values: PerCpuValues<P> = map
        .get(&0u32, 0)
        .context("PerCpuArray::get(slot 0)")?;
    let mut acc = T::default();
    for v in values.iter() {
        merge(&mut acc, v);
    }
    Ok(acc)
}

fn merge_sched(acc: &mut SchedHistogram, v: &PodSchedHistogram) {
    let s = &v.0;
    for i in 0..SCHED_HIST_BUCKETS {
        acc.buckets[i] = acc.buckets[i].wrapping_add(s.buckets[i]);
    }
    acc.total_count = acc.total_count.wrapping_add(s.total_count);
    acc.total_latency_ns = acc.total_latency_ns.wrapping_add(s.total_latency_ns);
    if s.max_latency_ns > acc.max_latency_ns {
        acc.max_latency_ns = s.max_latency_ns;
    }
}

fn merge_tcp(acc: &mut TcpStateSnapshot, v: &PodTcpStateSnapshot) {
    let s = &v.0;
    acc.established = acc.established.wrapping_add(s.established);
    acc.syn_sent = acc.syn_sent.wrapping_add(s.syn_sent);
    acc.syn_recv = acc.syn_recv.wrapping_add(s.syn_recv);
    acc.fin_wait1 = acc.fin_wait1.wrapping_add(s.fin_wait1);
    acc.fin_wait2 = acc.fin_wait2.wrapping_add(s.fin_wait2);
    acc.time_wait = acc.time_wait.wrapping_add(s.time_wait);
    acc.close_wait = acc.close_wait.wrapping_add(s.close_wait);
    acc.listen = acc.listen.wrapping_add(s.listen);
    acc.listen_overflows = acc.listen_overflows.wrapping_add(s.listen_overflows);
    acc.retransmits = acc.retransmits.wrapping_add(s.retransmits);
    acc.resets_in = acc.resets_in.wrapping_add(s.resets_in);
    acc.resets_out = acc.resets_out.wrapping_add(s.resets_out);
}

fn merge_iface(acc: &mut NetIfaceStats, v: &PodNetIfaceStats) {
    let s = &v.0;
    // Only slot 0 exists today — the kernel writes with `iface_idx = 0`
    // until per-interface breakdown lands. Propagate it verbatim.
    acc.iface_idx = s.iface_idx;
    acc.rx_bytes = acc.rx_bytes.wrapping_add(s.rx_bytes);
    acc.tx_bytes = acc.tx_bytes.wrapping_add(s.tx_bytes);
    acc.rx_packets = acc.rx_packets.wrapping_add(s.rx_packets);
    acc.tx_packets = acc.tx_packets.wrapping_add(s.tx_packets);
    acc.rx_drops = acc.rx_drops.wrapping_add(s.rx_drops);
    acc.tx_drops = acc.tx_drops.wrapping_add(s.tx_drops);
    acc.rx_errors = acc.rx_errors.wrapping_add(s.rx_errors);
    acc.tx_errors = acc.tx_errors.wrapping_add(s.tx_errors);
}

fn merge_security(acc: &mut SecurityEventCounts, v: &PodSecurityEventCounts) {
    let s = &v.0;
    acc.ptrace = acc.ptrace.wrapping_add(s.ptrace);
    acc.memfd_create = acc.memfd_create.wrapping_add(s.memfd_create);
    acc.prctl = acc.prctl.wrapping_add(s.prctl);
    acc.setuid = acc.setuid.wrapping_add(s.setuid);
    acc.exec_anomaly = acc.exec_anomaly.wrapping_add(s.exec_anomaly);
    acc.capability_use = acc.capability_use.wrapping_add(s.capability_use);
}

fn merge_mem(acc: &mut MemorySnapshot, v: &PodMemorySnapshot) {
    let s = &v.0;
    acc.page_faults_minor = acc.page_faults_minor.wrapping_add(s.page_faults_minor);
    acc.page_faults_major = acc.page_faults_major.wrapping_add(s.page_faults_major);
    acc.oom_kills_total = acc.oom_kills_total.wrapping_add(s.oom_kills_total);
    // Fields sourced from /proc (total, free, cached, swap, PSI) are
    // populated by a separate aggregator tier — see §5.2 of the plan.
}

fn collect_block(map: &AyaHash<MapData, u32, PodBlockStats>) -> Result<Vec<BlockStats>> {
    let mut out = Vec::new();
    for res in map.iter() {
        let (_dev, v) = res.context("BLOCK_STATS iter")?;
        out.push(v.0);
    }
    Ok(out)
}

