//! Aggregated metric snapshot published via the `/metrics/*` HTTP API.
//!
//! This module is unconditional: the daemon builds even without the `ebpf`
//! cargo feature, in which case the `SharedSnapshot` simply stays at its
//! default zero state and the API returns zero-valued JSON. When the feature
//! is enabled, `aggregator::start` refreshes this shared value every second
//! by polling the BPF maps.
//!
//! `MetricSnapshot` is the single source of truth for everything the API
//! layer serves. All field types come from `agl_health_common` so there is
//! one wire format shared between the daemon, the EdgeX bridge, and the
//! Flutter app.

use std::sync::Arc;

use agl_health_common::{
    metrics::{
        BlockStats, CgroupNetBytes, CpuStats, MemorySnapshot, NetIfaceStats, ProcessStats,
        SchedHistogram, SecurityEventCounts, TcpStateSnapshot,
    },
    SCHED_HIST_BUCKETS,
};
use serde::Serialize;
use tokio::sync::RwLock;

/// Full metric snapshot refreshed once per second by the aggregator.
#[derive(Default, Clone, Serialize)]
pub struct MetricSnapshot {
    /// Wall-clock nanoseconds since the UNIX epoch at the moment the
    /// aggregator finished collecting this snapshot. Zero before the first
    /// collection.
    pub timestamp_ns: u64,
    pub memory: MemorySnapshot,
    pub sched: SchedSnapshot,
    pub tcp: TcpStateSnapshot,
    /// System load averages from `/proc/loadavg`, refreshed by the
    /// `proc_tier` task. Populated even when the `ebpf` feature is off.
    pub load: LoadSnapshot,
    /// One `CpuStats` per online CPU core. Produced by the aggregator
    /// from the `CPU_STATS` per-CPU array. Empty without the `ebpf`
    /// feature.
    pub cpu_cores: Vec<CpuStats>,
    /// One entry per network interface. Currently a single aggregate slot;
    /// per-ifindex breakdown is a TODO on the kernel side.
    pub net_ifaces: Vec<NetIfaceStats>,
    /// One entry per block device seen since the daemon started.
    pub block: Vec<BlockStats>,
    /// Top processes by cumulative on-CPU time, sorted descending.
    /// Capped at `aggregator::TOP_PROCESS_CAP` entries; the API layer
    /// further trims via `?limit=N`.
    pub top_processes: Vec<ProcessStats>,
    /// Cumulative counts of security-relevant syscall events. See
    /// §5.7 of the implementation plan.
    pub security: SecurityEventCounts,
    /// Top cgroups by cumulative rx+tx bytes, sorted descending.
    /// Produced by the `netproc` eBPF programs via the aggregator.
    /// Empty without the `ebpf` feature.
    pub cgroup_net_top: Vec<CgroupNetBytes>,
}

/// System load averages. `f64` rather than the PSI-style x100 integer
/// because load averages are conventionally shown with two decimal
/// places and consumers expect floats.
#[derive(Default, Clone, Serialize)]
pub struct LoadSnapshot {
    pub load_1: f64,
    pub load_5: f64,
    pub load_15: f64,
}

/// Scheduler latency histogram with pre-computed percentiles so clients do
/// not need to understand the bucket layout.
#[derive(Default, Clone, Serialize)]
pub struct SchedSnapshot {
    pub histogram: SchedHistogram,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

/// The shared handle passed to the aggregator (writer) and every axum
/// handler (reader). `tokio::sync::RwLock` gives us an async-friendly
/// write operation at 1Hz; read contention from the API layer is
/// negligible at typical request rates.
pub type SharedSnapshot = Arc<RwLock<MetricSnapshot>>;

/// Upper bound of each scheduler latency bucket, in nanoseconds. Keep in
/// sync with `agl_health_ebpf::scheduler::bucket_of`. The final bucket is
/// unbounded in the kernel-side code but we report its upper edge as
/// `u64::MAX` to keep the percentile routine total.
// Used by the aggregator only; dormant in the default (non-ebpf) build.
#[allow(dead_code)]
const BUCKET_BOUNDS_NS: [u64; SCHED_HIST_BUCKETS] = [
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
    u64::MAX,
];

/// Compute the `p`-th percentile of a scheduler latency histogram (0.0 .. 1.0).
/// Returns the *upper bound* of the bucket in which the cumulative count
/// first reaches or exceeds the target — a standard conservative approximation.
#[allow(dead_code)]
pub fn percentile_ns(hist: &SchedHistogram, p: f64) -> u64 {
    if hist.total_count == 0 {
        return 0;
    }
    // ceil so p95 of 100 events lands in the bucket containing the 95th.
    let target = ((hist.total_count as f64) * p).ceil() as u64;
    let mut cum: u64 = 0;
    for i in 0..SCHED_HIST_BUCKETS {
        cum = cum.saturating_add(hist.buckets[i]);
        if cum >= target {
            return BUCKET_BOUNDS_NS[i];
        }
    }
    u64::MAX
}
