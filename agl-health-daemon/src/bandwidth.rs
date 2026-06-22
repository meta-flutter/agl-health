//! Rolling window for per-cgroup bandwidth history.
//!
//! Stores the last 60 seconds of per-cgroup byte snapshots. On each
//! aggregator tick the current `Vec<CgroupNetBytes>` is pushed into
//! the window. API queries with `?window=30s` compute deltas between
//! the current snapshot and the one closest to `now - window_secs`.
//!
//! This is the daemon's short-term memory. Long-term retention
//! (hours/days/weeks) is pushed to EdgeX or Prometheus via the
//! existing shm/REST path — see the project memory note on
//! bandwidth tracking decisions.

use std::collections::VecDeque;
use std::sync::Arc;

use agl_health_common::metrics::CgroupNetBytes;
use serde::Serialize;
use tokio::sync::RwLock;

/// Maximum number of samples kept in the window. At 1 sample/sec
/// this gives 60 seconds of history.
const MAX_SAMPLES: usize = 60;

/// A single timestamped snapshot of per-cgroup counters.
struct Sample {
    timestamp_ns: u64,
    entries: Vec<CgroupNetBytes>,
}

/// Rolling window state. Shared between the aggregator (writer)
/// and the API layer (reader) via `SharedBandwidthWindow`.
pub struct BandwidthWindow {
    samples: VecDeque<Sample>,
}

impl BandwidthWindow {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES + 1),
        }
    }

    /// Push a new snapshot. Called once per aggregator tick.
    /// Only called when the `ebpf` feature is enabled.
    #[allow(dead_code)]
    pub fn push(&mut self, timestamp_ns: u64, entries: Vec<CgroupNetBytes>) {
        if self.samples.len() >= MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(Sample {
            timestamp_ns,
            entries,
        });
    }

    /// Query the window for a delta over `window_secs`. Returns the
    /// per-cgroup difference between the latest snapshot and the
    /// one closest to `latest.timestamp - window_secs * 1e9`.
    ///
    /// If `window_secs == 0`, returns the latest cumulative snapshot
    /// (no delta computation). If the window is larger than the
    /// available history, uses the oldest available sample.
    pub fn query(&self, window_secs: u64) -> Vec<CgroupBandwidthDelta> {
        let latest = match self.samples.back() {
            Some(s) => s,
            None => return Vec::new(),
        };

        if window_secs == 0 {
            // Cumulative mode: return raw counters.
            return latest
                .entries
                .iter()
                .map(|e| CgroupBandwidthDelta {
                    cgroup_id: e.cgroup_id,
                    rx_bytes: e.rx_bytes,
                    tx_bytes: e.tx_bytes,
                    rx_internet_bytes: e.rx_internet_bytes,
                    tx_internet_bytes: e.tx_internet_bytes,
                    rx_packets: e.rx_packets,
                    tx_packets: e.tx_packets,
                })
                .collect();
        }

        let target_ts = latest
            .timestamp_ns
            .saturating_sub(window_secs * 1_000_000_000);

        // Find the sample closest to (but not after) target_ts.
        let old = self
            .samples
            .iter()
            .rev()
            .find(|s| s.timestamp_ns <= target_ts)
            .unwrap_or_else(|| self.samples.front().unwrap());

        // Build a lookup of old entries by cgroup_id.
        let old_map: std::collections::HashMap<u64, &CgroupNetBytes> = old
            .entries
            .iter()
            .map(|e| (e.cgroup_id, e))
            .collect();

        let mut deltas: Vec<CgroupBandwidthDelta> = latest
            .entries
            .iter()
            .map(|cur| {
                let zero = CgroupNetBytes::default();
                let prev = old_map.get(&cur.cgroup_id).copied().unwrap_or(&zero);
                CgroupBandwidthDelta {
                    cgroup_id: cur.cgroup_id,
                    rx_bytes: cur.rx_bytes.saturating_sub(prev.rx_bytes),
                    tx_bytes: cur.tx_bytes.saturating_sub(prev.tx_bytes),
                    rx_internet_bytes: cur
                        .rx_internet_bytes
                        .saturating_sub(prev.rx_internet_bytes),
                    tx_internet_bytes: cur
                        .tx_internet_bytes
                        .saturating_sub(prev.tx_internet_bytes),
                    rx_packets: cur.rx_packets.saturating_sub(prev.rx_packets),
                    tx_packets: cur.tx_packets.saturating_sub(prev.tx_packets),
                }
            })
            .collect();

        // Sort by total internet bytes descending.
        deltas.sort_by(|a, b| {
            // saturating_add: in cumulative (`window_secs == 0`) mode these
            // are full since-boot counters, and two summed can overflow u64
            // on a long-running system.
            let a_total = a.rx_internet_bytes.saturating_add(a.tx_internet_bytes);
            let b_total = b.rx_internet_bytes.saturating_add(b.tx_internet_bytes);
            b_total.cmp(&a_total)
        });

        deltas
    }
}

/// Shared handle passed to the aggregator (writer) and API (reader).
pub type SharedBandwidthWindow = Arc<RwLock<BandwidthWindow>>;

/// A single cgroup's delta over the queried window. Serialized
/// directly in the API response. The `cgroup_name` field is
/// overlaid by the API handler from the cgroup name cache.
#[derive(Serialize, Clone)]
pub struct CgroupBandwidthDelta {
    pub cgroup_id: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_internet_bytes: u64,
    pub tx_internet_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// Wire-format response for `/metrics/network/cgroup` with name
/// overlay and optional windowed delta.
#[derive(Serialize)]
pub struct CgroupBandwidthEntry {
    pub cgroup_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_name: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_internet_bytes: u64,
    pub tx_internet_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}
