//! `/proc` fallback tier for memory facts that have no eBPF equivalent.
//!
//! §5.2 of the implementation plan calls out three collection tiers -
//! event, map, and proc. This module owns the **proc** tier: facts that
//! are either genuinely static (`MemTotal`), near-static (`Cached`,
//! `Buffers`, `Slab`, swap totals), or that the kernel only exposes via
//! a pseudo-file (PSI memory pressure).
//!
//! The task runs unconditionally, independent of the `ebpf` cargo
//! feature: on a host without a BPF toolchain the aggregator is idle
//! and this module is the only writer on `SharedSnapshot.memory`, so
//! `/metrics/memory` still returns meaningful data.
//!
//! ### Writer discipline
//!
//! Two tasks write into `snap.memory`:
//!
//! * This one writes `total_bytes`, `free_bytes`, `cached_bytes`,
//!   `buffered_bytes`, `slab_bytes`, `swap_*_bytes`, `psi_*_pct_x100`.
//! * The eBPF aggregator writes `page_faults_minor`, `page_faults_major`,
//!   `oom_kills_total`.
//!
//! Each writer only touches its own fields under the shared lock, so
//! they don't clobber each other.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, warn};

use crate::metrics::{LoadSnapshot, SharedSnapshot};

/// Shared cache of per-pid facts sourced from `/proc/<pid>/status`.
///
/// The cache is written by this module once per tick and read by the
/// `/metrics/process` API handler, which overlays the fields onto each
/// returned `ProcessStats`. Keeping it separate from the snapshot means
/// the eBPF aggregator (1 Hz) can freely rewrite `snap.top_processes`
/// without clobbering the slower /proc-sourced fields.
pub type PidFactsCache = Arc<RwLock<HashMap<u32, PidStatusFacts>>>;

/// Per-pid facts we care about supplementing from `/proc/<pid>/status`.
/// Any field the kernel does not expose for the process (kernel threads
/// have no `VmRSS`, for example) stays at zero.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidStatusFacts {
    pub mem_rss_bytes: u64,
    pub mem_vms_bytes: u64,
    pub thread_count: u32,
}

/// Poll interval. Memory facts change slowly and /proc reads are cheap;
/// 5 seconds matches the plan's "proc" tier cadence.
const PROC_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum number of pids from `snap.top_processes` to supplement per tick.
/// Bounds the cost of per-process `/proc/<pid>/status` reads to ~100 file
/// reads every 5 seconds regardless of the total process count.
const MAX_PID_SUPPLEMENTS: usize = 100;

/// Subset of memory facts sourced from `/proc`. Mirrors the subset of
/// `MemorySnapshot` fields this module is the authoritative writer for.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ProcMemFacts {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub cached_bytes: u64,
    pub buffered_bytes: u64,
    pub slab_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_free_bytes: u64,
    /// PSI memory `some` avg10, scaled x100 to fit in a `u32`
    /// (e.g. 12.34 % becomes 1234). Zero when PSI is unavailable.
    pub psi_some_pct_x100: u32,
    pub psi_full_pct_x100: u32,
}

/// Spawn the /proc polling task. Returns immediately.
pub fn start(shared: SharedSnapshot, pid_cache: PidFactsCache) {
    tokio::spawn(async move {
        let mut ticker = interval(PROC_POLL_INTERVAL);
        loop {
            ticker.tick().await;

            // (1) Memory facts - required. On failure skip the whole tick.
            let mem_facts = match read_proc_memory() {
                Ok(f) => f,
                Err(e) => {
                    warn!(error = %e, "proc memory read failed");
                    continue;
                }
            };

            // (2) Load averages - required. Cheap single-file read.
            let load = read_loadavg().unwrap_or_default();

            // (3) Per-pid supplementation. Snapshot the top-N pids under a
            //     short read lock, drop it, then do the filesystem reads
            //     outside the lock so we never block API requests on IO.
            let target_pids: Vec<u32> = {
                let snap = shared.read().await;
                snap.top_processes
                    .iter()
                    .take(MAX_PID_SUPPLEMENTS)
                    .map(|p| p.pid)
                    .collect()
            };
            let mut new_pid_facts: HashMap<u32, PidStatusFacts> =
                HashMap::with_capacity(target_pids.len());
            for pid in target_pids {
                // Missing files (pid exited between snapshot and read) are
                // silently skipped - no need to log.
                if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                    new_pid_facts.insert(pid, parse_pid_status(&s));
                }
            }

            // (4) Write everything back.
            {
                let mut snap = shared.write().await;
                snap.memory.total_bytes = mem_facts.total_bytes;
                snap.memory.free_bytes = mem_facts.free_bytes;
                snap.memory.cached_bytes = mem_facts.cached_bytes;
                snap.memory.buffered_bytes = mem_facts.buffered_bytes;
                snap.memory.slab_bytes = mem_facts.slab_bytes;
                snap.memory.swap_used_bytes = mem_facts.swap_used_bytes;
                snap.memory.swap_free_bytes = mem_facts.swap_free_bytes;
                snap.memory.psi_some_pct_x100 = mem_facts.psi_some_pct_x100;
                snap.memory.psi_full_pct_x100 = mem_facts.psi_full_pct_x100;
                snap.load = load;
            }
            {
                let mut cache = pid_cache.write().await;
                *cache = new_pid_facts;
            }
            debug!(?mem_facts, "proc tier refreshed");
        }
    });
}

/// Read `/proc/meminfo` and `/proc/pressure/memory` (if present) and
/// combine into a single `ProcMemFacts`. The PSI file is optional on
/// kernels without `CONFIG_PSI=y`, so missing-or-unparseable is a
/// non-fatal warning.
fn read_proc_memory() -> std::io::Result<ProcMemFacts> {
    let meminfo = std::fs::read_to_string("/proc/meminfo")?;
    let mut facts = parse_meminfo(&meminfo);
    if let Ok(psi) = std::fs::read_to_string("/proc/pressure/memory") {
        let (some, full) = parse_psi(&psi);
        facts.psi_some_pct_x100 = some;
        facts.psi_full_pct_x100 = full;
    }
    Ok(facts)
}

/// Parse the lines of `/proc/meminfo` into a `ProcMemFacts`. Values in
/// the file are reported in kilobytes (kB suffix); we convert to bytes.
/// Unknown keys are ignored so the parser stays forward-compatible with
/// new kernel versions.
fn parse_meminfo(input: &str) -> ProcMemFacts {
    let mut f = ProcMemFacts::default();
    let mut swap_total = 0u64;
    for line in input.lines() {
        // Lines look like: "MemTotal:       16261732 kB"
        let mut it = line.split_whitespace();
        let key = match it.next() {
            Some(k) => k.trim_end_matches(':'),
            None => continue,
        };
        let value: u64 = match it.next().and_then(|v| v.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        let bytes = value.saturating_mul(1024);
        match key {
            "MemTotal" => f.total_bytes = bytes,
            "MemFree" => f.free_bytes = bytes,
            "Cached" => f.cached_bytes = bytes,
            "Buffers" => f.buffered_bytes = bytes,
            "Slab" => f.slab_bytes = bytes,
            "SwapTotal" => swap_total = bytes,
            "SwapFree" => f.swap_free_bytes = bytes,
            _ => {}
        }
    }
    f.swap_used_bytes = swap_total.saturating_sub(f.swap_free_bytes);
    f
}

/// Parse `/proc/pressure/memory`. Format:
///
/// ```text
/// some avg10=0.00 avg60=0.00 avg300=0.00 total=1234
/// full avg10=0.00 avg60=0.00 avg300=0.00 total=1234
/// ```
///
/// Returns `(some_pct_x100, full_pct_x100)`. Any parse failure yields 0
/// for that row.
fn parse_psi(input: &str) -> (u32, u32) {
    let mut some_pct = 0u32;
    let mut full_pct = 0u32;
    for line in input.lines() {
        let mut it = line.split_whitespace();
        let tag = it.next().unwrap_or("");
        let avg10_field = it.next().unwrap_or("");
        let Some(num) = avg10_field.strip_prefix("avg10=") else {
            continue;
        };
        let parsed: f64 = num.parse().unwrap_or(0.0);
        let pct_x100 = (parsed * 100.0) as u32;
        match tag {
            "some" => some_pct = pct_x100,
            "full" => full_pct = pct_x100,
            _ => {}
        }
    }
    (some_pct, full_pct)
}

/// Read and parse `/proc/loadavg`. Returns `Ok(LoadSnapshot::default())`
/// if the file exists but is unparseable - the daemon should keep
/// running rather than fail over something this tangential.
fn read_loadavg() -> std::io::Result<LoadSnapshot> {
    let s = std::fs::read_to_string("/proc/loadavg")?;
    Ok(parse_loadavg(&s))
}

/// Parse `/proc/loadavg`. Format:
///
/// ```text
/// 0.23 0.45 0.67 1/234 5678
/// ```
///
/// The first three whitespace-separated fields are the 1/5/15-minute
/// load averages as floats. The rest (running/total tasks, last pid) we
/// ignore. Any parse failure yields `0.0` for that slot.
fn parse_loadavg(input: &str) -> LoadSnapshot {
    let mut it = input.split_whitespace();
    let load_1 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load_5 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load_15 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    LoadSnapshot {
        load_1,
        load_5,
        load_15,
    }
}

/// Parse a subset of `/proc/<pid>/status`:
///
/// ```text
/// Name:   bash
/// Threads:        1
/// VmSize:      12345 kB
/// VmRSS:        5432 kB
/// ```
///
/// Kernel threads don't have `VmRSS`/`VmSize`; those fields stay zero.
/// Line order is not guaranteed so we scan every line.
fn parse_pid_status(input: &str) -> PidStatusFacts {
    let mut f = PidStatusFacts::default();
    for line in input.lines() {
        // Each recognized line has the form "Key:\t<value> [units]".
        // `split_once(':')` separates the key; trimming the rest gives
        // the numeric portion for `split_whitespace().next()`.
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let mut values = rest.split_whitespace();
        match key {
            "VmRSS" => {
                if let Some(kb) = values.next().and_then(|v| v.parse::<u64>().ok()) {
                    f.mem_rss_bytes = kb.saturating_mul(1024);
                }
            }
            "VmSize" => {
                if let Some(kb) = values.next().and_then(|v| v.parse::<u64>().ok()) {
                    f.mem_vms_bytes = kb.saturating_mul(1024);
                }
            }
            "Threads" => {
                if let Some(n) = values.next().and_then(|v| v.parse::<u32>().ok()) {
                    f.thread_count = n;
                }
            }
            _ => {}
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_parses_known_fields() {
        let input = "\
MemTotal:       16000000 kB
MemFree:         1000000 kB
Buffers:          200000 kB
Cached:          3000000 kB
SwapCached:          100 kB
Active:          5000000 kB
Slab:             500000 kB
SwapTotal:       8000000 kB
SwapFree:        7500000 kB
Mapped:           123456 kB
";
        let f = parse_meminfo(input);
        assert_eq!(f.total_bytes, 16_000_000 * 1024);
        assert_eq!(f.free_bytes, 1_000_000 * 1024);
        assert_eq!(f.buffered_bytes, 200_000 * 1024);
        assert_eq!(f.cached_bytes, 3_000_000 * 1024);
        assert_eq!(f.slab_bytes, 500_000 * 1024);
        assert_eq!(f.swap_free_bytes, 7_500_000 * 1024);
        assert_eq!(f.swap_used_bytes, (8_000_000 - 7_500_000) * 1024);
    }

    #[test]
    fn meminfo_ignores_unknown_and_malformed() {
        let input = "\
MemTotal:       1024 kB
WeirdNewField:  9999 kB
Garbage line with no colon
MemFree:        garbage
Cached:         512 kB
";
        let f = parse_meminfo(input);
        assert_eq!(f.total_bytes, 1024 * 1024);
        assert_eq!(f.free_bytes, 0, "malformed MemFree stays at default");
        assert_eq!(f.cached_bytes, 512 * 1024);
    }

    #[test]
    fn psi_parses_some_and_full_avg10() {
        let input = "\
some avg10=12.34 avg60=0.50 avg300=0.20 total=123456
full avg10=1.00 avg60=0.00 avg300=0.00 total=654321
";
        let (some, full) = parse_psi(input);
        assert_eq!(some, 1234);
        assert_eq!(full, 100);
    }

    #[test]
    fn psi_tolerates_missing_rows() {
        let (some, full) = parse_psi("");
        assert_eq!(some, 0);
        assert_eq!(full, 0);

        let only_some = "some avg10=5.00 avg60=0 avg300=0 total=0\n";
        let (s, f) = parse_psi(only_some);
        assert_eq!(s, 500);
        assert_eq!(f, 0);
    }

    #[test]
    fn loadavg_parses_three_averages() {
        let input = "0.23 0.45 0.67 1/234 5678\n";
        let load = parse_loadavg(input);
        assert_eq!(load.load_1, 0.23);
        assert_eq!(load.load_5, 0.45);
        assert_eq!(load.load_15, 0.67);
    }

    #[test]
    fn loadavg_tolerates_short_or_malformed() {
        let load = parse_loadavg("");
        assert_eq!(load.load_1, 0.0);

        let load = parse_loadavg("garbage 1.0 not_a_float 1/1 1");
        assert_eq!(load.load_1, 0.0);
        assert_eq!(load.load_5, 1.0);
        assert_eq!(load.load_15, 0.0);
    }

    #[test]
    fn pid_status_parses_vm_and_threads() {
        let input = "\
Name:\tsomeproc
Umask:\t0022
State:\tS (sleeping)
Tgid:\t1234
Pid:\t1234
VmPeak:\t  400000 kB
VmSize:\t  380000 kB
VmRSS:\t   42000 kB
Threads:\t4
";
        let f = parse_pid_status(input);
        assert_eq!(f.mem_vms_bytes, 380_000 * 1024);
        assert_eq!(f.mem_rss_bytes, 42_000 * 1024);
        assert_eq!(f.thread_count, 4);
    }

    #[test]
    fn pid_status_zero_for_kernel_thread() {
        // Kernel threads have no VmRSS/VmSize lines at all.
        let input = "\
Name:\tkworker/0:0
State:\tI (idle)
Tgid:\t42
Threads:\t1
";
        let f = parse_pid_status(input);
        assert_eq!(f.mem_rss_bytes, 0);
        assert_eq!(f.mem_vms_bytes, 0);
        assert_eq!(f.thread_count, 1);
    }
}
