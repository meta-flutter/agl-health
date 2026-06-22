//! Aggregated metric snapshot types.
//!
//! High-frequency counters (scheduler, CPU, block I/O) are accumulated inside
//! BPF maps in the kernel and polled by the userspace aggregator once per
//! second. The aggregator produces a `MetricSnapshot` containing the
//! structs in this module, then publishes it both via the REST API and via
//! the POSIX shared memory segment (see §4.3 of the implementation plan).

use crate::{COMM_LEN, SCHED_HIST_BUCKETS};

#[cfg(feature = "user")]
use serde::Serialize;

/// Per-CPU accumulated time (nanoseconds) in each scheduling class,
/// plus context-switch count. Derived from `sched:sched_switch` and
/// `irq:*` tracepoints.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct CpuStats {
    pub cpu_id: u32,
    /// C-ABI alignment padding. Excluded from the JSON wire format.
    #[cfg_attr(feature = "user", serde(skip))]
    pub _pad: u32,
    pub user_ns: u64,
    pub system_ns: u64,
    pub iowait_ns: u64,
    pub irq_ns: u64,
    pub softirq_ns: u64,
    pub idle_ns: u64,
    pub ctx_switches: u64,
}

/// Per-process accumulated statistics. Sourced entirely from kernel
/// tracepoints and kprobes - no `/proc` polling.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct ProcessStats {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub thread_count: u32,
    pub cpu_user_ns: u64,
    pub cpu_system_ns: u64,
    pub mem_rss_bytes: u64,
    pub mem_vms_bytes: u64,
    pub voluntary_ctx_sw: u64,
    pub involuntary_ctx_sw: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub page_faults_minor: u64,
    pub page_faults_major: u64,
    pub start_time_ns: u64,
    pub open_fds: u32,
    /// C-ABI alignment padding. Excluded from the JSON wire format.
    #[cfg_attr(feature = "user", serde(skip))]
    pub _pad: u32,
    pub comm: [u8; COMM_LEN],
}

/// Per-block-device I/O statistics from `block:block_rq_*` tracepoints.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct BlockStats {
    pub device_major: u32,
    pub device_minor: u32,
    pub reads_completed: u64,
    pub writes_completed: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_latency_ns: u64,
    pub write_latency_ns: u64,
    pub io_inflight: u64,
    pub io_ticks_ms: u64,
}

/// Per-network-interface byte/packet counters from `net:netif_*` tracepoints.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct NetIfaceStats {
    pub iface_idx: u32,
    /// C-ABI alignment padding. Excluded from the JSON wire format.
    #[cfg_attr(feature = "user", serde(skip))]
    pub _pad: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// System-wide TCP state machine snapshot, computed from
/// `sock:inet_sock_set_state`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct TcpStateSnapshot {
    pub established: u64,
    pub syn_sent: u64,
    pub syn_recv: u64,
    pub fin_wait1: u64,
    pub fin_wait2: u64,
    pub time_wait: u64,
    pub close_wait: u64,
    pub listen: u64,
    pub listen_overflows: u64,
    pub retransmits: u64,
    pub resets_in: u64,
    pub resets_out: u64,
}

/// Runqueue-wait latency histogram, one instance per CPU in a `PerCpuArray`.
/// Buckets are log-spaced as defined in `crate::SCHED_HIST_BUCKETS`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct SchedHistogram {
    pub buckets: [u64; SCHED_HIST_BUCKETS],
    pub total_count: u64,
    pub total_latency_ns: u64,
    pub max_latency_ns: u64,
}

/// Memory pressure and faulting snapshot (§5.2).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct MemorySnapshot {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub cached_bytes: u64,
    pub buffered_bytes: u64,
    pub slab_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_free_bytes: u64,
    pub page_faults_minor: u64,
    pub page_faults_major: u64,
    pub psi_some_pct_x100: u32,
    pub psi_full_pct_x100: u32,
    pub oom_kills_total: u64,
}

/// Per-cgroup network byte and packet counters populated by the
/// `cgroup_skb` ingress + egress programs in `agl-health-ebpf::netproc`.
///
/// The key for userspace aggregation is the cgroup v2 id, which is
/// the inode number of the cgroup directory under `/sys/fs/cgroup` and
/// is returned by `bpf_get_current_cgroup_id` / `bpf_skb_cgroup_id` on
/// the kernel side.
///
/// Internet vs local classification is done inside the cgroup_skb
/// BPF program by inspecting the IP header: RFC1918, loopback,
/// and link-local addresses are classified as "local"; everything
/// else is "internet". The `*_internet_bytes` fields are the
/// internet-classified subset of the total `*_bytes` counters.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct CgroupNetBytes {
    pub cgroup_id: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// Subset of `rx_bytes` whose source IP was not RFC1918/loopback/link-local.
    pub rx_internet_bytes: u64,
    /// Subset of `tx_bytes` whose destination IP was not RFC1918/loopback/link-local.
    pub tx_internet_bytes: u64,
}

/// Per-CPU count of ring-buffer events dropped because the buffer was
/// full when the kernel program tried to reserve space. Summed across
/// CPUs by the userspace aggregator and logged when it grows so that
/// event loss (e.g. a fork/ptrace storm) is observable rather than
/// silent.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct EventDropCounts {
    pub process: u64,
    pub security: u64,
    pub network: u64,
}

/// Cumulative counts of security-relevant syscalls and anomalies.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct SecurityEventCounts {
    pub ptrace: u64,
    pub memfd_create: u64,
    pub prctl: u64,
    pub setuid: u64,
    pub exec_anomaly: u64,
    pub capability_use: u64,
}
