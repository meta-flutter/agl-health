// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! One-shot offset dump used by the Dart side of agl-health-native
//! to hand-code ByteData offsets. Not a regression test — run with
//! `--nocapture` to see the numbers.

use agl_health_common::metrics::MemorySnapshot;
use agl_health_common::metrics_v3::{
    LoadSnapshotFixed, MetricSnapshotV3, SchedSnapshotFixed, ShmHeader,
};
use std::mem::{offset_of, size_of};

macro_rules! off {
    ($root:ty, $($field:ident).+) => {
        offset_of!($root, $($field).+)
    };
}

#[test]
fn dump_offsets() {
    eprintln!("MetricSnapshotV3::SIZE     = {}", size_of::<MetricSnapshotV3>());
    eprintln!("ShmHeader size              = {}", size_of::<ShmHeader>());
    eprintln!();
    eprintln!("--- Header ---");
    eprintln!("magic                       @ {}", offset_of!(ShmHeader, magic));
    eprintln!("version                     @ {}", offset_of!(ShmHeader, version));
    eprintln!("sequence                    @ {}", offset_of!(ShmHeader, sequence));
    eprintln!("timestamp_ns_wall           @ {}", offset_of!(ShmHeader, timestamp_ns_wall));
    eprintln!("snapshot_size               @ {}", offset_of!(ShmHeader, snapshot_size));
    eprintln!();
    eprintln!("--- MetricSnapshotV3 top level ---");
    eprintln!("header                      @ {}", offset_of!(MetricSnapshotV3, header));
    eprintln!("memory                      @ {}", offset_of!(MetricSnapshotV3, memory));
    eprintln!("load                        @ {}", offset_of!(MetricSnapshotV3, load));
    eprintln!("sched                       @ {}", offset_of!(MetricSnapshotV3, sched));
    eprintln!("tcp                         @ {}", offset_of!(MetricSnapshotV3, tcp));
    eprintln!("security                    @ {}", offset_of!(MetricSnapshotV3, security));
    eprintln!("cpu_core_count              @ {}", offset_of!(MetricSnapshotV3, cpu_core_count));
    eprintln!("cpu_cores                   @ {}", offset_of!(MetricSnapshotV3, cpu_cores));
    eprintln!("net_iface_count             @ {}", offset_of!(MetricSnapshotV3, net_iface_count));
    eprintln!("net_ifaces                  @ {}", offset_of!(MetricSnapshotV3, net_ifaces));
    eprintln!("block_dev_count             @ {}", offset_of!(MetricSnapshotV3, block_dev_count));
    eprintln!("block_devs                  @ {}", offset_of!(MetricSnapshotV3, block_devs));
    eprintln!("process_count               @ {}", offset_of!(MetricSnapshotV3, process_count));
    eprintln!("top_processes               @ {}", offset_of!(MetricSnapshotV3, top_processes));
    eprintln!();
    eprintln!("--- MemorySnapshot sub-offsets ---");
    let m = off!(MetricSnapshotV3, memory);
    eprintln!("memory.total_bytes          @ {}", m + offset_of!(MemorySnapshot, total_bytes));
    eprintln!("memory.free_bytes           @ {}", m + offset_of!(MemorySnapshot, free_bytes));
    eprintln!("memory.cached_bytes         @ {}", m + offset_of!(MemorySnapshot, cached_bytes));
    eprintln!("memory.buffered_bytes       @ {}", m + offset_of!(MemorySnapshot, buffered_bytes));
    eprintln!("memory.slab_bytes           @ {}", m + offset_of!(MemorySnapshot, slab_bytes));
    eprintln!("memory.swap_used_bytes      @ {}", m + offset_of!(MemorySnapshot, swap_used_bytes));
    eprintln!("memory.swap_free_bytes      @ {}", m + offset_of!(MemorySnapshot, swap_free_bytes));
    eprintln!("memory.page_faults_minor    @ {}", m + offset_of!(MemorySnapshot, page_faults_minor));
    eprintln!("memory.page_faults_major    @ {}", m + offset_of!(MemorySnapshot, page_faults_major));
    eprintln!("memory.psi_some_pct_x100    @ {}", m + offset_of!(MemorySnapshot, psi_some_pct_x100));
    eprintln!("memory.psi_full_pct_x100    @ {}", m + offset_of!(MemorySnapshot, psi_full_pct_x100));
    eprintln!("memory.oom_kills_total      @ {}", m + offset_of!(MemorySnapshot, oom_kills_total));
    eprintln!();
    eprintln!("--- LoadSnapshotFixed sub-offsets ---");
    let l = off!(MetricSnapshotV3, load);
    eprintln!("load.load_1                 @ {}", l + offset_of!(LoadSnapshotFixed, load_1));
    eprintln!("load.load_5                 @ {}", l + offset_of!(LoadSnapshotFixed, load_5));
    eprintln!("load.load_15                @ {}", l + offset_of!(LoadSnapshotFixed, load_15));
    eprintln!();
    eprintln!("--- SchedSnapshotFixed top-level ---");
    let s = off!(MetricSnapshotV3, sched);
    eprintln!("sched.p50_ns                @ {}", s + offset_of!(SchedSnapshotFixed, p50_ns));
    eprintln!("sched.p95_ns                @ {}", s + offset_of!(SchedSnapshotFixed, p95_ns));
    eprintln!("sched.p99_ns                @ {}", s + offset_of!(SchedSnapshotFixed, p99_ns));
    // histogram total_count etc computed on demand later.
}

#[test]
fn dump_entry_sizes_and_sub_offsets() {
    use agl_health_common::metrics::*;
    use std::mem::{offset_of, size_of};
    eprintln!("--- Entry sizes ---");
    eprintln!("ProcessStats  = {} bytes", size_of::<ProcessStats>());
    eprintln!("CpuStats      = {} bytes", size_of::<CpuStats>());
    eprintln!("NetIfaceStats = {} bytes", size_of::<NetIfaceStats>());
    eprintln!("BlockStats    = {} bytes", size_of::<BlockStats>());
    eprintln!("TcpState      = {} bytes", size_of::<TcpStateSnapshot>());
    eprintln!();
    eprintln!("--- ProcessStats sub-offsets ---");
    eprintln!("pid            @ {}", offset_of!(ProcessStats, pid));
    eprintln!("ppid           @ {}", offset_of!(ProcessStats, ppid));
    eprintln!("uid            @ {}", offset_of!(ProcessStats, uid));
    eprintln!("thread_count   @ {}", offset_of!(ProcessStats, thread_count));
    eprintln!("cpu_user_ns    @ {}", offset_of!(ProcessStats, cpu_user_ns));
    eprintln!("cpu_system_ns  @ {}", offset_of!(ProcessStats, cpu_system_ns));
    eprintln!("mem_rss_bytes  @ {}", offset_of!(ProcessStats, mem_rss_bytes));
    eprintln!("mem_vms_bytes  @ {}", offset_of!(ProcessStats, mem_vms_bytes));
    eprintln!("vol_ctx_sw     @ {}", offset_of!(ProcessStats, voluntary_ctx_sw));
    eprintln!("invol_ctx_sw   @ {}", offset_of!(ProcessStats, involuntary_ctx_sw));
    eprintln!("read_bytes     @ {}", offset_of!(ProcessStats, read_bytes));
    eprintln!("write_bytes    @ {}", offset_of!(ProcessStats, write_bytes));
    eprintln!("pf_minor       @ {}", offset_of!(ProcessStats, page_faults_minor));
    eprintln!("pf_major       @ {}", offset_of!(ProcessStats, page_faults_major));
    eprintln!("start_time_ns  @ {}", offset_of!(ProcessStats, start_time_ns));
    eprintln!("open_fds       @ {}", offset_of!(ProcessStats, open_fds));
    eprintln!("comm           @ {}", offset_of!(ProcessStats, comm));
    eprintln!();
    eprintln!("--- CpuStats sub-offsets ---");
    eprintln!("cpu_id         @ {}", offset_of!(CpuStats, cpu_id));
    eprintln!("user_ns        @ {}", offset_of!(CpuStats, user_ns));
    eprintln!("system_ns      @ {}", offset_of!(CpuStats, system_ns));
    eprintln!("iowait_ns      @ {}", offset_of!(CpuStats, iowait_ns));
    eprintln!("irq_ns         @ {}", offset_of!(CpuStats, irq_ns));
    eprintln!("softirq_ns     @ {}", offset_of!(CpuStats, softirq_ns));
    eprintln!("idle_ns        @ {}", offset_of!(CpuStats, idle_ns));
    eprintln!("ctx_switches   @ {}", offset_of!(CpuStats, ctx_switches));
    eprintln!();
    eprintln!("--- NetIfaceStats sub-offsets ---");
    eprintln!("iface_idx      @ {}", offset_of!(NetIfaceStats, iface_idx));
    eprintln!("rx_bytes       @ {}", offset_of!(NetIfaceStats, rx_bytes));
    eprintln!("tx_bytes       @ {}", offset_of!(NetIfaceStats, tx_bytes));
    eprintln!("rx_packets     @ {}", offset_of!(NetIfaceStats, rx_packets));
    eprintln!("tx_packets     @ {}", offset_of!(NetIfaceStats, tx_packets));
    eprintln!("rx_drops       @ {}", offset_of!(NetIfaceStats, rx_drops));
    eprintln!("tx_drops       @ {}", offset_of!(NetIfaceStats, tx_drops));
    eprintln!("rx_errors      @ {}", offset_of!(NetIfaceStats, rx_errors));
    eprintln!("tx_errors      @ {}", offset_of!(NetIfaceStats, tx_errors));
    eprintln!();
    eprintln!("--- BlockStats sub-offsets ---");
    eprintln!("device_major   @ {}", offset_of!(BlockStats, device_major));
    eprintln!("device_minor   @ {}", offset_of!(BlockStats, device_minor));
    eprintln!("reads_comp     @ {}", offset_of!(BlockStats, reads_completed));
    eprintln!("writes_comp    @ {}", offset_of!(BlockStats, writes_completed));
    eprintln!("read_bytes     @ {}", offset_of!(BlockStats, read_bytes));
    eprintln!("write_bytes    @ {}", offset_of!(BlockStats, write_bytes));
    eprintln!("read_lat_ns    @ {}", offset_of!(BlockStats, read_latency_ns));
    eprintln!("write_lat_ns   @ {}", offset_of!(BlockStats, write_latency_ns));
    eprintln!("io_inflight    @ {}", offset_of!(BlockStats, io_inflight));
    eprintln!("io_ticks_ms    @ {}", offset_of!(BlockStats, io_ticks_ms));
    eprintln!();
    eprintln!("--- TcpStateSnapshot sub-offsets ---");
    eprintln!("established    @ {}", offset_of!(TcpStateSnapshot, established));
    eprintln!("syn_sent       @ {}", offset_of!(TcpStateSnapshot, syn_sent));
    eprintln!("syn_recv       @ {}", offset_of!(TcpStateSnapshot, syn_recv));
    eprintln!("fin_wait1      @ {}", offset_of!(TcpStateSnapshot, fin_wait1));
    eprintln!("fin_wait2      @ {}", offset_of!(TcpStateSnapshot, fin_wait2));
    eprintln!("time_wait      @ {}", offset_of!(TcpStateSnapshot, time_wait));
    eprintln!("close_wait     @ {}", offset_of!(TcpStateSnapshot, close_wait));
    eprintln!("listen         @ {}", offset_of!(TcpStateSnapshot, listen));
    eprintln!("listen_ofl     @ {}", offset_of!(TcpStateSnapshot, listen_overflows));
    eprintln!("retransmits    @ {}", offset_of!(TcpStateSnapshot, retransmits));
    eprintln!("resets_in      @ {}", offset_of!(TcpStateSnapshot, resets_in));
    eprintln!("resets_out     @ {}", offset_of!(TcpStateSnapshot, resets_out));
}

#[test]
fn dump_per_cpu_sched_offsets() {
    use agl_health_common::metrics_v3::{MetricSnapshotV3, SchedSnapshotFixed};
    use std::mem::{offset_of, size_of};
    eprintln!("--- Per-CPU scheduler ---");
    eprintln!("sched_cpu_count             @ {}", offset_of!(MetricSnapshotV3, sched_cpu_count));
    eprintln!("sched_per_cpu               @ {}", offset_of!(MetricSnapshotV3, sched_per_cpu));
    eprintln!("SchedSnapshotFixed size      = {}", size_of::<SchedSnapshotFixed>());
    eprintln!("MetricSnapshotV3 total       = {}", size_of::<MetricSnapshotV3>());
}
