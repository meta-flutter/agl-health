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
