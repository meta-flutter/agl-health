//! eBPF program loader.
//!
//! The module compiles unconditionally so CI catches regressions whether or
//! not the `ebpf` cargo feature is enabled. Without the feature `EBPF_OBJ`
//! is an empty slice and `load()` returns an error before touching any
//! kernel interface, so `cargo build -p agl-health-daemon` works on a host
//! without a BPF toolchain.
//!
//! With the feature enabled, `load()` performs:
//!
//!   1. `Ebpf::load(EBPF_OBJ)` — parse the relocatable object emitted by
//!      stage 1.
//!   2. Attach every tracepoint and kprobe declared in the `agl-health-ebpf`
//!      crate. Per-program errors are logged and tolerated: a missing
//!      tracepoint (e.g. a missing tracepoint on an unusual kernel
//!      on aarch64) must not take the whole daemon down.
//!   3. Take ownership of the `PROCESS_EVENTS` and `NET_EVENTS` ring buffer
//!      maps and spawn tokio tasks that drain them via `AsyncFd`.
//!
//! The returned `LoadedEbpf` owns the `Ebpf` struct. Dropping it detaches
//! all programs, so callers must keep it alive for the lifetime of the
//! daemon.

#![allow(dead_code)] // parts are only reachable under cfg(feature = "ebpf")

use anyhow::{bail, Result};
#[cfg(feature = "ebpf")]
use anyhow::Context;

#[cfg(feature = "ebpf")]
mod aligned {
    //! Ensures the embedded BPF object is aligned to at least 8 bytes, which
    //! is what aya's ELF parser requires. `include_bytes!` alone yields a
    //! `&[u8; N]` with no specific alignment; wrapping it in a repr(align)
    //! struct forces the static allocation to be over-aligned.
    #[repr(C)]
    #[repr(align(32))]
    pub struct Aligned<Bytes: ?Sized>(pub Bytes);

    pub static EBPF_ALIGNED: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(
        env!("OUT_DIR"),
        "/agl-health-ebpf.bin"
    )));
}

#[cfg(feature = "ebpf")]
const EBPF_OBJ: &[u8] = &aligned::EBPF_ALIGNED.0;

#[cfg(not(feature = "ebpf"))]
const EBPF_OBJ: &[u8] = &[];

/// Table of every tracepoint program defined by the `agl-health-ebpf` crate.
/// Each row is `(program_name, tracepoint_category, tracepoint_event)`.
/// `program_name` must match the Rust function name annotated with
/// `#[tracepoint]` on the kernel side.
/// Regular tracepoints — use tracepoint format offsets (named
/// constants in the eBPF crate's `offsets.rs`).
const TRACEPOINTS: &[(&str, &str, &str)] = &[
    // network.rs (format offsets for len/rc)
    ("netif_receive_skb", "net", "netif_receive_skb"),
    ("net_dev_xmit", "net", "net_dev_xmit"),
    ("tcp_retransmit_skb", "tcp", "tcp_retransmit_skb"),
    // block.rs (format offsets for dev/bytes/rwbs)
    ("block_rq_complete", "block", "block_rq_complete"),
    // cpu.rs (no payload reads, just timing)
    ("irq_handler_entry", "irq", "irq_handler_entry"),
    ("irq_handler_exit", "irq", "irq_handler_exit"),
    ("softirq_entry", "irq", "softirq_entry"),
    ("softirq_exit", "irq", "softirq_exit"),
    // security.rs (syscall arg offsets)
    ("sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
    ("sys_enter_memfd_create", "syscalls", "sys_enter_memfd_create"),
    ("sys_enter_setuid", "syscalls", "sys_enter_setuid"),
    ("sys_enter_prctl", "syscalls", "sys_enter_prctl"),
];

/// BTF tracepoints — use `ctx.arg::<T>(n)` with compile-time type
/// safety from vmlinux.rs. No format offsets needed. Requires
/// kernel 5.5+ with `CONFIG_DEBUG_INFO_BTF=y`.
const BTF_TRACEPOINTS: &[&str] = &[
    // process.rs
    "sched_process_exec",
    "sched_process_exit",
    "sched_process_fork",
    // scheduler.rs
    "sched_wakeup",
    "sched_switch",
    // network.rs
    "inet_sock_set_state",
    "kfree_skb",
];

/// Table of every kprobe program. Each row is `(program_name, kernel_symbol)`.
const KPROBES: &[(&str, &str)] = &[
    // memory.rs
    ("handle_mm_fault", "handle_mm_fault"),
    ("oom_kill_process", "oom_kill_process"),
    // process.rs - captures `long code` before sched_process_exit fires.
    ("do_exit", "do_exit"),
    // fileio.rs - per-pid byte counters.
    ("vfs_read", "vfs_read"),
    ("vfs_write", "vfs_write"),
];

/// Names of ring buffer maps we expect the daemon to drain.
const RINGBUFS: &[&str] = &["PROCESS_EVENTS", "NET_EVENTS", "SECURITY_EVENTS"];

/// Table of every cgroup_skb program. Each row is
/// `(program_name, "ingress" | "egress")`. Attached to the cgroup v2
/// root at `/sys/fs/cgroup` at load time.
const CGROUP_SKB_PROGS: &[(&str, &str)] = &[
    // netproc.rs
    ("cgroup_skb_ingress", "ingress"),
    ("cgroup_skb_egress", "egress"),
];

/// Path of the cgroup v2 root. On modern systemd distributions this is
/// always the single unified hierarchy at `/sys/fs/cgroup`. If the
/// file can't be opened (cgroup v1, unusual chroot) we log and skip
/// the attach; the rest of the daemon continues without cgroup
/// bandwidth accounting.
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// Summary of what `load()` successfully attached. Reported via `/health`.
#[derive(Default, Clone)]
pub struct LoadSummary {
    pub programs: Vec<&'static str>,
    pub maps: Vec<&'static str>,
}

/// Guard type returned from `load()`. Owning `Ebpf` keeps the programs
/// attached. The `summary` is cloned out for the HTTP API.
pub struct LoadedEbpf {
    #[cfg(feature = "ebpf")]
    _ebpf: aya::Ebpf,
    pub summary: LoadSummary,
}

#[cfg(not(feature = "ebpf"))]
pub fn load(
    _shared: crate::metrics::SharedSnapshot,
    _bus: crate::events::EventBus,
    _time_base: crate::time_base::TimeBase,
    _bw_window: crate::bandwidth::SharedBandwidthWindow,
) -> Result<LoadedEbpf> {
    bail!(
        "agl-health-daemon was built without the `ebpf` feature; \
         rebuild with `--features ebpf` (requires nightly + bpf-linker)"
    );
}

#[cfg(feature = "ebpf")]
pub fn load(
    shared: crate::metrics::SharedSnapshot,
    bus: crate::events::EventBus,
    time_base: crate::time_base::TimeBase,
    bw_window: crate::bandwidth::SharedBandwidthWindow,
) -> Result<LoadedEbpf> {
    use aya::{
        maps::RingBuf,
        programs::{BtfTracePoint, KProbe, TracePoint},
        Btf, Ebpf,
    };
    use std::convert::TryInto;
    use tokio::io::unix::AsyncFd;
    use tracing::{debug, info, warn};

    if EBPF_OBJ.is_empty() {
        bail!("eBPF object is empty - build.rs did not produce stage 1 output");
    }

    let mut ebpf =
        Ebpf::load(EBPF_OBJ).context("failed to parse the embedded eBPF ELF object")?;

    // Load the host kernel's BTF for btf_tracepoint programs.
    let btf = Btf::from_sys_fs().context("failed to load kernel BTF from /sys/kernel/btf/vmlinux")?;

    let mut summary = LoadSummary::default();

    for &(name, category, event) in TRACEPOINTS {
        match ebpf.program_mut(name) {
            Some(prog) => {
                let tp: &mut TracePoint = match prog.try_into() {
                    Ok(tp) => tp,
                    Err(e) => {
                        warn!(program = name, error = %e, "not a tracepoint program");
                        continue;
                    }
                };
                if let Err(e) = tp.load() {
                    warn!(program = name, error = %e, "tracepoint load failed");
                    continue;
                }
                if let Err(e) = tp.attach(category, event) {
                    warn!(
                        program = name,
                        %category, %event, error = %e,
                        "tracepoint attach failed"
                    );
                    continue;
                }
                info!(program = name, %category, %event, "tracepoint attached");
                summary.programs.push(name);
            }
            None => warn!(program = name, "tracepoint program not present in object"),
        }
    }

    for &name in BTF_TRACEPOINTS {
        match ebpf.program_mut(name) {
            Some(prog) => {
                let btp: &mut BtfTracePoint = match prog.try_into() {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(program = name, error = %e, "not a btf_tracepoint program");
                        continue;
                    }
                };
                if let Err(e) = btp.load(name, &btf) {
                    warn!(program = name, error = %e, "btf_tracepoint load failed");
                    continue;
                }
                if let Err(e) = btp.attach() {
                    warn!(program = name, error = %e, "btf_tracepoint attach failed");
                    continue;
                }
                info!(program = name, "btf_tracepoint attached");
                summary.programs.push(name);
            }
            None => warn!(program = name, "btf_tracepoint program not present in object"),
        }
    }

    for &(name, symbol) in KPROBES {
        match ebpf.program_mut(name) {
            Some(prog) => {
                let kp: &mut KProbe = match prog.try_into() {
                    Ok(kp) => kp,
                    Err(e) => {
                        warn!(program = name, error = %e, "not a kprobe program");
                        continue;
                    }
                };
                if let Err(e) = kp.load() {
                    warn!(program = name, error = %e, "kprobe load failed");
                    continue;
                }
                if let Err(e) = kp.attach(symbol, 0) {
                    warn!(program = name, %symbol, error = %e, "kprobe attach failed");
                    continue;
                }
                info!(program = name, %symbol, "kprobe attached");
                summary.programs.push(name);
            }
            None => warn!(program = name, "kprobe program not present in object"),
        }
    }

    // Attach cgroup_skb programs to the cgroup v2 root.
    //
    // If the filesystem isn't cgroup v2, if the path doesn't exist,
    // or if the kernel lacks `CONFIG_CGROUP_BPF`, we degrade
    // gracefully: the rest of the eBPF pipeline still works, but the
    // /metrics/network/cgroup endpoint returns the empty array.
    attach_cgroup_skb(&mut ebpf, &mut summary);

    // Take each ring buffer map out of the Ebpf struct and spawn a
    // type-specific drain task. Taking is necessary because RingBuf<_>
    // and the async task both want owned access to the map's fd.
    for &name in RINGBUFS {
        match ebpf.take_map(name) {
            Some(map) => {
                let ring: RingBuf<_> = match map.try_into() {
                    Ok(rb) => rb,
                    Err(e) => {
                        warn!(map = name, error = %e, "map is not a ring buffer");
                        continue;
                    }
                };
                let async_fd = match AsyncFd::new(ring) {
                    Ok(fd) => fd,
                    Err(e) => {
                        warn!(map = name, error = %e, "AsyncFd::new failed");
                        continue;
                    }
                };
                summary.maps.push(name);
                match name {
                    "PROCESS_EVENTS" => {
                        tokio::spawn(drain_process_ring(async_fd, bus.clone(), time_base));
                    }
                    "NET_EVENTS" => {
                        tokio::spawn(drain_net_ring(async_fd, bus.clone(), time_base));
                    }
                    "SECURITY_EVENTS" => {
                        tokio::spawn(drain_security_ring(async_fd, bus.clone(), time_base));
                    }
                    other => {
                        warn!(map = other, "no drainer registered for this ring buffer");
                        continue;
                    }
                }
                info!(map = name, "ring buffer drain task spawned");
            }
            None => warn!(map = name, "ring buffer map not present in object"),
        }
    }

    // Take the polled maps (aggregator inputs) out of the Ebpf struct and
    // hand them to the aggregator task. Partial success is tolerated: if
    // any required map is missing we skip the aggregator entirely so the
    // rest of the daemon still runs.
    match take_polled_maps(&mut ebpf) {
        Ok(polled) => {
            crate::aggregator::start(polled, shared, time_base, bw_window);
            info!("aggregator task spawned");
            summary.maps.extend([
                "SCHED_HISTOGRAM",
                "NET_IFACE_STATS",
                "TCP_STATE",
                "MEMORY_STATS",
                "BLOCK_STATS",
                "PROCESS_STATS",
                "CPU_STATS",
                "SECURITY_COUNTS",
                "NET_CGROUP_STATS",
            ]);
        }
        Err(e) => warn!(error = %e, "aggregator not started - polled maps unavailable"),
    }

    debug!(
        programs_attached = summary.programs.len(),
        maps_opened = summary.maps.len(),
        "eBPF load complete"
    );

    Ok(LoadedEbpf {
        _ebpf: ebpf,
        summary,
    })
}

/// Attach every `cgroup_skb` program in `CGROUP_SKB_PROGS` to the
/// cgroup v2 root. Per-program failures are warn-logged so a partially
/// successful load (e.g. ingress attached but egress rejected by a
/// quirky kernel) still counts.
#[cfg(feature = "ebpf")]
fn attach_cgroup_skb(ebpf: &mut aya::Ebpf, summary: &mut LoadSummary) {
    use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType};
    use std::convert::TryInto;
    use std::fs::File;
    use tracing::{info, warn};

    let cgroup = match File::open(CGROUP_V2_ROOT) {
        Ok(f) => f,
        Err(e) => {
            warn!(path = CGROUP_V2_ROOT, error = %e, "cgroup v2 root not accessible - cgroup_skb programs skipped");
            return;
        }
    };

    for &(name, direction) in CGROUP_SKB_PROGS {
        let attach_type = match direction {
            "ingress" => CgroupSkbAttachType::Ingress,
            "egress" => CgroupSkbAttachType::Egress,
            other => {
                warn!(program = name, direction = other, "unknown cgroup_skb direction");
                continue;
            }
        };

        let Some(prog) = ebpf.program_mut(name) else {
            warn!(program = name, "cgroup_skb program not present in object");
            continue;
        };
        let cgskb: &mut CgroupSkb = match prog.try_into() {
            Ok(p) => p,
            Err(e) => {
                warn!(program = name, error = %e, "not a cgroup_skb program");
                continue;
            }
        };
        if let Err(e) = cgskb.load() {
            warn!(program = name, error = %e, "cgroup_skb load failed");
            continue;
        }
        if let Err(e) = cgskb.attach(&cgroup, attach_type, CgroupAttachMode::AllowMultiple) {
            warn!(program = name, %direction, error = %e, "cgroup_skb attach failed");
            continue;
        }
        info!(program = name, %direction, "cgroup_skb attached");
        summary.programs.push(name);
    }
}

#[cfg(feature = "ebpf")]
fn take_polled_maps(ebpf: &mut aya::Ebpf) -> Result<crate::aggregator::PolledMaps> {
    use crate::aggregator::{
        PodBlockStats, PodCgroupNetBytes, PodCpuStats, PodMemorySnapshot, PodNetIfaceStats,
        PodProcessStats, PodSchedHistogram, PodSecurityEventCounts, PodTcpStateSnapshot,
        PolledMaps,
    };
    use aya::maps::{HashMap as AyaHash, PerCpuArray};
    use std::convert::TryInto;

    fn take_array<P: aya::Pod>(
        ebpf: &mut aya::Ebpf,
        name: &'static str,
    ) -> Result<PerCpuArray<aya::maps::MapData, P>> {
        let map = ebpf
            .take_map(name)
            .ok_or_else(|| anyhow::anyhow!("map not found: {name}"))?;
        let arr: PerCpuArray<_, P> = map
            .try_into()
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
        Ok(arr)
    }

    let sched = take_array::<PodSchedHistogram>(ebpf, "SCHED_HISTOGRAM")?;
    let net_iface = take_array::<PodNetIfaceStats>(ebpf, "NET_IFACE_STATS")?;
    let tcp_state = take_array::<PodTcpStateSnapshot>(ebpf, "TCP_STATE")?;
    let memory = take_array::<PodMemorySnapshot>(ebpf, "MEMORY_STATS")?;
    let cpu = take_array::<PodCpuStats>(ebpf, "CPU_STATS")?;
    let security = take_array::<PodSecurityEventCounts>(ebpf, "SECURITY_COUNTS")?;

    fn take_hash<K: aya::Pod, V: aya::Pod>(
        ebpf: &mut aya::Ebpf,
        name: &'static str,
    ) -> Result<AyaHash<aya::maps::MapData, K, V>> {
        let map = ebpf
            .take_map(name)
            .ok_or_else(|| anyhow::anyhow!("map not found: {name}"))?;
        let h: AyaHash<_, K, V> = map
            .try_into()
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
        Ok(h)
    }

    let block = take_hash::<u32, PodBlockStats>(ebpf, "BLOCK_STATS")?;
    let process = take_hash::<u32, PodProcessStats>(ebpf, "PROCESS_STATS")?;
    let net_cgroup = take_hash::<u64, PodCgroupNetBytes>(ebpf, "NET_CGROUP_STATS")?;

    Ok(PolledMaps {
        sched,
        net_iface,
        tcp_state,
        memory,
        block,
        process,
        cpu,
        security,
        net_cgroup,
    })
}

/// Drain the `PROCESS_EVENTS` ring. Each item is a `ProcessEvent` struct
/// the kernel wrote directly into ring memory via `RingBuf::reserve`.
/// We `read_unaligned` rather than relying on aya's alignment contract
/// because rust UB rules around repr(C) POD are strictest here, and the
/// kernel doesn't give stronger alignment than the map entry header
/// forces (8 bytes).
#[cfg(feature = "ebpf")]
async fn drain_process_ring(
    mut async_fd: tokio::io::unix::AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    bus: crate::events::EventBus,
    time_base: crate::time_base::TimeBase,
) {
    use agl_health_common::events::ProcessEvent;
    use tracing::warn;

    const NAME: &str = "PROCESS_EVENTS";
    loop {
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                warn!(map = NAME, error = %e, "AsyncFd readable_mut failed");
                return;
            }
        };
        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < core::mem::size_of::<ProcessEvent>() {
                continue;
            }
            // SAFETY: ProcessEvent is #[repr(C)] POD. `read_unaligned`
            // produces a valid value for any byte pattern since all
            // fields are integers or fixed-length byte arrays.
            let mut ev: ProcessEvent = unsafe {
                core::ptr::read_unaligned(bytes.as_ptr() as *const ProcessEvent)
            };
            // Convert from CLOCK_MONOTONIC (BPF side) to wall-clock ns.
            ev.timestamp_ns = time_base.to_wall_ns(ev.timestamp_ns);
            // Ignore SendError: no subscribers is a normal state.
            let _ = bus.send(crate::events::WireEvent::from_process(&ev));
        }
        guard.clear_ready();
    }
}

/// Drain the `SECURITY_EVENTS` ring; same shape as the process drainer
/// but parses `SecurityEvent` records.
#[cfg(feature = "ebpf")]
async fn drain_security_ring(
    mut async_fd: tokio::io::unix::AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    bus: crate::events::EventBus,
    time_base: crate::time_base::TimeBase,
) {
    use agl_health_common::events::SecurityEvent;
    use tracing::warn;

    const NAME: &str = "SECURITY_EVENTS";
    loop {
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                warn!(map = NAME, error = %e, "AsyncFd readable_mut failed");
                return;
            }
        };
        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < core::mem::size_of::<SecurityEvent>() {
                continue;
            }
            let mut ev: SecurityEvent = unsafe {
                core::ptr::read_unaligned(bytes.as_ptr() as *const SecurityEvent)
            };
            ev.timestamp_ns = time_base.to_wall_ns(ev.timestamp_ns);
            let _ = bus.send(crate::events::WireEvent::from_security(&ev));
        }
        guard.clear_ready();
    }
}

/// Drain the `NET_EVENTS` ring; same shape as the process drainer but
/// parses `NetEvent` records.
#[cfg(feature = "ebpf")]
async fn drain_net_ring(
    mut async_fd: tokio::io::unix::AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    bus: crate::events::EventBus,
    time_base: crate::time_base::TimeBase,
) {
    use agl_health_common::events::NetEvent;
    use tracing::warn;

    const NAME: &str = "NET_EVENTS";
    loop {
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                warn!(map = NAME, error = %e, "AsyncFd readable_mut failed");
                return;
            }
        };
        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < core::mem::size_of::<NetEvent>() {
                continue;
            }
            let mut ev: NetEvent = unsafe {
                core::ptr::read_unaligned(bytes.as_ptr() as *const NetEvent)
            };
            ev.timestamp_ns = time_base.to_wall_ns(ev.timestamp_ns);
            let _ = bus.send(crate::events::WireEvent::from_net(&ev));
        }
        guard.clear_ready();
    }
}
