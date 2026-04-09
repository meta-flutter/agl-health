//! Per-cgroup network byte accounting via `cgroup_skb` programs.
//!
//! Two programs are attached to the cgroup v2 root (`/sys/fs/cgroup`)
//! at load time - one for ingress, one for egress - so every packet
//! on every socket in every cgroup passes through them. Each program:
//!
//!   1. Reads `bpf_get_current_cgroup_id()` - the leaf cgroup id of
//!      the task currently running on this CPU. For egress this is
//!      the sending task's cgroup (correct). For ingress this is
//!      whatever task was running during softirq processing.
//!   2. Reads `skb.len` (total packet bytes).
//!   3. Upserts `NET_CGROUP_STATS[cgroup_id]` accumulating rx/tx
//!      bytes and packets.
//!   4. Returns 1 (allow) - we never drop packets, only observe.
//!
//! ### Caveat: ingress attribution is approximate
//!
//! For egress, `current` is the task that issued the `write()`/`sendmsg()`
//! syscall, so cgroup attribution is precise. For ingress, the kernel
//! delivers the skb to the program in softirq context where `current`
//! is often unrelated to the receiving socket's owner. In practice on
//! Linux 5.15+ with `RPS` / `RSS` enabled the packet is usually
//! processed on the receiving CPU by the ksoftirqd thread, whose
//! cgroup is the root - so ingress traffic ends up accounted to the
//! root cgroup rather than the real owner.
//!
//! Two known follow-ups, ordered by cost, tracked in project memory:
//!
//! * Walk `skb->sk` via CO-RE to retrieve the owning socket's cgroup
//!   directly. This is the "proper" fix and requires the generated
//!   `vmlinux.rs` from `cargo xtask gen-vmlinux`.
//! * Alternatively, walk `/sys/fs/cgroup` in the loader and attach a
//!   separate copy of the programs to each leaf cgroup. This gets
//!   accurate attribution for free but multiplies attach points by
//!   the number of cgroups on the system.
//!
//! Internet vs local byte classification is also deferred - the first
//! pass is raw total bytes per cgroup. Once the CO-RE infrastructure
//! is in place a follow-up will inspect the IP header in the skb and
//! filter against RFC1918 / loopback / link-local ranges.

use agl_health_common::metrics::CgroupNetBytes;
use aya_ebpf::{
    helpers::bpf_get_current_cgroup_id,
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};

/// Per-cgroup network byte accumulator. 1024 entries comfortably
/// covers typical systemd + Docker cgroup counts with headroom.
#[map]
pub static NET_CGROUP_STATS: HashMap<u64, CgroupNetBytes> =
    HashMap::<u64, CgroupNetBytes>::with_max_entries(1024, 0);

/// `cgroup_skb/ingress` - accumulate received byte count.
#[cgroup_skb]
pub fn cgroup_skb_ingress(ctx: SkBuffContext) -> i32 {
    account(&ctx, Direction::Rx);
    // 1 = allow the packet to proceed; we never drop.
    1
}

/// `cgroup_skb/egress` - accumulate transmitted byte count.
#[cgroup_skb]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    account(&ctx, Direction::Tx);
    1
}

#[derive(Copy, Clone)]
enum Direction {
    Rx,
    Tx,
}

fn account(ctx: &SkBuffContext, dir: Direction) {
    let cgid = unsafe { bpf_get_current_cgroup_id() };
    if cgid == 0 {
        return;
    }
    let len = ctx.len() as u64;

    // Fast path: entry exists. In-place update avoids a copy + insert.
    if let Some(stats) = NET_CGROUP_STATS.get_ptr_mut(&cgid) {
        // SAFETY: pointer into a HashMap slot valid for the program's
        // duration; preemption disabled while the program runs.
        unsafe {
            match dir {
                Direction::Rx => {
                    (*stats).rx_bytes = (*stats).rx_bytes.wrapping_add(len);
                    (*stats).rx_packets = (*stats).rx_packets.wrapping_add(1);
                }
                Direction::Tx => {
                    (*stats).tx_bytes = (*stats).tx_bytes.wrapping_add(len);
                    (*stats).tx_packets = (*stats).tx_packets.wrapping_add(1);
                }
            }
        }
        return;
    }

    // Slow path: first time we see this cgroup. Zero-init and apply
    // the initial sample before inserting.
    // SAFETY: CgroupNetBytes is #[repr(C)] POD of u64s; all-zero is valid.
    let mut fresh: CgroupNetBytes = unsafe { core::mem::zeroed() };
    fresh.cgroup_id = cgid;
    match dir {
        Direction::Rx => {
            fresh.rx_bytes = len;
            fresh.rx_packets = 1;
        }
        Direction::Tx => {
            fresh.tx_bytes = len;
            fresh.tx_packets = 1;
        }
    }
    let _ = NET_CGROUP_STATS.insert(&cgid, &fresh, 0);
}
