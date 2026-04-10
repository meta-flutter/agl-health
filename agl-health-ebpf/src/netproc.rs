//! Per-cgroup network byte accounting via `cgroup_skb` programs
//! with internet vs local IP classification.
//!
//! Attached to the cgroup v2 root at `/sys/fs/cgroup`. Each packet
//! is classified by inspecting the IP header:
//!
//!   * **Egress**: destination IP checked. If not RFC1918/loopback/
//!     link-local → counted as internet.
//!   * **Ingress**: source IP checked. Same classification.
//!
//! Both total and internet-only byte counters are maintained per
//! cgroup_id in `NET_CGROUP_STATS`.
//!
//! ### IP ranges classified as "local"
//!
//! IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
//!       169.254.0.0/16, 0.0.0.0/8
//! IPv6: ::1, fe80::/10, fc00::/7
//!
//! Everything else is "internet".

use agl_health_common::metrics::CgroupNetBytes;
use aya_ebpf::{
    helpers::bpf_get_current_cgroup_id,
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};

#[map]
pub static NET_CGROUP_STATS: HashMap<u64, CgroupNetBytes> =
    HashMap::<u64, CgroupNetBytes>::with_max_entries(1024, 0);

#[cgroup_skb]
pub fn cgroup_skb_ingress(ctx: SkBuffContext) -> i32 {
    account(&ctx, Direction::Rx);
    1
}

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

    // Classify the relevant IP address as internet vs local.
    // For egress: check destination. For ingress: check source.
    let is_internet = classify_internet(ctx, dir);

    if let Some(stats) = NET_CGROUP_STATS.get_ptr_mut(&cgid) {
        unsafe {
            match dir {
                Direction::Rx => {
                    (*stats).rx_bytes = (*stats).rx_bytes.wrapping_add(len);
                    (*stats).rx_packets = (*stats).rx_packets.wrapping_add(1);
                    if is_internet {
                        (*stats).rx_internet_bytes =
                            (*stats).rx_internet_bytes.wrapping_add(len);
                    }
                }
                Direction::Tx => {
                    (*stats).tx_bytes = (*stats).tx_bytes.wrapping_add(len);
                    (*stats).tx_packets = (*stats).tx_packets.wrapping_add(1);
                    if is_internet {
                        (*stats).tx_internet_bytes =
                            (*stats).tx_internet_bytes.wrapping_add(len);
                    }
                }
            }
        }
        return;
    }

    let mut fresh: CgroupNetBytes = unsafe { core::mem::zeroed() };
    fresh.cgroup_id = cgid;
    match dir {
        Direction::Rx => {
            fresh.rx_bytes = len;
            fresh.rx_packets = 1;
            if is_internet {
                fresh.rx_internet_bytes = len;
            }
        }
        Direction::Tx => {
            fresh.tx_bytes = len;
            fresh.tx_packets = 1;
            if is_internet {
                fresh.tx_internet_bytes = len;
            }
        }
    }
    let _ = NET_CGROUP_STATS.insert(&cgid, &fresh, 0);
}

/// Inspect the IP header to determine whether the relevant address
/// (dst for egress, src for ingress) is "internet" traffic.
///
/// Returns `true` if the address is NOT in any of the local ranges.
/// Returns `false` (local) on any read failure so we don't
/// over-count internet traffic on malformed packets.
fn classify_internet(ctx: &SkBuffContext, dir: Direction) -> bool {
    // In cgroup_skb programs, skb data starts at the network (L3)
    // header. Read the first byte to determine IP version.
    let Ok(version_byte) = ctx.load::<u8>(0) else {
        return false;
    };
    let ip_version = version_byte >> 4;

    match ip_version {
        4 => classify_ipv4(ctx, dir),
        6 => classify_ipv6(ctx, dir),
        _ => false, // Unknown protocol — treat as local.
    }
}

/// IPv4: read 4-byte address and check against local ranges.
fn classify_ipv4(ctx: &SkBuffContext, dir: Direction) -> bool {
    // IPv4 header: src @ offset 12, dst @ offset 16 (each 4 bytes).
    let offset = match dir {
        Direction::Rx => 12usize, // source address for ingress
        Direction::Tx => 16usize, // destination address for egress
    };
    // Read as [u8; 4] to avoid endian confusion. The IP address
    // octets are in network order, which is byte order in memory.
    let Ok(ip) = ctx.load::<[u8; 4]>(offset) else {
        return false;
    };
    !is_ipv4_local(ip)
}

/// IPv6: read 16-byte address and check against local ranges.
fn classify_ipv6(ctx: &SkBuffContext, dir: Direction) -> bool {
    // IPv6 header: src @ offset 8, dst @ offset 24 (each 16 bytes).
    let offset = match dir {
        Direction::Rx => 8usize,
        Direction::Tx => 24usize,
    };
    let Ok(ip) = ctx.load::<[u8; 16]>(offset) else {
        return false;
    };
    !is_ipv6_local(ip)
}

/// Check if an IPv4 address falls into a "local" range.
#[inline(always)]
fn is_ipv4_local(ip: [u8; 4]) -> bool {
    let a = ip[0];
    let b = ip[1];

    a == 10                          // 10.0.0.0/8
    || (a == 172 && (b & 0xF0) == 16) // 172.16.0.0/12
    || (a == 192 && b == 168)        // 192.168.0.0/16
    || a == 127                      // 127.0.0.0/8 (loopback)
    || (a == 169 && b == 254)        // 169.254.0.0/16 (link-local)
    || a == 0                        // 0.0.0.0/8 (unspecified)
    || a == 255                      // 255.255.255.255 (broadcast)
}

/// Check if an IPv6 address falls into a "local" range.
#[inline(always)]
fn is_ipv6_local(ip: [u8; 16]) -> bool {
    // ::1 (loopback)
    let is_loopback = ip[0..15] == [0u8; 15] && ip[15] == 1;
    // fe80::/10 (link-local)
    let is_link_local = ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80;
    // fc00::/7 (unique local address, includes fd00::/8)
    let is_ula = (ip[0] & 0xfe) == 0xfc;
    // :: (unspecified)
    let is_unspecified = ip == [0u8; 16];

    is_loopback || is_link_local || is_ula || is_unspecified
}
