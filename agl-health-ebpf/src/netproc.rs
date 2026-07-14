// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-process/cgroup network byte accounting.
//!
//! ### Default path (kernel 5.5+, `cgroup_skb`)
//!
//! Two `cgroup_skb` programs attached to the cgroup v2 root classify
//! each packet as internet vs local by inspecting the IP header, then
//! accumulate byte/packet counters into `NET_CGROUP_STATS` keyed by
//! cgroup id (`bpf_get_current_cgroup_id`).
//!
//! ### kernel-5-4 path (`tcp_sendmsg` / `tcp_cleanup_rbuf` kprobes)
//!
//! `bpf_get_current_cgroup_id` requires `CONFIG_CGROUP_BPF=y` which is
//! absent on the target BSP kernel. Instead, kprobes on `tcp_sendmsg`
//! (TX) and `tcp_cleanup_rbuf` (RX) are used — both run synchronously
//! in the calling process's context so `bpf_get_current_pid_tgid` is
//! reliable. Counters are accumulated into `NET_CGROUP_STATS` keyed by
//! PID (cast to u64) so the rest of the aggregator/API pipeline is
//! unchanged. Internet vs local classification is available for IPv4 TCP
//! via `sk->__sk_common.skc_daddr`. IPv6 internet classification is not
//! implemented on this path (skc_v6_daddr offset is config-dependent).
//! UDP is not accounted for because UDP RX is delivered in softirq
//! context where the PID is unreliable.

use agl_health_common::metrics::CgroupNetBytes;
use aya_ebpf::{macros::map, maps::HashMap};

#[map]
pub static NET_CGROUP_STATS: HashMap<u64, CgroupNetBytes> =
    HashMap::<u64, CgroupNetBytes>::with_max_entries(1024, 0);

// ── Default path: cgroup_skb ─────────────────────────────────────────────────

#[cfg(not(feature = "kernel-5-4"))]
use aya_ebpf::{macros::cgroup_skb, programs::SkBuffContext};

#[cfg(not(feature = "kernel-5-4"))]
#[cgroup_skb]
pub fn cgroup_skb_ingress(ctx: SkBuffContext) -> i32 {
    account_cgroup(&ctx, Direction::Rx);
    1
}

#[cfg(not(feature = "kernel-5-4"))]
#[cgroup_skb]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    account_cgroup(&ctx, Direction::Tx);
    1
}

#[cfg(not(feature = "kernel-5-4"))]
#[derive(Copy, Clone)]
enum Direction {
    Rx,
    Tx,
}

#[cfg(not(feature = "kernel-5-4"))]
fn account_cgroup(ctx: &SkBuffContext, dir: Direction) {
    use aya_ebpf::helpers::bpf_get_current_cgroup_id;

    let cgid = unsafe { bpf_get_current_cgroup_id() };
    if cgid == 0 {
        return;
    }
    let len = ctx.len() as u64;
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

// ── kernel-5-4 path: tcp_sendmsg / tcp_cleanup_rbuf kprobes ─────────────────

#[cfg(feature = "kernel-5-4")]
use aya_ebpf::{macros::kprobe, programs::ProbeContext};

/// Minimal overlay for `struct sock_common` to read family and IPv4 addresses.
/// `__sk_common` is the first field of `struct sock`, so `sock *` and
/// `sock_common *` are interchangeable in terms of pointer value.
///
/// Layout (stable since 3.x, unchanged through 5.4):
///   offset 0:  skc_daddr       (__be32, remote IPv4)
///   offset 4:  skc_rcv_saddr   (__be32, local IPv4)
///   offset 16: skc_family      (u16, AF_INET=2 / AF_INET6=10)
#[cfg(feature = "kernel-5-4")]
#[repr(C)]
struct SockCommonHead {
    skc_daddr: u32,
    skc_rcv_saddr: u32,
    _pad: [u8; 8],
    skc_family: u16,
}

/// `tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)` — arg 2 is
/// the requested byte count. Runs in process context; PID is reliable.
#[cfg(feature = "kernel-5-4")]
#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let len: u64 = match ctx.arg::<usize>(2) {
        Some(v) => v as u64,
        None => return 1,
    };
    if len == 0 {
        return 0;
    }
    let pid = (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() } >> 32) as u64;
    if pid == 0 {
        return 0;
    }
    let is_internet = classify_sock_internet(&ctx, 0);
    account_pid(pid, len, false, is_internet);
    0
}

/// `tcp_cleanup_rbuf(struct sock *sk, int copied)` — arg 1 is the number of
/// bytes consumed from the receive buffer. Only called when `copied > 0`.
/// Runs in process context; PID is reliable.
#[cfg(feature = "kernel-5-4")]
#[kprobe]
pub fn tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    let copied: i32 = match ctx.arg::<i32>(1) {
        Some(v) => v,
        None => return 1,
    };
    if copied <= 0 {
        return 0;
    }
    let pid = (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() } >> 32) as u64;
    if pid == 0 {
        return 0;
    }
    let is_internet = classify_sock_internet(&ctx, 0);
    account_pid(pid, copied as u64, true, is_internet);
    0
}

/// Read `skc_family` and the remote IPv4 address from the `struct sock *` at
/// kprobe arg `arg_idx`, then classify as internet or local.
/// Returns `false` on any read failure (conservative — no over-counting).
/// IPv6 classification is not implemented: `skc_v6_daddr` offset depends on
/// kernel config options, making it unsafe to hardcode.
#[cfg(feature = "kernel-5-4")]
#[inline(always)]
fn classify_sock_internet(ctx: &ProbeContext, arg_idx: u32) -> bool {
    use aya_ebpf::helpers::bpf_probe_read_kernel;
    const AF_INET: u16 = 2;

    let sk: *const SockCommonHead = match ctx.arg::<*const SockCommonHead>(arg_idx as usize) {
        Some(p) if !p.is_null() => p,
        _ => return false,
    };
    let head = match unsafe { bpf_probe_read_kernel(sk) } {
        Ok(h) => h,
        Err(_) => return false,
    };
    if head.skc_family != AF_INET {
        // Non-IPv4 (e.g. IPv6, Unix): conservatively treat as non-internet.
        return false;
    }
    // skc_daddr is __be32 (network/big-endian byte order). bpf_probe_read_kernel
    // copies the raw bytes into our LE u32, so to_ne_bytes() recovers the
    // original octet order (e.g. 192.168.1.1 → [C0, A8, 01, 01]).
    // to_be_bytes() would reverse them and misclassify private addresses.
    let ip = head.skc_daddr.to_ne_bytes();
    !is_ipv4_local(ip)
}

/// Update or insert the per-PID counters.
/// `cgroup_id` is set to the PID so the aggregator/API layer is unchanged.
#[cfg(feature = "kernel-5-4")]
#[inline(always)]
fn account_pid(pid: u64, len: u64, is_rx: bool, is_internet: bool) {
    if let Some(stats) = NET_CGROUP_STATS.get_ptr_mut(&pid) {
        unsafe {
            if is_rx {
                (*stats).rx_bytes = (*stats).rx_bytes.wrapping_add(len);
                (*stats).rx_packets = (*stats).rx_packets.wrapping_add(1);
                if is_internet {
                    (*stats).rx_internet_bytes =
                        (*stats).rx_internet_bytes.wrapping_add(len);
                }
            } else {
                (*stats).tx_bytes = (*stats).tx_bytes.wrapping_add(len);
                (*stats).tx_packets = (*stats).tx_packets.wrapping_add(1);
                if is_internet {
                    (*stats).tx_internet_bytes =
                        (*stats).tx_internet_bytes.wrapping_add(len);
                }
            }
        }
        return;
    }
    let mut fresh: CgroupNetBytes = unsafe { core::mem::zeroed() };
    fresh.cgroup_id = pid;
    if is_rx {
        fresh.rx_bytes = len;
        fresh.rx_packets = 1;
        if is_internet { fresh.rx_internet_bytes = len; }
    } else {
        fresh.tx_bytes = len;
        fresh.tx_packets = 1;
        if is_internet { fresh.tx_internet_bytes = len; }
    }
    let _ = NET_CGROUP_STATS.insert(&pid, &fresh, 0);
}

// ── IP classification (cgroup_skb path only) ─────────────────────────────────

#[cfg(not(feature = "kernel-5-4"))]
fn classify_internet(ctx: &SkBuffContext, dir: Direction) -> bool {
    let Ok(version_byte) = ctx.load::<u8>(0) else {
        return false;
    };
    match version_byte >> 4 {
        4 => classify_ipv4(ctx, dir),
        6 => classify_ipv6(ctx, dir),
        _ => false,
    }
}

#[cfg(not(feature = "kernel-5-4"))]
fn classify_ipv4(ctx: &SkBuffContext, dir: Direction) -> bool {
    let offset = match dir {
        Direction::Rx => 12usize,
        Direction::Tx => 16usize,
    };
    let Ok(ip) = ctx.load::<[u8; 4]>(offset) else {
        return false;
    };
    !is_ipv4_local(ip)
}

#[cfg(not(feature = "kernel-5-4"))]
fn classify_ipv6(ctx: &SkBuffContext, dir: Direction) -> bool {
    let offset = match dir {
        Direction::Rx => 8usize,
        Direction::Tx => 24usize,
    };
    let Ok(ip) = ctx.load::<[u8; 16]>(offset) else {
        return false;
    };
    !is_ipv6_local(ip)
}

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

#[cfg(not(feature = "kernel-5-4"))]
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
