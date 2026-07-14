// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Network probes.
//!
//! Mixed approach: `netif_receive_skb` and `net_dev_xmit` remain as
//! regular `#[tracepoint]` with named offset constants (these only
//! read `len`/`rc` from the format struct and there's no BTF arg
//! that directly gives packet length without struct access).
//!
//! `tcp_retransmit_skb` stays as tracepoint (no args needed, just
//! bump a counter).
//!
//! Default (5.5+): `inet_sock_set_state` and `kfree_skb` use
//! `#[btf_tracepoint]` — `newstate` and `reason` are direct BTF args.
//!
//! kernel-5-4: `inet_sock_set_state` and `kfree_skb` use `#[tracepoint]`
//! with raw format-struct reads. `kfree_skb` emits with drop_reason=0
//! (the field was added in 5.17) and drops the reason>=2 filter.

use core::mem;

use agl_health_common::{
    events::{NetEvent, NetEventKind},
    metrics::{NetIfaceStats, TcpStateSnapshot},
};
use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};

use crate::offsets;

// ----- map declarations -----

#[cfg(not(feature = "kernel-5-4"))]
use aya_ebpf::maps::RingBuf;
#[cfg(not(feature = "kernel-5-4"))]
#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

#[cfg(feature = "kernel-5-4")]
use aya_ebpf::maps::PerfEventArray;
#[cfg(feature = "kernel-5-4")]
#[map]
static NET_EVENTS: PerfEventArray<NetEvent> = PerfEventArray::new(0);
#[cfg(feature = "kernel-5-4")]
#[map]
static NET_EVENT_SCRATCH: PerCpuArray<NetEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NET_IFACE_STATS: PerCpuArray<NetIfaceStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static TCP_STATE: PerCpuArray<TcpStateSnapshot> = PerCpuArray::with_max_entries(1, 0);

/// `net:netif_receive_skb` — regular tracepoint (len from format).
#[tracepoint]
pub fn netif_receive_skb(ctx: TracePointContext) -> u32 {
    let len: u32 = match unsafe { ctx.read_at::<u32>(offsets::NETIF_RECEIVE_SKB_LEN) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let Some(stats) = NET_IFACE_STATS.get_ptr_mut(0) else { return 1 };
    unsafe {
        (*stats).rx_bytes = (*stats).rx_bytes.wrapping_add(len as u64);
        (*stats).rx_packets = (*stats).rx_packets.wrapping_add(1);
    }
    0
}

/// `net:net_dev_xmit` — regular tracepoint.
#[tracepoint]
pub fn net_dev_xmit(ctx: TracePointContext) -> u32 {
    let len: u32 = match unsafe { ctx.read_at::<u32>(offsets::NET_DEV_XMIT_LEN) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let rc: i32 = unsafe { ctx.read_at::<i32>(offsets::NET_DEV_XMIT_RC) }.unwrap_or(0);
    let Some(stats) = NET_IFACE_STATS.get_ptr_mut(0) else { return 1 };
    unsafe {
        if rc == 0 {
            (*stats).tx_bytes = (*stats).tx_bytes.wrapping_add(len as u64);
            (*stats).tx_packets = (*stats).tx_packets.wrapping_add(1);
        } else {
            (*stats).tx_errors = (*stats).tx_errors.wrapping_add(1);
        }
    }
    0
}

/// `tcp:tcp_retransmit_skb` — just bump a counter.
#[tracepoint]
pub fn tcp_retransmit_skb(_ctx: TracePointContext) -> u32 {
    let Some(tcp) = TCP_STATE.get_ptr_mut(0) else { return 1 };
    unsafe {
        (*tcp).retransmits = (*tcp).retransmits.wrapping_add(1);
    }
    0
}

// ----- inet_sock_set_state -----

/// `inet_sock_set_state` — 5.5+ path (btf_tracepoint).
///
/// `newstate` is arg(2), eliminating the format offset entirely.
#[cfg(not(feature = "kernel-5-4"))]
use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};

#[cfg(not(feature = "kernel-5-4"))]
#[btf_tracepoint(function = "inet_sock_set_state")]
pub fn inet_sock_set_state(ctx: BtfTracePointContext) -> u32 {
    let newstate: i32 = unsafe { ctx.arg(2) };
    update_tcp_state(newstate);
    0
}

/// `inet_sock_set_state` — 5.4 path (tracepoint with raw args).
///
/// /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
#[cfg(feature = "kernel-5-4")]
#[repr(C)]
struct InetSockSetStateArgs {
    _pad: [u8; 8],
    skaddr: u64,
    oldstate: i32,
    newstate: i32,
    sport: u16,
    dport: u16,
    family: u16,
    protocol: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
    saddr_v6: [u8; 16],
    daddr_v6: [u8; 16],
}

#[cfg(feature = "kernel-5-4")]
#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    let args = match unsafe { ctx.read_at::<InetSockSetStateArgs>(0) } {
        Ok(a) => a,
        Err(_) => return 1,
    };
    update_tcp_state(args.newstate);
    0
}

#[inline(always)]
fn update_tcp_state(newstate: i32) {
    let Some(tcp) = TCP_STATE.get_ptr_mut(0) else { return };
    unsafe {
        match newstate {
            1 => (*tcp).established = (*tcp).established.wrapping_add(1),
            2 => (*tcp).syn_sent = (*tcp).syn_sent.wrapping_add(1),
            3 => (*tcp).syn_recv = (*tcp).syn_recv.wrapping_add(1),
            4 => (*tcp).fin_wait1 = (*tcp).fin_wait1.wrapping_add(1),
            5 => (*tcp).fin_wait2 = (*tcp).fin_wait2.wrapping_add(1),
            6 => (*tcp).time_wait = (*tcp).time_wait.wrapping_add(1),
            8 => (*tcp).close_wait = (*tcp).close_wait.wrapping_add(1),
            10 => (*tcp).listen = (*tcp).listen.wrapping_add(1),
            _ => {}
        }
    }
}

// ----- kfree_skb -----

/// `kfree_skb` — 5.5+ path (btf_tracepoint).
///
/// `reason` is arg(2). Only real drops (reason >= 2) are reported.
#[cfg(not(feature = "kernel-5-4"))]
#[btf_tracepoint(function = "kfree_skb")]
pub fn kfree_skb(ctx: BtfTracePointContext) -> u32 {
    let reason: u32 = unsafe { ctx.arg(2) };
    if reason < 2 {
        return 0;
    }
    emit_skb_drop_55(reason);
    0
}

#[cfg(not(feature = "kernel-5-4"))]
fn emit_skb_drop_55(reason: u32) {
    let Some(mut entry) = NET_EVENTS.reserve::<NetEvent>(0) else {
        crate::stats::drop_network();
        return;
    };
    let ptr = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, mem::size_of::<NetEvent>());
        (*ptr).kind = NetEventKind::SkbDrop as u32;
        (*ptr).drop_reason = reason as u16;
        (*ptr).timestamp_ns = bpf_ktime_get_ns();
    }
    entry.submit(0);
}

/// `kfree_skb` — 5.4 path (tracepoint).
///
/// `drop_reason` was added in 5.17 — not present in the 5.4 format.
/// Emit with drop_reason=0; the reason>=2 filter is omitted because
/// on 5.4 all kfree_skb calls are genuine drops (no NOT_SPECIFIED).
#[cfg(feature = "kernel-5-4")]
#[tracepoint]
pub fn kfree_skb(ctx: TracePointContext) -> u32 {
    let Some(scratch) = NET_EVENT_SCRATCH.get_ptr_mut(0) else {
        crate::stats::drop_network();
        return 1;
    };
    unsafe {
        core::ptr::write_bytes(scratch as *mut u8, 0, mem::size_of::<NetEvent>());
        (*scratch).kind = NetEventKind::SkbDrop as u32;
        (*scratch).drop_reason = 0;
        (*scratch).timestamp_ns = bpf_ktime_get_ns();
    }
    NET_EVENTS.output(&ctx, unsafe { &*scratch }, 0);
    0
}
