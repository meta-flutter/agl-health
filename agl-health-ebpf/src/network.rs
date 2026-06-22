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
//! `inet_sock_set_state` and `kfree_skb` are switched to
//! `#[btf_tracepoint]` because their key arguments (`newstate`,
//! `reason`) are direct function parameters — no format offsets
//! needed at all.

use core::mem;

use agl_health_common::{
    events::{NetEvent, NetEventKind},
    metrics::{NetIfaceStats, TcpStateSnapshot},
};
use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{btf_tracepoint, map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::{BtfTracePointContext, TracePointContext},
};

use crate::offsets;

#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

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

/// `inet_sock_set_state(const struct sock *sk, int oldstate,
///                      int newstate)` — btf_tracepoint.
///
/// `newstate` is arg(2), eliminating the format offset entirely.
#[btf_tracepoint(function = "inet_sock_set_state")]
pub fn inet_sock_set_state(ctx: BtfTracePointContext) -> u32 {
    let newstate: i32 = unsafe { ctx.arg(2) };
    let Some(tcp) = TCP_STATE.get_ptr_mut(0) else { return 1 };
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
    0
}

/// `kfree_skb(struct sk_buff *skb, void *location,
///            enum skb_drop_reason reason, ...)` — btf_tracepoint.
///
/// `reason` is arg(2). Only real drops (reason >= 2) are reported.
#[btf_tracepoint(function = "kfree_skb")]
pub fn kfree_skb(ctx: BtfTracePointContext) -> u32 {
    let reason: u32 = unsafe { ctx.arg(2) };
    if reason < 2 {
        return 0;
    }
    let Some(mut entry) = NET_EVENTS.reserve::<NetEvent>(0) else {
        crate::stats::drop_network();
        return 1;
    };
    let ptr = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, mem::size_of::<NetEvent>());
        (*ptr).kind = NetEventKind::SkbDrop as u32;
        (*ptr).drop_reason = reason as u16;
        (*ptr).timestamp_ns = bpf_ktime_get_ns();
    }
    entry.submit(0);
    0
}
