//! Network probes.
//!
//! Layered across four tracepoints:
//!
//! * `net:netif_receive_skb` and `net:net_dev_xmit` are per-packet and update
//!   a single global `NetIfaceStats` PerCpuArray. Per-interface indexing
//!   (currently `iface_idx = 0`) is deferred: the tracepoint format exposes
//!   the device name as a `__data_loc` field, which needs a small helper to
//!   resolve the ifindex — TODO in a later pass.
//!
//! * `tcp:tcp_retransmit_skb` bumps `TcpStateSnapshot.retransmits`.
//!
//! * `sock:inet_sock_set_state` bumps the counter corresponding to the
//!   *new* state. These fields are transition counters, not snapshots of
//!   currently-held state - userspace derives rates from deltas.
//!
//! * `skb:kfree_skb` filters on `drop_reason >= 2` (reason 1 is
//!   `NOT_SPECIFIED` which fires on every normal free) and emits a
//!   `NetEvent::SkbDrop` on the `NET_EVENTS` ring buffer for userspace to
//!   consume as a discrete event.

use core::mem;

use agl_health_common::{
    events::{NetEvent, NetEventKind},
    metrics::{NetIfaceStats, TcpStateSnapshot},
};
use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};

/// Ring buffer for low-frequency network events (drops, resets, state
/// transitions worth surfacing individually).
#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

/// Global per-CPU accumulator for interface byte/packet counters. Slot 0
/// currently aggregates across all interfaces; per-iface indexing is a TODO.
#[map]
static NET_IFACE_STATS: PerCpuArray<NetIfaceStats> = PerCpuArray::with_max_entries(1, 0);

/// Global per-CPU accumulator for TCP state-transition counters and
/// retransmission totals.
#[map]
static TCP_STATE: PerCpuArray<TcpStateSnapshot> = PerCpuArray::with_max_entries(1, 0);

/// `net:netif_receive_skb` - every packet handed up from the driver.
///
/// Format: field `unsigned int len` at offset 16.
#[tracepoint]
pub fn netif_receive_skb(ctx: TracePointContext) -> u32 {
    let len: u32 = match unsafe { ctx.read_at::<u32>(16) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let Some(stats) = NET_IFACE_STATS.get_ptr_mut(0) else {
        return 1;
    };
    // SAFETY: valid pointer into this CPU's slot; preemption is disabled
    // while a BPF program runs.
    unsafe {
        (*stats).rx_bytes = (*stats).rx_bytes.wrapping_add(len as u64);
        (*stats).rx_packets = (*stats).rx_packets.wrapping_add(1);
    }
    0
}

/// `net:net_dev_xmit` - every packet handed down to the driver.
///
/// Format: `unsigned int len` at offset 16, `int rc` at offset 20.
#[tracepoint]
pub fn net_dev_xmit(ctx: TracePointContext) -> u32 {
    let len: u32 = match unsafe { ctx.read_at::<u32>(16) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let rc: i32 = unsafe { ctx.read_at::<i32>(20) }.unwrap_or(0);
    let Some(stats) = NET_IFACE_STATS.get_ptr_mut(0) else {
        return 1;
    };
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

/// `tcp:tcp_retransmit_skb` - kernel is retransmitting a segment.
#[tracepoint]
pub fn tcp_retransmit_skb(_ctx: TracePointContext) -> u32 {
    let Some(tcp) = TCP_STATE.get_ptr_mut(0) else {
        return 1;
    };
    unsafe {
        (*tcp).retransmits = (*tcp).retransmits.wrapping_add(1);
    }
    0
}

/// `sock:inet_sock_set_state` - TCP socket transitions between states.
///
/// Format: `int oldstate` at offset 16, `int newstate` at offset 20.
/// Kernel state enum (linux/tcp_states.h): 1=ESTABLISHED, 2=SYN_SENT,
/// 3=SYN_RECV, 4=FIN_WAIT1, 5=FIN_WAIT2, 6=TIME_WAIT, 7=CLOSE,
/// 8=CLOSE_WAIT, 10=LISTEN.
#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    let newstate: i32 = match unsafe { ctx.read_at::<i32>(20) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let Some(tcp) = TCP_STATE.get_ptr_mut(0) else {
        return 1;
    };
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

/// `skb:kfree_skb` - every freed sk_buff. The `drop_reason` field
/// distinguishes real drops (>= 2) from normal frees (reason 1 /
/// NOT_SPECIFIED). Only real drops are reported as events.
///
/// Format: `enum skb_drop_reason reason` at offset 28 (u32 on the wire).
#[tracepoint]
pub fn kfree_skb(ctx: TracePointContext) -> u32 {
    let reason: u32 = match unsafe { ctx.read_at::<u32>(28) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    if reason < 2 {
        return 0;
    }

    let Some(mut entry) = NET_EVENTS.reserve::<NetEvent>(0) else {
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
