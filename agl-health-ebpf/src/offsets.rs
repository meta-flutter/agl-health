//! Named offset constants for tracepoint format fields.
//!
//! These replace the anonymous magic numbers that were previously
//! inlined at each `ctx.read_at::<T>(N)` call site. The offsets
//! come from the tracepoint format files under:
//!
//!   /sys/kernel/debug/tracing/events/<category>/<event>/format
//!
//! Tracepoint format offsets are explicitly designed as a stable ABI
//! and change extremely rarely. They are only used by programs that
//! remain as regular `#[tracepoint]` — programs switched to
//! `#[btf_tracepoint]` use `ctx.arg::<T>(n)` and don't need format
//! offsets at all.
//!
//! If you add a new tracepoint program, add its offsets here with a
//! comment referencing the format file.

// ---- net:netif_receive_skb ----
// field:unsigned int len;  offset:16; size:4
pub const NETIF_RECEIVE_SKB_LEN: usize = 16;

// ---- net:net_dev_xmit ----
// field:unsigned int len;  offset:16; size:4
// field:int rc;            offset:20; size:4
pub const NET_DEV_XMIT_LEN: usize = 16;
pub const NET_DEV_XMIT_RC: usize = 20;

// ---- block:block_rq_complete ----
// field:dev_t dev;           offset:8;  size:4
// field:unsigned int bytes;  offset:28; size:4
// field:char rwbs[8];        offset:32; size:8
pub const BLOCK_RQ_COMPLETE_DEV: usize = 8;
pub const BLOCK_RQ_COMPLETE_BYTES: usize = 28;
pub const BLOCK_RQ_COMPLETE_RWBS: usize = 32;

// ---- syscalls:sys_enter_* (common for all sys_enter tracepoints) ----
// Args start at offset 16 as 8-byte values after the common header
// (common_type 2B + common_flags 1B + common_preempt_count 1B +
// common_pid 4B = 8B common + __syscall_nr 4B + 4B pad = 16B).
pub const SYSCALL_ARG0: usize = 16;
pub const SYSCALL_ARG1: usize = 24;
