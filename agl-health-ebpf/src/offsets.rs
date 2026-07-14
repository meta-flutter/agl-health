// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

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

// block:block_rq_complete — switched to btf_tracepoint in block.rs.
// Format offsets no longer needed; args come from BTF directly.

// ---- raw_syscalls:sys_enter ----
// field:long id;       offset:8;  size:8
// field:long args[6];  offset:16; size:48
pub const RAW_SYSCALL_NR: usize = 8;
pub const SYSCALL_ARG0: usize = 16;
pub const SYSCALL_ARG1: usize = 24;
