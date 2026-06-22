// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared types between the `agl-health-ebpf` kernel programs and the
//! `agl-health-daemon` userspace binary.
//!
//! This crate is `#![no_std]` and contains only plain-old-data (`#[repr(C)]`,
//! fixed-size arrays, integer primitives). It must compile cleanly for the
//! `bpfel-unknown-none` target, so it may not use `alloc`, `std`, or any
//! OS-dependent types.
//!
//! The userspace side should enable the `user` feature to get `serde`
//! derives for JSON serialization in the REST/WS API layer.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod events;
pub mod metrics;
pub mod metrics_v3;

/// Fixed-length `comm` field (TASK_COMM_LEN in the kernel).
pub const COMM_LEN: usize = 16;

/// Fixed-length filename field used in process/file events.
pub const FILENAME_LEN: usize = 256;

/// Number of buckets in the scheduler latency histogram.
/// Buckets are log-spaced: <10us, <100us, <1ms, <10ms, <100ms, <1s, <10s, >=10s.
pub const SCHED_HIST_BUCKETS: usize = 8;

// --------- v3 shm layout caps ---------
// See `metrics_v3` and the project memory note "agl-health v3 migration decisions".
// If a system exceeds one of these caps the *top-N by CPU time* (or equivalent
// sort key) wins and the rest are invisible to the shm / Flutter path.
pub const V3_MAX_CPU_CORES: usize = 16;
pub const V3_MAX_PROCESSES: usize = 512;
pub const V3_MAX_BLOCK_DEVS: usize = 16;
pub const V3_MAX_NET_IFACES: usize = 8;
