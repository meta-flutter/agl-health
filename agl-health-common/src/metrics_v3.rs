// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Fixed-size, memory-mappable metric snapshot layout for the v3
//! Flutter native plugin path.
//!
//! # Why this module exists
//!
//! The v1 [`crate::metrics::MetricSnapshot`] in the sibling `metrics`
//! module uses `Vec<T>` for its per-core / per-process / per-device
//! collections, which is fine for JSON serialization but fundamentally
//! incompatible with POSIX shared memory: you cannot `mmap` a `Vec`.
//!
//! The v3 plan (`IMPLEMENTATION_PLAN_v3.docx` §3.6) replaces the
//! Flutter WebSocket/JSON path with a zero-copy shm channel. Dart
//! receives the snapshot as an `ExternalTypedData` backed directly by
//! the mmapped kernel segment. For that to work the snapshot must be:
//!
//! * `#[repr(C)]` with a stable, documented field order
//! * composed entirely of plain-old-data (integers, fixed arrays,
//!   nested `#[repr(C)]` structs)
//! * statically sized — no `Vec`, no trailing variable-length data
//! * safe to read on a different CPU than the writer, under a seqlock
//!
//! This module delivers that. It deliberately does **not** derive
//! `serde::Serialize` — the v3 shm path is binary, not JSON. The v1
//! JSON types in [`crate::metrics`] are unchanged and still flow
//! through `/metrics/*` REST endpoints for EdgeX/Prometheus/eKuiper.
//!
//! # Layout discipline
//!
//! The header occupies the first 64 bytes so the payload starts at a
//! cache-line boundary. The seqlock protocol lives entirely in the
//! header:
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!     0      8    magic              // 0x41474C5F48454C54 ("AGL_HELT")
//!     8      4    version            // currently 1
//!    12      4    _pad0
//!    16      8    sequence           // odd = write in progress
//!    24      8    timestamp_ns_wall  // nanoseconds since UNIX epoch
//!    32      4    snapshot_size      // sizeof<MetricSnapshotV3>
//!    36      4    _pad1
//!    40     24    _reserved          // for future header growth
//!    64      *    payload...
//! ```
//!
//! The reader protocol is:
//!
//! 1. Load `sequence` (acquire). If odd, retry.
//! 2. Copy the payload bytes.
//! 3. Load `sequence` again. If changed, retry.
//!
//! Because every field after the header is `#[repr(C)]` POD, the
//! "copy the payload bytes" step is a single `memcpy` — or, on the
//! Dart side, just a `Uint8List` view via `Dart_NewExternalTypedData`
//! with no copy at all (the reader is responsible for retrying if the
//! read straddles a writer update).
//!
//! # Why a hand-rolled `ShmPod` marker trait instead of `bytemuck`
//!
//! `bytemuck` would save a few lines, but the crate is `#![no_std]`
//! and we want to keep its dependency surface minimal (it compiles
//! into BPF programs). `ShmPod` is a sealed marker trait we use only
//! to self-document which types are safe to transmute and to feed
//! into the daemon-side `seqlock_read` helper.

use crate::{
    metrics::{
        BlockStats, CpuStats, MemorySnapshot, NetIfaceStats, ProcessStats, SchedHistogram,
        SecurityEventCounts, TcpStateSnapshot,
    },
    V3_MAX_BLOCK_DEVS, V3_MAX_CPU_CORES, V3_MAX_NET_IFACES, V3_MAX_PROCESSES,
};

// ----- sealed "safe to memmap" marker -----

mod private {
    pub trait Sealed {}
}

/// Marker trait for types that are safe to transmute from raw bytes
/// read out of a POSIX shared memory segment. Sealed so only this
/// crate can assert soundness — callers on the daemon side use it
/// as a bound on a `seqlock_read::<T>` helper.
///
/// # Safety
///
/// Every implementor must be:
///
/// * `#[repr(C)]` with a well-defined field layout
/// * composed entirely of integer primitives, fixed-size arrays of
///   integers, or other `ShmPod` types
/// * safe to read from any bit pattern (no enums with discriminant
///   holes, no `NonZero*`, no references, no `bool`)
pub unsafe trait ShmPod: Copy + Sized + private::Sealed {}

// Base case implementations. Every type listed here has already been
// declared `#[repr(C)]` elsewhere in this crate; we just lift them
// into the ShmPod vocabulary so the composite snapshot can use them.
macro_rules! impl_shm_pod {
    ($($t:ty),* $(,)?) => {
        $(
            impl private::Sealed for $t {}
            unsafe impl ShmPod for $t {}
        )*
    };
}

impl_shm_pod!(
    CpuStats,
    ProcessStats,
    BlockStats,
    NetIfaceStats,
    TcpStateSnapshot,
    SchedHistogram,
    MemorySnapshot,
    SecurityEventCounts,
);

// ----- header -----

/// Magic number at offset 0 of the shm segment. ASCII "AGL_HELT".
pub const SHM_MAGIC: u64 = 0x4147_4C5F_4845_4C54;

/// Current shm schema version. Bump on any breaking layout change.
pub const SHM_VERSION: u32 = 1;

/// Fixed-size header. 64 bytes total so the payload starts
/// cache-line-aligned. The final 24-byte `_reserved` region exists so
/// future versions can add fields without breaking alignment.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ShmHeader {
    pub magic: u64,
    pub version: u32,
    pub _pad0: u32,
    /// Seqlock sequence counter. Even = stable, odd = writer in
    /// progress. Loaded with acquire ordering by the reader.
    pub sequence: u64,
    /// Wall-clock nanoseconds since the UNIX epoch at the moment the
    /// writer finished assembling this snapshot.
    pub timestamp_ns_wall: u64,
    /// `size_of::<MetricSnapshotV3>()`, emitted by the writer for
    /// sanity-checking on the reader side.
    pub snapshot_size: u32,
    pub _pad1: u32,
    pub _reserved: [u8; 24],
}

impl private::Sealed for ShmHeader {}
unsafe impl ShmPod for ShmHeader {}

impl ShmHeader {
    /// Construct a header ready to be written into shm. `sequence`
    /// starts at 0 (stable) and is bumped by the writer before the
    /// first payload update.
    pub const fn new() -> Self {
        Self {
            magic: SHM_MAGIC,
            version: SHM_VERSION,
            _pad0: 0,
            sequence: 0,
            timestamp_ns_wall: 0,
            snapshot_size: core::mem::size_of::<MetricSnapshotV3>() as u32,
            _pad1: 0,
            _reserved: [0u8; 24],
        }
    }
}

impl Default for ShmHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ----- per-subsystem fixed-size wrappers -----

/// `SchedHistogram` plus pre-computed percentiles. The v1
/// `SchedSnapshot` type lives in the daemon (with serde); duplicating
/// the struct layout here keeps this crate free of daemon dependencies.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SchedSnapshotFixed {
    pub histogram: SchedHistogram,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

impl private::Sealed for SchedSnapshotFixed {}
unsafe impl ShmPod for SchedSnapshotFixed {}

/// System load averages from `/proc/loadavg`, mirrored from the
/// daemon-side `LoadSnapshot` but kept here as plain `f64` so this
/// crate stays free of daemon dependencies.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LoadSnapshotFixed {
    pub load_1: f64,
    pub load_5: f64,
    pub load_15: f64,
}

impl private::Sealed for LoadSnapshotFixed {}
unsafe impl ShmPod for LoadSnapshotFixed {}

// Per-process rows in the v3 snapshot reuse [`crate::metrics::ProcessStats`]
// directly — it's already `#[repr(C)]` POD with the exact field set we
// want (pid/ppid/uid/thread_count, all the BPF-sourced counters, and
// the `comm` byte array), so defining a separate `ProcessRow` type
// would just be duplicated layout. The aggregator / shm writer
// overlays the `/proc`-sourced fields (`mem_rss_bytes`, `mem_vms_bytes`,
// `thread_count`) onto each row before publishing.

// ----- root snapshot -----

/// The full v3 metric snapshot written into
/// `/dev/shm/agl-health-metrics`. Laid out so that every subsystem
/// the Flutter Overview / Process / Network / Disk / Scheduler screens
/// consume is reachable via a fixed `ByteData` offset from Dart.
///
/// **NOT** serde-serialized. The v1 JSON path in
/// [`crate::metrics::MetricSnapshot`] is preserved for REST/WebSocket
/// consumers (EdgeX, Prometheus, eKuiper, external tooling).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MetricSnapshotV3 {
    pub header: ShmHeader,

    // System-wide gauges.
    pub memory: MemorySnapshot,
    pub load: LoadSnapshotFixed,
    pub sched: SchedSnapshotFixed,
    pub tcp: TcpStateSnapshot,
    pub security: SecurityEventCounts,

    // Fixed-size collections. Each row array is paired with a `*_count`
    // field giving the number of valid entries. Excess capacity is
    // guaranteed zero-initialized by the writer; the reader should
    // iterate `..count`, not the full array.
    pub cpu_core_count: u32,
    pub _pad_cpu: u32,
    pub cpu_cores: [CpuStats; V3_MAX_CPU_CORES],

    pub net_iface_count: u32,
    pub _pad_net: u32,
    pub net_ifaces: [NetIfaceStats; V3_MAX_NET_IFACES],

    pub block_dev_count: u32,
    pub _pad_blk: u32,
    pub block_devs: [BlockStats; V3_MAX_BLOCK_DEVS],

    pub process_count: u32,
    pub _pad_proc: u32,
    pub top_processes: [ProcessStats; V3_MAX_PROCESSES],

    /// Per-CPU scheduler latency histograms with pre-computed
    /// percentiles, one entry per online CPU. The merged histogram
    /// above (`sched`) is the cross-CPU aggregate; these give
    /// per-core granularity for the Flutter Scheduler screen's
    /// per-CPU view.
    pub sched_cpu_count: u32,
    pub _pad_sched_cpu: u32,
    pub sched_per_cpu: [SchedSnapshotFixed; V3_MAX_CPU_CORES],
}

impl private::Sealed for MetricSnapshotV3 {}
unsafe impl ShmPod for MetricSnapshotV3 {}

impl MetricSnapshotV3 {
    /// Compile-time size of the full snapshot including the 64-byte
    /// header. The value is emitted into the header as `snapshot_size`
    /// so the reader can sanity-check layout compatibility.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Zero-initialized snapshot. Useful as a write buffer for the
    /// daemon aggregator, and as a safe initial state for the reader
    /// before the first seqlock-valid read completes.
    ///
    /// # Safety
    ///
    /// Every field in `MetricSnapshotV3` is itself a `ShmPod` and
    /// therefore safe to construct from an all-zero bit pattern.
    #[inline]
    pub const fn zeroed() -> Self {
        // SAFETY: see doc comment above.
        unsafe { core::mem::zeroed() }
    }
}

impl Default for MetricSnapshotV3 {
    fn default() -> Self {
        Self::zeroed()
    }
}

// A hard compile-time budget on the snapshot size. The v3 plan
// specifies a 16 KB shm segment for a minimal metric slot set; our
// expanded layout with 512 ProcessRows and 16 CpuStats is larger.
// 512 KB is a generous ceiling that rules out accidental bloat (e.g.
// someone bumping V3_MAX_PROCESSES to 65536 without thinking).
const _: () = assert!(
    MetricSnapshotV3::SIZE <= 512 * 1024,
    "MetricSnapshotV3 exceeded 512 KiB budget - check array caps",
);

// The header must stay exactly 64 bytes so the payload lands on a
// cache-line boundary. If anything changes the layout this fires.
const _: () = assert!(
    core::mem::size_of::<ShmHeader>() == 64,
    "ShmHeader must be exactly 64 bytes",
);
