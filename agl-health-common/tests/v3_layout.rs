// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Compile-time + runtime sanity checks on the v3 shm layout.
//!
//! The `const _: () = assert!(...)` invariants inside `metrics_v3.rs`
//! already fail the build if the header drifts off 64 bytes or the
//! snapshot blows the 512 KiB budget. This test file exists to print
//! the actual numbers when run with `--nocapture`, so it's easy to
//! tell *how much* budget we've used at any given moment.

use agl_health_common::metrics_v3::{MetricSnapshotV3, ShmHeader};

#[test]
fn shm_header_is_exactly_64_bytes() {
    assert_eq!(std::mem::size_of::<ShmHeader>(), 64);
}

#[test]
fn v3_snapshot_fits_budget() {
    let total = std::mem::size_of::<MetricSnapshotV3>();
    let header = std::mem::size_of::<ShmHeader>();
    let align = std::mem::align_of::<MetricSnapshotV3>();
    eprintln!("ShmHeader:        {header} bytes");
    eprintln!(
        "MetricSnapshotV3: {total} bytes ({:.1} KiB, {:.1}% of 512 KiB budget)",
        total as f64 / 1024.0,
        (total as f64 / (512.0 * 1024.0)) * 100.0
    );
    eprintln!("align:            {align}");
    assert!(total <= 512 * 1024);
}

#[test]
fn v3_snapshot_default_is_zeroed() {
    let snap = MetricSnapshotV3::default();
    assert_eq!(snap.header.magic, 0);
    assert_eq!(snap.process_count, 0);
    assert_eq!(snap.cpu_core_count, 0);
}
