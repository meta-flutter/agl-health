// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Time base conversion between BPF `bpf_ktime_get_ns` and wall clock.
//!
//! BPF programs use `bpf_ktime_get_ns`, which returns `CLOCK_MONOTONIC`
//! nanoseconds (nanoseconds since boot, **not** including suspended
//! time). Flutter and every external consumer want wall-clock
//! nanoseconds since the UNIX epoch. This module computes the fixed
//! offset once at daemon startup and provides `to_wall_ns(ktime)` as
//! the only conversion point in the codebase.
//!
//! Assumptions documented for future-me:
//!
//! * The offset is fixed for the lifetime of the daemon. `CLOCK_MONOTONIC`
//!   and wall clock both advance in real time, so their difference is
//!   stable unless the real-time clock is adjusted (NTP step, manual
//!   set). If that happens the reported `timestamp_ns_wall` values
//!   become slightly wrong but the daemon does not misbehave.
//! * `CLOCK_MONOTONIC` does not include time the system was suspended.
//!   On IVI hardware that doesn't suspend this is moot. If a platform
//!   suspends and we care about correct post-resume timestamps, the
//!   offset needs to be re-sampled on resume — an explicit follow-up
//!   but not something v3 promises today.
//! * Sub-microsecond drift between the two clocks over days is well
//!   below any rendering or visualization resolution (1 Hz shm poll,
//!   vsync rendering at 60-120 Hz).

use std::time::{SystemTime, UNIX_EPOCH};

/// Captured-at-startup conversion from `CLOCK_MONOTONIC` nanoseconds
/// (the BPF time base) to wall-clock nanoseconds since the UNIX epoch.
///
/// Construct once with `TimeBase::capture()` and clone into every
/// subsystem that needs to emit a wall-clock timestamp. The struct is
/// `Copy` so cloning is free.
#[derive(Copy, Clone, Debug)]
pub struct TimeBase {
    /// `wall_ns - ktime_ns` at the moment of capture. Signed because
    /// a wall clock set behind boot time would give a negative offset.
    /// We store it as i128 to keep the arithmetic simple on both sides
    /// of the sum regardless of 32/64-bit host.
    #[allow(dead_code)]
    offset_ns: i128,
}

// Every caller of `to_wall_ns` / `now_wall_ns` lives inside the
// `cfg(feature = "ebpf")` aggregator and loader drainers. In the
// default (no-ebpf) build the struct is still captured at startup
// and threaded into `loader::load`, but the methods are never
// actually invoked — hence the blanket allow.
#[allow(dead_code)]
impl TimeBase {
    /// Sample both clocks as close to simultaneously as possible and
    /// compute the fixed offset. Call once at daemon startup.
    pub fn capture() -> Self {
        let ktime_ns = clock_monotonic_ns();
        let wall_ns = wall_clock_ns();
        Self {
            offset_ns: wall_ns as i128 - ktime_ns as i128,
        }
    }

    /// Convert a `bpf_ktime_get_ns()` value (or any other
    /// `CLOCK_MONOTONIC` nanosecond reading) into wall-clock
    /// nanoseconds since the UNIX epoch.
    ///
    /// Saturating conversion: if the arithmetic would underflow a
    /// `u64` we return 0 rather than panic or produce garbage. That
    /// only happens if the offset is a large negative number (wall
    /// clock behind boot time) and the `ktime_ns` is very small,
    /// which in practice means "the daemon just started and
    /// something is very wrong."
    #[inline]
    pub fn to_wall_ns(&self, ktime_ns: u64) -> u64 {
        let sum = (ktime_ns as i128) + self.offset_ns;
        if sum < 0 {
            0
        } else if sum > u64::MAX as i128 {
            u64::MAX
        } else {
            sum as u64
        }
    }

    /// Return the current wall-clock time via the same offset, for
    /// use in the aggregator when stamping `snap.timestamp_ns` /
    /// `ShmHeader.timestamp_ns_wall`. Going through the offset rather
    /// than calling `SystemTime::now()` directly guarantees that
    /// every `timestamp_ns` field in every output path uses the
    /// exact same time base.
    #[inline]
    pub fn now_wall_ns(&self) -> u64 {
        self.to_wall_ns(clock_monotonic_ns())
    }
}

/// Read `CLOCK_MONOTONIC` nanoseconds via libc. This is the same
/// clock that BPF's `bpf_ktime_get_ns` helper reads.
fn clock_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: libc::clock_gettime takes a valid pointer to a writable
    // timespec. On failure we get a zero timestamp, which the caller
    // will interpret sensibly (offset will be wrong, but no UB).
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// Read wall-clock nanoseconds since the UNIX epoch via `SystemTime`.
/// Used only once at capture; the steady-state hot path goes through
/// `now_wall_ns`, which uses the faster `clock_gettime(MONOTONIC)`.
fn wall_clock_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_produces_reasonable_offset() {
        let tb = TimeBase::capture();
        let now = tb.now_wall_ns();
        // Sanity: a recent wall-clock ns should be in the
        // 1.7e18 .. 2.0e18 range (2023 .. 2033).
        assert!(now > 1_700_000_000_000_000_000);
        assert!(now < 2_000_000_000_000_000_000);
    }

    #[test]
    fn to_wall_ns_is_monotonic() {
        let tb = TimeBase::capture();
        let a = tb.to_wall_ns(1_000);
        let b = tb.to_wall_ns(2_000);
        assert!(b > a);
        assert_eq!(b - a, 1_000);
    }
}
