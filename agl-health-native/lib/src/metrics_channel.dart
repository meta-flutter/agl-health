// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

/// Magic number in the shm header. ASCII "AGL_HELT" as a little-endian
/// 64-bit unsigned integer. Must match `metrics_v3::SHM_MAGIC` on the
/// Rust side.
const int _shmMagic = 0x41474C5F48454C54;

/// Expected snapshot size. Anything else and the layout has drifted;
/// the caller should reject the payload.
const int _shmSnapshotSize = 68752;

// --- Field offsets ---
//
// Every offset in this file matches a value emitted by the Rust test
// `agl-health-common/tests/v3_offsets_dump.rs`. Re-run that test
// after any layout change:
//
//   cargo test -p agl-health-common --test v3_offsets_dump -- --nocapture
//
// and update the constants below. The `MetricSnapshot.fromBytes`
// factory validates `snapshot_size` against `_shmSnapshotSize` so
// the only failure mode from forgetting this step is a hard "wrong
// size" error at startup, not silently corrupted fields.

// Header (see ShmHeader in metrics_v3.rs).
const int _offMagic = 0;
const int _offVersion = 8;
const int _offSequence = 16;
const int _offTimestampNsWall = 24;
const int _offSnapshotSize = 32;

// Memory section (MemorySnapshot at offset 64).
const int _offMemTotal = 64;
const int _offMemFree = 72;
const int _offMemCached = 80;
const int _offMemBuffered = 88;
const int _offMemSlab = 96;
const int _offMemSwapUsed = 104;
const int _offMemSwapFree = 112;
const int _offMemPageFaultsMinor = 120;
const int _offMemPageFaultsMajor = 128;
const int _offMemPsiSomeX100 = 136;
const int _offMemPsiFullX100 = 140;
const int _offMemOomKillsTotal = 144;

// Load section (LoadSnapshotFixed at offset 152).
const int _offLoad1 = 152;
const int _offLoad5 = 160;
const int _offLoad15 = 168;

// Scheduler percentiles (SchedSnapshotFixed.{p50,p95,p99}_ns).
const int _offSchedP50 = 264;
const int _offSchedP95 = 272;
const int _offSchedP99 = 280;

/// Memory subsection of [`MetricSnapshot`].
///
/// All byte fields are raw `u64` values in the same units the kernel
/// reports (bytes). The x100 PSI percentages are kept as integers to
/// match the Rust side; [psiSomePct] / [psiFullPct] return `double`
/// for convenience.
class MemorySection {
  final int totalBytes;
  final int freeBytes;
  final int cachedBytes;
  final int bufferedBytes;
  final int slabBytes;
  final int swapUsedBytes;
  final int swapFreeBytes;
  final int pageFaultsMinor;
  final int pageFaultsMajor;
  final int psiSomeX100;
  final int psiFullX100;
  final int oomKillsTotal;

  const MemorySection({
    required this.totalBytes,
    required this.freeBytes,
    required this.cachedBytes,
    required this.bufferedBytes,
    required this.slabBytes,
    required this.swapUsedBytes,
    required this.swapFreeBytes,
    required this.pageFaultsMinor,
    required this.pageFaultsMajor,
    required this.psiSomeX100,
    required this.psiFullX100,
    required this.oomKillsTotal,
  });

  double get psiSomePct => psiSomeX100 / 100.0;
  double get psiFullPct => psiFullX100 / 100.0;
}

/// 1 / 5 / 15-minute load averages as reported by `/proc/loadavg`
/// via the daemon's `proc_tier` task.
class LoadSection {
  final double load1;
  final double load5;
  final double load15;

  const LoadSection({
    required this.load1,
    required this.load5,
    required this.load15,
  });
}

/// Typed view over a `MetricSnapshotV3` byte buffer received from
/// the C++ plugin's shm channel.
///
/// Phase 2 exposes the subset of fields needed to prove the
/// zero-copy plumbing: header sanity, memory gauges, load averages,
/// and scheduler percentiles. Every additional field the Flutter
/// screens need in Phases 3-6 gets added here as a cheap ByteData
/// read.
///
/// The underlying [Uint8List] is (on the happy path) backed directly
/// by the mmap'd shm segment — that's the whole point of
/// `Dart_NewExternalTypedData`. Fields are read on demand via
/// [_data.getUint64] etc, so constructing a `MetricSnapshot` does no
/// heap allocation beyond the small [MemorySection] / [LoadSection]
/// wrappers.
class MetricSnapshot {
  final Uint8List _bytes;
  final ByteData _data;

  MetricSnapshot._(this._bytes)
      : _data = ByteData.view(
          _bytes.buffer,
          _bytes.offsetInBytes,
          _bytes.lengthInBytes,
        );

  /// Parse a `MetricSnapshotV3` payload from raw bytes.
  ///
  /// Throws [FormatException] if the buffer is the wrong size,
  /// carries the wrong magic, or reports a `snapshot_size` other
  /// than what we expect — any of which indicates a layout drift
  /// between this Dart client and the daemon and is unrecoverable
  /// without a code update.
  factory MetricSnapshot.fromBytes(Uint8List bytes) {
    if (bytes.lengthInBytes != _shmSnapshotSize) {
      throw FormatException(
          'MetricSnapshot: expected $_shmSnapshotSize bytes, got '
          '${bytes.lengthInBytes}');
    }
    final snap = MetricSnapshot._(bytes);
    if (snap.magic != _shmMagic) {
      throw FormatException(
          'MetricSnapshot: magic mismatch: expected '
          '0x${_shmMagic.toRadixString(16)}, got '
          '0x${snap.magic.toRadixString(16)}');
    }
    if (snap.snapshotSize != _shmSnapshotSize) {
      throw FormatException(
          'MetricSnapshot: header snapshot_size ${snap.snapshotSize} '
          'does not match expected $_shmSnapshotSize');
    }
    return snap;
  }

  // --- header ---

  int get magic => _data.getUint64(_offMagic, Endian.little);
  int get version => _data.getUint32(_offVersion, Endian.little);
  int get sequence => _data.getUint64(_offSequence, Endian.little);
  int get timestampNsWall =>
      _data.getUint64(_offTimestampNsWall, Endian.little);
  int get snapshotSize => _data.getUint32(_offSnapshotSize, Endian.little);

  // --- sections (construction is cheap; no stored field) ---

  MemorySection get memory => MemorySection(
        totalBytes: _data.getUint64(_offMemTotal, Endian.little),
        freeBytes: _data.getUint64(_offMemFree, Endian.little),
        cachedBytes: _data.getUint64(_offMemCached, Endian.little),
        bufferedBytes: _data.getUint64(_offMemBuffered, Endian.little),
        slabBytes: _data.getUint64(_offMemSlab, Endian.little),
        swapUsedBytes: _data.getUint64(_offMemSwapUsed, Endian.little),
        swapFreeBytes: _data.getUint64(_offMemSwapFree, Endian.little),
        pageFaultsMinor:
            _data.getUint64(_offMemPageFaultsMinor, Endian.little),
        pageFaultsMajor:
            _data.getUint64(_offMemPageFaultsMajor, Endian.little),
        psiSomeX100: _data.getUint32(_offMemPsiSomeX100, Endian.little),
        psiFullX100: _data.getUint32(_offMemPsiFullX100, Endian.little),
        oomKillsTotal:
            _data.getUint64(_offMemOomKillsTotal, Endian.little),
      );

  LoadSection get load => LoadSection(
        load1: _data.getFloat64(_offLoad1, Endian.little),
        load5: _data.getFloat64(_offLoad5, Endian.little),
        load15: _data.getFloat64(_offLoad15, Endian.little),
      );

  // --- scheduler (percentiles only for Phase 2) ---

  int get schedP50Ns => _data.getUint64(_offSchedP50, Endian.little);
  int get schedP95Ns => _data.getUint64(_offSchedP95, Endian.little);
  int get schedP99Ns => _data.getUint64(_offSchedP99, Endian.little);
}
