// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

/// Magic number in the shm header. ASCII "AGL_HELT" as a little-endian
/// 64-bit unsigned integer. Must match `metrics_v3::SHM_MAGIC` on the
/// Rust side.
const int _shmMagic = 0x41474C5F48454C54;

/// Expected snapshot size. Anything else and the layout has drifted;
/// the caller should reject the payload.
const int _shmSnapshotSize = 70552;

/// Expected header version. Must match `metrics_v3::SHM_VERSION`. A
/// segment with the same size/magic but a different version carries
/// different field semantics and must be rejected.
const int _shmVersion = 1;

// Fixed array capacities in MetricSnapshotV3. The header counts are
// writer-controlled; every count getter clamps to these so a bogus or
// hostile header can never drive an out-of-bounds read (which would
// throw RangeError and kill the metrics stream every tick).
const int _maxCpuCores = 16;
const int _maxNetIfaces = 8;
const int _maxBlockDevs = 16;
const int _maxProcesses = 512;
const int _maxSchedPerCpu = 16;

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

// Scheduler (SchedSnapshotFixed at offset 176, 112 bytes).
// Contains a SchedHistogram (88 bytes) then 3 percentile u64s.
const int _offSchedBuckets = 176; // 8 x u64 = 64 bytes
const int _offSchedTotalCount = 240; // 176 + 64
const int _offSchedTotalLatency = 248; // 176 + 72
const int _offSchedMaxLatency = 256; // 176 + 80
const int _offSchedP50 = 264; // 176 + 88
const int _offSchedP95 = 272; // 176 + 96
const int _offSchedP99 = 280; // 176 + 104
const int _schedBucketCount = 8;

// TCP state snapshot (TcpStateSnapshot at offset 288, 96 bytes).
const int _offTcp = 288;

// Security counters (SecurityEventCounts at offset 384, 48 bytes = 6 u64).
const int _offSecurity = 384;

// CPU cores (CpuStats[16] at offset 440, count u32 at offset 432).
const int _offCpuCount = 432;
const int _offCpuCores = 440;
const int _cpuEntrySize = 64;

// Net interfaces (NetIfaceStats[8] at offset 1472, count u32 at offset 1464).
const int _offNetCount = 1464;
const int _offNetIfaces = 1472;
const int _netEntrySize = 72;

// Block devices (BlockStats[16] at offset 2056, count u32 at offset 2048).
const int _offBlockCount = 2048;
const int _offBlockDevs = 2056;
const int _blockEntrySize = 72;

// Top processes (ProcessStats[512] at offset 3216, count u32 at offset 3208).
const int _offProcCount = 3208;
const int _offProcStats = 3216;
const int _procEntrySize = 128;

// Per-CPU scheduler histograms (SchedSnapshotFixed[16] at offset 68760,
// count u32 at offset 68752). Appended at end — no existing offsets shifted.
const int _offSchedCpuCount = 68752;
const int _offSchedPerCpu = 68760;
const int _schedSnapshotFixedSize = 112; // same as merged sched entry

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

// -------- section classes --------

/// Cumulative counts of security-relevant syscall events from the
/// daemon's `security.rs` eBPF probes.
class SecuritySection {
  final int ptrace;
  final int memfdCreate;
  final int prctl;
  final int setuid;
  final int execAnomaly;
  final int capabilityUse;

  const SecuritySection({
    required this.ptrace,
    required this.memfdCreate,
    required this.prctl,
    required this.setuid,
    required this.execAnomaly,
    required this.capabilityUse,
  });

  /// Total across all categories.
  int get total =>
      ptrace + memfdCreate + prctl + setuid + execAnomaly + capabilityUse;
}

// -------- array section classes --------

/// Per-CPU scheduling class time accumulator.
class CpuStatsSection {
  final int cpuId;
  final int userNs, systemNs, iowaitNs, irqNs, softirqNs, idleNs;
  final int ctxSwitches;
  const CpuStatsSection({
    required this.cpuId,
    required this.userNs,
    required this.systemNs,
    required this.iowaitNs,
    required this.irqNs,
    required this.softirqNs,
    required this.idleNs,
    required this.ctxSwitches,
  });
}

/// Per-process accumulated stats.
class ProcessStatsSection {
  final int pid, ppid, uid, threadCount;
  final int cpuUserNs, cpuSystemNs;
  final int memRssBytes, memVmsBytes;
  final int voluntaryCtxSw, involuntaryCtxSw;
  final int readBytes, writeBytes;
  final int pageFaultsMinor, pageFaultsMajor;
  final int startTimeNs, openFds;
  final String comm;
  const ProcessStatsSection({
    required this.pid,
    required this.ppid,
    required this.uid,
    required this.threadCount,
    required this.cpuUserNs,
    required this.cpuSystemNs,
    required this.memRssBytes,
    required this.memVmsBytes,
    required this.voluntaryCtxSw,
    required this.involuntaryCtxSw,
    required this.readBytes,
    required this.writeBytes,
    required this.pageFaultsMinor,
    required this.pageFaultsMajor,
    required this.startTimeNs,
    required this.openFds,
    required this.comm,
  });
}

/// Per-network-interface byte/packet counters.
class NetIfaceSection {
  final int ifaceIdx;
  final int rxBytes, txBytes, rxPackets, txPackets;
  final int rxDrops, txDrops, rxErrors, txErrors;
  const NetIfaceSection({
    required this.ifaceIdx,
    required this.rxBytes,
    required this.txBytes,
    required this.rxPackets,
    required this.txPackets,
    required this.rxDrops,
    required this.txDrops,
    required this.rxErrors,
    required this.txErrors,
  });
}

/// Per-block-device I/O statistics.
class BlockStatsSection {
  final int deviceMajor, deviceMinor;
  final int readsCompleted, writesCompleted;
  final int readBytes, writeBytes;
  final int readLatencyNs, writeLatencyNs;
  final int ioInflight, ioTicksMs;
  const BlockStatsSection({
    required this.deviceMajor,
    required this.deviceMinor,
    required this.readsCompleted,
    required this.writesCompleted,
    required this.readBytes,
    required this.writeBytes,
    required this.readLatencyNs,
    required this.writeLatencyNs,
    required this.ioInflight,
    required this.ioTicksMs,
  });
}

/// Scheduler runqueue-wait latency histogram + percentiles.
///
/// Bucket boundaries are log-spaced: <10us, <100us, <1ms, <10ms,
/// <100ms, <1s, <10s, >=10s. The value in each bucket is the
/// cumulative count of sched_switch events whose runqueue-wait
/// duration fell into that range.
class SchedSection {
  final List<int> buckets; // length == 8
  final int totalCount;
  final int totalLatencyNs;
  final int maxLatencyNs;
  final int p50Ns, p95Ns, p99Ns;

  const SchedSection({
    required this.buckets,
    required this.totalCount,
    required this.totalLatencyNs,
    required this.maxLatencyNs,
    required this.p50Ns,
    required this.p95Ns,
    required this.p99Ns,
  });

  /// Average runqueue-wait latency in nanoseconds. Zero if no
  /// events have been recorded yet.
  double get avgLatencyNs => totalCount > 0 ? totalLatencyNs / totalCount : 0.0;

  /// Human-readable bucket labels matching the kernel-side
  /// `bucket_of` function in `scheduler.rs`.
  static const bucketLabels = [
    '<10us',
    '<100us',
    '<1ms',
    '<10ms',
    '<100ms',
    '<1s',
    '<10s',
    '>=10s',
  ];
}

/// System-wide TCP state machine counters.
class TcpStateSection {
  final int established, synSent, synRecv;
  final int finWait1, finWait2, timeWait, closeWait;
  final int listen, listenOverflows;
  final int retransmits, resetsIn, resetsOut;
  const TcpStateSection({
    required this.established,
    required this.synSent,
    required this.synRecv,
    required this.finWait1,
    required this.finWait2,
    required this.timeWait,
    required this.closeWait,
    required this.listen,
    required this.listenOverflows,
    required this.retransmits,
    required this.resetsIn,
    required this.resetsOut,
  });
}

/// Typed view over a `MetricSnapshotV3` byte buffer received from
/// the C++ plugin's shm channel.
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
        '${bytes.lengthInBytes}',
      );
    }
    final snap = MetricSnapshot._(bytes);
    if (snap.magic != _shmMagic) {
      throw FormatException(
        'MetricSnapshot: magic mismatch: expected '
        '0x${_shmMagic.toRadixString(16)}, got '
        '0x${snap.magic.toRadixString(16)}',
      );
    }
    if (snap.snapshotSize != _shmSnapshotSize) {
      throw FormatException(
        'MetricSnapshot: header snapshot_size ${snap.snapshotSize} '
        'does not match expected $_shmSnapshotSize',
      );
    }
    if (snap.version != _shmVersion) {
      throw FormatException(
        'MetricSnapshot: header version ${snap.version} does not match '
        'expected $_shmVersion',
      );
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
    pageFaultsMinor: _data.getUint64(_offMemPageFaultsMinor, Endian.little),
    pageFaultsMajor: _data.getUint64(_offMemPageFaultsMajor, Endian.little),
    psiSomeX100: _data.getUint32(_offMemPsiSomeX100, Endian.little),
    psiFullX100: _data.getUint32(_offMemPsiFullX100, Endian.little),
    oomKillsTotal: _data.getUint64(_offMemOomKillsTotal, Endian.little),
  );

  LoadSection get load => LoadSection(
    load1: _data.getFloat64(_offLoad1, Endian.little),
    load5: _data.getFloat64(_offLoad5, Endian.little),
    load15: _data.getFloat64(_offLoad15, Endian.little),
  );

  // --- scheduler ---

  SchedSection get sched => SchedSection(
    buckets: [
      for (int i = 0; i < _schedBucketCount; i++)
        _u64(_offSchedBuckets + i * 8),
    ],
    totalCount: _u64(_offSchedTotalCount),
    totalLatencyNs: _u64(_offSchedTotalLatency),
    maxLatencyNs: _u64(_offSchedMaxLatency),
    p50Ns: _u64(_offSchedP50),
    p95Ns: _u64(_offSchedP95),
    p99Ns: _u64(_offSchedP99),
  );

  // Keep individual getters for backward compat with Phase 3 overview.
  int get schedP50Ns => _u64(_offSchedP50);
  int get schedP95Ns => _u64(_offSchedP95);
  int get schedP99Ns => _u64(_offSchedP99);

  // --- TCP ---

  TcpStateSection get tcp => TcpStateSection(
    established: _u64(_offTcp + 0),
    synSent: _u64(_offTcp + 8),
    synRecv: _u64(_offTcp + 16),
    finWait1: _u64(_offTcp + 24),
    finWait2: _u64(_offTcp + 32),
    timeWait: _u64(_offTcp + 40),
    closeWait: _u64(_offTcp + 48),
    listen: _u64(_offTcp + 56),
    listenOverflows: _u64(_offTcp + 64),
    retransmits: _u64(_offTcp + 72),
    resetsIn: _u64(_offTcp + 80),
    resetsOut: _u64(_offTcp + 88),
  );

  // --- security ---

  SecuritySection get security => SecuritySection(
    ptrace: _u64(_offSecurity + 0),
    memfdCreate: _u64(_offSecurity + 8),
    prctl: _u64(_offSecurity + 16),
    setuid: _u64(_offSecurity + 24),
    execAnomaly: _u64(_offSecurity + 32),
    capabilityUse: _u64(_offSecurity + 40),
  );

  // --- arrays (indexed, no list allocation) ---

  int get cpuCount {
    final c = _u32(_offCpuCount);
    return c < _maxCpuCores ? c : _maxCpuCores;
  }

  CpuStatsSection cpu(int i) {
    final o = _offCpuCores + i * _cpuEntrySize;
    return CpuStatsSection(
      cpuId: _u32(o + 0),
      userNs: _u64(o + 8),
      systemNs: _u64(o + 16),
      iowaitNs: _u64(o + 24),
      irqNs: _u64(o + 32),
      softirqNs: _u64(o + 40),
      idleNs: _u64(o + 48),
      ctxSwitches: _u64(o + 56),
    );
  }

  int get netIfaceCount {
    final c = _u32(_offNetCount);
    return c < _maxNetIfaces ? c : _maxNetIfaces;
  }

  NetIfaceSection netIface(int i) {
    final o = _offNetIfaces + i * _netEntrySize;
    return NetIfaceSection(
      ifaceIdx: _u32(o + 0),
      rxBytes: _u64(o + 8),
      txBytes: _u64(o + 16),
      rxPackets: _u64(o + 24),
      txPackets: _u64(o + 32),
      rxDrops: _u64(o + 40),
      txDrops: _u64(o + 48),
      rxErrors: _u64(o + 56),
      txErrors: _u64(o + 64),
    );
  }

  int get blockDeviceCount {
    final c = _u32(_offBlockCount);
    return c < _maxBlockDevs ? c : _maxBlockDevs;
  }

  BlockStatsSection blockDevice(int i) {
    final o = _offBlockDevs + i * _blockEntrySize;
    return BlockStatsSection(
      deviceMajor: _u32(o + 0),
      deviceMinor: _u32(o + 4),
      readsCompleted: _u64(o + 8),
      writesCompleted: _u64(o + 16),
      readBytes: _u64(o + 24),
      writeBytes: _u64(o + 32),
      readLatencyNs: _u64(o + 40),
      writeLatencyNs: _u64(o + 48),
      ioInflight: _u64(o + 56),
      ioTicksMs: _u64(o + 64),
    );
  }

  int get processCount {
    final c = _u32(_offProcCount);
    return c < _maxProcesses ? c : _maxProcesses;
  }

  ProcessStatsSection process(int i) {
    final o = _offProcStats + i * _procEntrySize;
    return ProcessStatsSection(
      pid: _u32(o + 0),
      ppid: _u32(o + 4),
      uid: _u32(o + 8),
      threadCount: _u32(o + 12),
      cpuUserNs: _u64(o + 16),
      cpuSystemNs: _u64(o + 24),
      memRssBytes: _u64(o + 32),
      memVmsBytes: _u64(o + 40),
      voluntaryCtxSw: _u64(o + 48),
      involuntaryCtxSw: _u64(o + 56),
      readBytes: _u64(o + 64),
      writeBytes: _u64(o + 72),
      pageFaultsMinor: _u64(o + 80),
      pageFaultsMajor: _u64(o + 88),
      startTimeNs: _u64(o + 96),
      openFds: _u32(o + 104),
      comm: _cstr(o + 112, 16),
    );
  }

  // --- per-CPU scheduler ---

  int get schedCpuCount {
    final c = _u32(_offSchedCpuCount);
    return c < _maxSchedPerCpu ? c : _maxSchedPerCpu;
  }

  /// Read the per-CPU scheduler histogram for CPU [i].
  /// Returns the same `SchedSection` type as the merged `sched`
  /// getter but for a single CPU core.
  SchedSection schedPerCpu(int i) {
    final o = _offSchedPerCpu + i * _schedSnapshotFixedSize;
    return SchedSection(
      buckets: [for (int j = 0; j < _schedBucketCount; j++) _u64(o + j * 8)],
      totalCount: _u64(o + 64),
      totalLatencyNs: _u64(o + 72),
      maxLatencyNs: _u64(o + 80),
      p50Ns: _u64(o + 88),
      p95Ns: _u64(o + 96),
      p99Ns: _u64(o + 104),
    );
  }

  // --- private helpers ---

  int _u32(int off) => _data.getUint32(off, Endian.little);
  int _u64(int off) => _data.getUint64(off, Endian.little);

  /// Decode a fixed-size null-terminated byte array as a UTF-8 string.
  /// Scans for the terminator in place and decodes the range directly,
  /// avoiding the two intermediate `sublist` allocations this is called
  /// once per process per snapshot.
  String _cstr(int off, int maxLen) {
    int end = off + maxLen;
    for (int k = off; k < off + maxLen; k++) {
      if (_bytes[k] == 0) {
        end = k;
        break;
      }
    }
    return String.fromCharCodes(_bytes, off, end);
  }
}
