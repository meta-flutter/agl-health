// SPDX-License-Identifier: Apache-2.0
//
// Frame-aligned MetricSnapshot notifier per v3 plan §12.3.
//
// The shm channel posts at 1 Hz from the C++ plugin. This notifier
// coalesces updates to the vsync boundary via addPostFrameCallback
// so that widgets rebuild at most once per display frame —
// regardless of the underlying event rate (which will be higher
// once Phase 5 adds the Unix socket channel).

import 'dart:collection';

import 'package:flutter/foundation.dart';
import 'package:flutter/scheduler.dart';

import 'package:agl_health_native/agl_health_native.dart';

/// Per-CPU delta computed from consecutive snapshots.
class CpuDelta {
  final int cpuId;
  final int userDelta, systemDelta, irqDelta, softirqDelta;
  final int totalDelta;

  CpuDelta({
    required this.cpuId,
    required this.userDelta,
    required this.systemDelta,
    required this.irqDelta,
    required this.softirqDelta,
  }) : totalDelta = userDelta + systemDelta + irqDelta + softirqDelta;
}

/// Rolling buffer of the last [maxSamples] metric snapshots, used
/// by sparkline charts on the Overview screen.
class MetricsNotifier extends ChangeNotifier {
  MetricsNotifier({this.maxSamples = 60});

  final int maxSamples;

  MetricSnapshot? _latest;
  bool _pendingNotify = false;

  /// The most recent snapshot. Null before the first shm post.
  MetricSnapshot? get current => _latest;

  // Rolling history for sparklines (load_1 and memory used %).
  final _loadHistory = Queue<double>();
  final _memUsedPctHistory = Queue<double>();

  /// Last [maxSamples] load_1 values for the sparkline.
  List<double> get loadHistory => List.unmodifiable(_loadHistory);

  /// Last [maxSamples] memory-used-percentage values.
  List<double> get memUsedPctHistory => List.unmodifiable(_memUsedPctHistory);

  // Per-CPU deltas between consecutive snapshots, smoothed.
  List<CpuDelta> _cpuDeltas = [];
  // Previous tick's cumulative per-CPU values for delta computation.
  List<_CpuAccum> _prevCpu = [];
  // EMA-smoothed per-CPU deltas for visual smoothing.
  final List<_SmoothedCpu> _smoothed = [];

  /// EMA alpha. 0.35 gives ~3-sample smoothing (responsive but
  /// not jittery). Lower = smoother but more lag.
  static const _emaAlpha = 0.35;

  /// Per-CPU activity deltas over the last 1-second tick. Each entry
  /// shows how many nanoseconds that core spent in user/system/irq/
  /// softirq since the previous snapshot. The Overview CPU bars
  /// render these as proportional bars.
  List<CpuDelta> get cpuDeltas => _cpuDeltas;

  /// Called from the [AglHealthClient.metrics] stream listener.
  /// Safe to call at any frequency — notification is coalesced to
  /// the next vsync via [addPostFrameCallback].
  void update(MetricSnapshot snapshot) {
    _latest = snapshot;

    // Sparkline history.
    final load = snapshot.load;
    _pushBounded(_loadHistory, load.load1);

    final mem = snapshot.memory;
    final total = mem.totalBytes;
    final used = total > 0 ? (total - mem.freeBytes) / total : 0.0;
    _pushBounded(_memUsedPctHistory, used * 100.0);

    // Per-CPU deltas with EMA smoothing.
    final cpuCount = snapshot.cpuCount;
    final newCpu = <_CpuAccum>[];
    final deltas = <CpuDelta>[];
    for (int i = 0; i < cpuCount; i++) {
      final c = snapshot.cpu(i);
      final cur = _CpuAccum(
        c.cpuId,
        c.userNs,
        c.systemNs,
        c.irqNs,
        c.softirqNs,
      );
      newCpu.add(cur);
      if (i < _prevCpu.length) {
        final prev = _prevCpu[i];
        final rawUser = (cur.user - prev.user).clamp(0, 1 << 62);
        final rawSys = (cur.system - prev.system).clamp(0, 1 << 62);
        final rawIrq = (cur.irq - prev.irq).clamp(0, 1 << 62);
        final rawSi = (cur.softirq - prev.softirq).clamp(0, 1 << 62);

        // Apply EMA: smoothed = alpha * raw + (1 - alpha) * prev_smoothed
        final s = i < _smoothed.length
            ? _smoothed[i]
            : _SmoothedCpu(
                rawUser.toDouble(),
                rawSys.toDouble(),
                rawIrq.toDouble(),
                rawSi.toDouble(),
              );
        final sUser = _emaAlpha * rawUser + (1 - _emaAlpha) * s.user;
        final sSys = _emaAlpha * rawSys + (1 - _emaAlpha) * s.system;
        final sIrq = _emaAlpha * rawIrq + (1 - _emaAlpha) * s.irq;
        final sSi = _emaAlpha * rawSi + (1 - _emaAlpha) * s.softirq;

        if (i < _smoothed.length) {
          _smoothed[i] = _SmoothedCpu(sUser, sSys, sIrq, sSi);
        } else {
          _smoothed.add(_SmoothedCpu(sUser, sSys, sIrq, sSi));
        }

        deltas.add(
          CpuDelta(
            cpuId: c.cpuId,
            userDelta: sUser.round(),
            systemDelta: sSys.round(),
            irqDelta: sIrq.round(),
            softirqDelta: sSi.round(),
          ),
        );
      }
    }
    _prevCpu = newCpu;
    _cpuDeltas = deltas;

    if (_pendingNotify) return;
    _pendingNotify = true;
    SchedulerBinding.instance.addPostFrameCallback((_) {
      _pendingNotify = false;
      notifyListeners();
    });
  }

  void _pushBounded(Queue<double> q, double value) {
    if (q.length >= maxSamples) q.removeFirst();
    q.addLast(value);
  }
}

class _CpuAccum {
  final int id, user, system, irq, softirq;
  _CpuAccum(this.id, this.user, this.system, this.irq, this.softirq);
}

class _SmoothedCpu {
  double user, system, irq, softirq;
  _SmoothedCpu(this.user, this.system, this.irq, this.softirq);
}
