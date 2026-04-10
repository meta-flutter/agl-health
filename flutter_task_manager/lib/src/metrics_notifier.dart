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
