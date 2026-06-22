// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0
//
// Phase 2 end-to-end smoke test.
//
// Launches the native plugin, subscribes to its metrics stream,
// and prints the first few `MetricSnapshot` payloads that arrive
// from the daemon's shm segment. Proves the full Rust -> shm ->
// C++ plugin -> Dart_PostCObject_DL -> Dart Stream pipeline.
//
// Prerequisites:
//
//   1. `agl-health-daemon` is running (default build, no ebpf
//      feature needed — proc_tier writes real memory + load
//      into the snapshot).
//   2. `libagl_health_native.so` has been built under
//      `agl-health-native/native/build/`.
//
// Invoke with Dart from the package root:
//
//   . /mnt/raid10/workspace-automation/setup_env.sh
//   cd agl-health-native
//   dart run test/shm_smoke.dart

import 'dart:async';
import 'dart:io';

import 'package:agl_health_native/agl_health_native.dart';

const _targetCount = 3;
const _timeout = Duration(seconds: 6);

Future<void> main() async {
  print('=== agl-health-native Phase 2 smoke test ===');
  final AglHealthClient client;
  try {
    client = AglHealthClient.initialize();
  } on ArgumentError catch (e) {
    print('FAIL: failed to load libagl_health_native.so: $e');
    print('      Did you run `cmake --build native/build`?');
    exit(1);
  }

  // We record the sequence at receive time rather than at teardown.
  // All MetricSnapshot instances share the same zero-copy mmap
  // backing, so reading `.sequence` later returns the *current*
  // value, not the value at the time of receipt. Capturing eagerly
  // proves fresh data arrived on every tick.
  final sequences = <int>[];
  var count = 0;
  final done = Completer<void>();

  late final StreamSubscription<MetricSnapshot> sub;
  sub = client.metrics.listen(
    (snap) {
      count++;
      sequences.add(snap.sequence);
      print('--- snapshot $count ---');
      _print(snap);
      if (count >= _targetCount && !done.isCompleted) {
        done.complete();
      }
    },
    onError: (Object err, StackTrace st) {
      print('stream error: $err');
    },
  );

  try {
    await done.future.timeout(_timeout);
  } on TimeoutException {
    print('');
    print('FAIL: timed out after ${_timeout.inSeconds}s with '
        '$count/$_targetCount snapshots.');
    print('      Is the daemon running? `./target/debug/agl-health-daemon`');
    print('      Is /dev/shm/agl-health-metrics readable?');
    await sub.cancel();
    await client.dispose();
    exit(1);
  }

  await sub.cancel();
  await client.dispose();

  print('');
  print('PASS: received $count snapshots in ${_timeout.inSeconds}s budget.');
  print('sequences: $sequences');
  if (sequences.toSet().length < sequences.length) {
    print('WARN: duplicate sequence values — data may not be advancing');
  } else {
    print('All sequences unique — fresh data on every tick.');
  }
  exit(0);
}

void _print(MetricSnapshot snap) {
  print('  magic:             0x${snap.magic.toRadixString(16)}');
  print('  version:           ${snap.version}');
  print('  sequence:          ${snap.sequence}');
  print('  snapshot_size:     ${snap.snapshotSize}');
  print('  timestamp_ns_wall: ${snap.timestampNsWall}');
  final mem = snap.memory;
  print('  memory.total:      ${_fmtBytes(mem.totalBytes)}');
  print('  memory.free:       ${_fmtBytes(mem.freeBytes)}');
  print('  memory.cached:     ${_fmtBytes(mem.cachedBytes)}');
  print('  memory.swap used:  ${_fmtBytes(mem.swapUsedBytes)}');
  final load = snap.load;
  print('  load 1/5/15:       ${load.load1.toStringAsFixed(2)} / '
      '${load.load5.toStringAsFixed(2)} / '
      '${load.load15.toStringAsFixed(2)}');
  print('  sched p50/p95/p99: ${snap.schedP50Ns} / ${snap.schedP95Ns} / '
      '${snap.schedP99Ns} ns');
}

String _fmtBytes(int b) {
  const kib = 1024;
  const mib = kib * 1024;
  const gib = mib * 1024;
  if (b >= gib) return '${(b / gib).toStringAsFixed(2)} GiB';
  if (b >= mib) return '${(b / mib).toStringAsFixed(1)} MiB';
  if (b >= kib) return '${(b / kib).toStringAsFixed(1)} KiB';
  return '$b B';
}
