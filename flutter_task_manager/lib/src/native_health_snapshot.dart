// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

import 'package:agl_health_native/agl_health_native.dart';

import 'health_snapshot.dart';

/// Wraps a native-plugin [MetricSnapshot] as a [HealthSnapshot].
///
/// All getters forward to the underlying snapshot; no copies are made.
class NativeHealthSnapshot implements HealthSnapshot {
  final MetricSnapshot _snap;
  const NativeHealthSnapshot(this._snap);

  @override
  int get sequence => _snap.sequence;

  @override
  int get version => _snap.version;

  @override
  int get timestampNsWall => _snap.timestampNsWall;

  @override
  MemorySection get memory => _snap.memory;

  @override
  LoadSection get load => _snap.load;

  @override
  SchedSection get sched => _snap.sched;

  @override
  TcpStateSection get tcp => _snap.tcp;

  @override
  SecuritySection get security => _snap.security;

  @override
  int get schedP99Ns => _snap.schedP99Ns;

  @override
  int get cpuCount => _snap.cpuCount;

  @override
  CpuStatsSection cpu(int i) => _snap.cpu(i);

  @override
  int get netIfaceCount => _snap.netIfaceCount;

  @override
  NetIfaceSection netIface(int i) => _snap.netIface(i);

  @override
  int get blockDeviceCount => _snap.blockDeviceCount;

  @override
  BlockStatsSection blockDevice(int i) => _snap.blockDevice(i);

  @override
  int get processCount => _snap.processCount;

  @override
  ProcessStatsSection process(int i) => _snap.process(i);

  @override
  int get schedCpuCount => _snap.schedCpuCount;

  @override
  SchedSection schedPerCpu(int i) => _snap.schedPerCpu(i);
}
