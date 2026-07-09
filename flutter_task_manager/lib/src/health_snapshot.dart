// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

import 'package:agl_health_native/agl_health_native.dart';

/// Common interface for metric snapshots regardless of transport.
///
/// Both the native shm path (via [NativeHealthSnapshot]) and the HTTP
/// polling path (via [HttpMetricSnapshot]) implement this interface so
/// widgets are transport-agnostic.
abstract interface class HealthSnapshot {
  int get sequence;
  int get version;
  int get timestampNsWall;

  MemorySection get memory;
  LoadSection get load;
  SchedSection get sched;
  TcpStateSection get tcp;
  SecuritySection get security;

  // Convenience getter present on MetricSnapshot for backward compat.
  int get schedP99Ns;

  int get cpuCount;
  CpuStatsSection cpu(int i);

  int get netIfaceCount;
  NetIfaceSection netIface(int i);

  int get blockDeviceCount;
  BlockStatsSection blockDevice(int i);

  int get processCount;
  ProcessStatsSection process(int i);

  int get schedCpuCount;
  SchedSection schedPerCpu(int i);
}
