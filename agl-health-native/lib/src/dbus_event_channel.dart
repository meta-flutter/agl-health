// SPDX-License-Identifier: Apache-2.0
//
// Dart model for security events received from the D-Bus signal
// channel (com.agl.health.Events.SecurityEvent).
//
// The C++ plugin decodes the D-Bus signal arguments and posts them
// as a Dart_CObject_kArray with 7 elements:
//   [0] int32  pid
//   [1] string kind       ("Ptrace", "MemfdCreate", etc)
//   [2] string severity   ("info", "warn", "critical")
//   [3] string comm
//   [4] int32  uid
//   [5] int64  timestamp_ns
//   [6] int64  arg

/// A single security event received via the D-Bus signal channel.
class SecurityEventData {
  final int pid;
  final String kind;
  final String severity;
  final String comm;
  final int uid;
  final int timestampNs;
  final int arg;

  const SecurityEventData({
    required this.pid,
    required this.kind,
    required this.severity,
    required this.comm,
    required this.uid,
    required this.timestampNs,
    required this.arg,
  });

  /// Parse from the raw List posted by the C++ plugin via
  /// Dart_PostCObject_DL(Dart_CObject_kArray).
  factory SecurityEventData.fromNativeList(List<Object?> list) {
    return SecurityEventData(
      pid: list[0] as int,
      kind: list[1] as String,
      severity: list[2] as String,
      comm: list[3] as String,
      uid: list[4] as int,
      timestampNs: list[5] as int,
      arg: list[6] as int,
    );
  }
}
