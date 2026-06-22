// SPDX-FileCopyrightText: 2026 AGL Contributors
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
  ///
  /// Validates the shape up front so a malformed message (wrong length
  /// or wrong element types) raises a clear [FormatException] rather than
  /// an opaque `RangeError`/`CastError` deep in field access.
  factory SecurityEventData.fromNativeList(List<Object?> list) {
    if (list.length != 7) {
      throw FormatException(
        'SecurityEventData: expected 7 elements, got ${list.length}',
      );
    }
    final pid = list[0];
    final kind = list[1];
    final severity = list[2];
    final comm = list[3];
    final uid = list[4];
    final timestampNs = list[5];
    final arg = list[6];
    if (pid is! int ||
        kind is! String ||
        severity is! String ||
        comm is! String ||
        uid is! int ||
        timestampNs is! int ||
        arg is! int) {
      throw const FormatException(
        'SecurityEventData: element type mismatch in native list',
      );
    }
    return SecurityEventData(
      pid: pid,
      kind: kind,
      severity: severity,
      comm: comm,
      uid: uid,
      timestampNs: timestampNs,
      arg: arg,
    );
  }
}
