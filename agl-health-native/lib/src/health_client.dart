// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'dbus_event_channel.dart';
import 'metrics_channel.dart';

/// Signature of the exported C `agl_health_init(void*)`.
typedef _AglHealthInitNative = IntPtr Function(Pointer<Void>);
typedef _AglHealthInitDart = int Function(Pointer<Void>);

/// Signature of the exported `agl_health_set_metrics_port(int64)`.
typedef _AglHealthSetMetricsPortNative = Void Function(Int64);
typedef _AglHealthSetMetricsPortDart = void Function(int);

/// Signature of the exported `agl_health_set_security_port(int64)`.
typedef _AglHealthSetSecurityPortNative = Void Function(Int64);
typedef _AglHealthSetSecurityPortDart = void Function(int);

/// Default library filename. Looked up under:
///
///   1. explicit path passed to [AglHealthClient.initialize]
///   2. `AGL_HEALTH_NATIVE_LIB` environment variable
///   3. the standard relative path used by the smoke test
///      (native/build/libagl_health_native.so)
///   4. `libagl_health_native.so` via the default loader search
///      path (LD_LIBRARY_PATH, rpath, etc.)
const _libraryBasename = 'libagl_health_native.so';

/// Singleton entry point for the agl-health Flutter native plugin.
///
/// Construction is private — call [AglHealthClient.initialize] at
/// app startup, then use [metrics] to subscribe to the live
/// `MetricSnapshot` stream.
///
/// Phase 2 exposes only the metrics (shm) channel. Phases 5 and 6
/// will add `Stream<KernelEvent> events` and
/// `Stream<SecurityEvent> security` getters on the same class.
class AglHealthClient {
  static AglHealthClient? _instance;

  final _AglHealthSetMetricsPortDart _setMetricsPort;
  final _AglHealthSetSecurityPortDart _setSecurityPort;
  final RawReceivePort _metricsPort;
  final RawReceivePort _securityPort;
  final StreamController<MetricSnapshot> _metricsController;
  final StreamController<SecurityEventData> _securityController;

  AglHealthClient._({
    required _AglHealthSetMetricsPortDart setMetricsPort,
    required _AglHealthSetSecurityPortDart setSecurityPort,
    required RawReceivePort metricsPort,
    required RawReceivePort securityPort,
  }) : _setMetricsPort = setMetricsPort,
       _setSecurityPort = setSecurityPort,
       _metricsPort = metricsPort,
       _securityPort = securityPort,
       _metricsController = StreamController<MetricSnapshot>.broadcast(),
       _securityController = StreamController<SecurityEventData>.broadcast();

  /// Initialize the plugin. Opens `libagl_health_native.so`, runs
  /// `Dart_InitializeApiDL`, registers a `RawReceivePort` for the
  /// metrics channel, and passes its native port to the C++
  /// side. Returns the singleton instance.
  ///
  /// Idempotent: subsequent calls return the existing instance
  /// and ignore [libraryPath].
  ///
  /// [libraryPath] — explicit path to `libagl_health_native.so`.
  /// If null, falls back to `AGL_HEALTH_NATIVE_LIB`, then the
  /// smoke-test relative path, then the default loader search.
  static AglHealthClient initialize({String? libraryPath}) {
    final existing = _instance;
    if (existing != null) return existing;

    final lib = _openLibrary(libraryPath);

    // Resolve exported symbols.
    final init = lib
        .lookup<NativeFunction<_AglHealthInitNative>>('agl_health_init')
        .asFunction<_AglHealthInitDart>();
    final setMetricsPort = lib
        .lookup<NativeFunction<_AglHealthSetMetricsPortNative>>(
          'agl_health_set_metrics_port',
        )
        .asFunction<_AglHealthSetMetricsPortDart>();
    final setSecurityPort = lib
        .lookup<NativeFunction<_AglHealthSetSecurityPortNative>>(
          'agl_health_set_security_port',
        )
        .asFunction<_AglHealthSetSecurityPortDart>();

    // Hand the Dart VM DL API bootstrap pointer to the plugin.
    final rc = init(NativeApi.initializeApiDLData);
    if (rc != 0) {
      throw StateError(
        'agl_health_init failed with code $rc (check that the '
        'plugin was built against a compatible Dart SDK)',
      );
    }

    final metricsPort = RawReceivePort();
    final securityPort = RawReceivePort();
    final client = AglHealthClient._(
      setMetricsPort: setMetricsPort,
      setSecurityPort: setSecurityPort,
      metricsPort: metricsPort,
      securityPort: securityPort,
    );
    metricsPort.handler = client._onMetricsMessage;
    securityPort.handler = client._onSecurityMessage;
    setMetricsPort(metricsPort.sendPort.nativePort);
    setSecurityPort(securityPort.sendPort.nativePort);

    _instance = client;
    return client;
  }

  /// Stream of every decoded [MetricSnapshot] pushed by the C++
  /// plugin's shm channel. Broadcast.
  Stream<MetricSnapshot> get metrics => _metricsController.stream;

  /// Stream of [SecurityEventData] received via the D-Bus signal
  /// channel. Each event corresponds to a single SecurityEvent
  /// D-Bus signal emitted by the daemon. Broadcast.
  Stream<SecurityEventData> get securityEvents => _securityController.stream;

  /// Shut down the plugin. Stops the native shm reader, closes the
  /// port, and drops the singleton so subsequent
  /// [AglHealthClient.initialize] rebuilds from scratch.
  ///
  /// Not required for normal process exit — the OS cleans up mmaps
  /// and threads. Provided for tests and hot-reload scenarios.
  Future<void> dispose() async {
    _setMetricsPort(0);
    _setSecurityPort(0);
    _metricsPort.close();
    _securityPort.close();
    await _metricsController.close();
    await _securityController.close();
    if (identical(_instance, this)) _instance = null;
  }

  void _onMetricsMessage(Object? message) {
    if (message is! Uint8List) return;
    try {
      _metricsController.add(MetricSnapshot.fromBytes(message));
    } on FormatException catch (e) {
      _metricsController.addError(e);
    }
  }

  void _onSecurityMessage(Object? message) {
    if (message is! List) return;
    try {
      _securityController.add(SecurityEventData.fromNativeList(message));
    } catch (e) {
      _securityController.addError(e);
    }
  }

  static DynamicLibrary _openLibrary(String? explicit) {
    if (explicit != null) {
      return DynamicLibrary.open(explicit);
    }
    final envPath = Platform.environment['AGL_HEALTH_NATIVE_LIB'];
    if (envPath != null && envPath.isNotEmpty) {
      return DynamicLibrary.open(envPath);
    }
    // Smoke-test convenience: when this file is run from the
    // package root, `native/build/libagl_health_native.so` is
    // where the CMake build lands.
    final smokePath = 'native/build/$_libraryBasename';
    if (File(smokePath).existsSync()) {
      return DynamicLibrary.open(smokePath);
    }
    // Last resort: default loader search path.
    return DynamicLibrary.open(_libraryBasename);
  }
}
