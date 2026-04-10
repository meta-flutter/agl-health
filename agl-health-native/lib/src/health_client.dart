// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'metrics_channel.dart';

/// Signature of the exported C `agl_health_init(void*)`.
typedef _AglHealthInitNative = IntPtr Function(Pointer<Void>);
typedef _AglHealthInitDart = int Function(Pointer<Void>);

/// Signature of the exported `agl_health_set_metrics_port(int64)`.
typedef _AglHealthSetMetricsPortNative = Void Function(Int64);
typedef _AglHealthSetMetricsPortDart = void Function(int);

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

  final DynamicLibrary _lib;
  final _AglHealthSetMetricsPortDart _setMetricsPort;
  final RawReceivePort _metricsPort;
  final StreamController<MetricSnapshot> _metricsController;

  AglHealthClient._({
    required DynamicLibrary lib,
    required _AglHealthSetMetricsPortDart setMetricsPort,
    required RawReceivePort metricsPort,
  })  : _lib = lib,
        _setMetricsPort = setMetricsPort,
        _metricsPort = metricsPort,
        _metricsController = StreamController<MetricSnapshot>.broadcast();

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
            'agl_health_set_metrics_port')
        .asFunction<_AglHealthSetMetricsPortDart>();

    // Hand the Dart VM DL API bootstrap pointer to the plugin.
    // Without this, Dart_PostCObject_DL would segfault on first use.
    final rc = init(NativeApi.initializeApiDLData);
    if (rc != 0) {
      throw StateError(
          'agl_health_init failed with code $rc (check that the '
          'plugin was built against a compatible Dart SDK)');
    }

    // Create the RawReceivePort and wire it to the C++ side.
    // RawReceivePort is preferred over ReceivePort here because
    // the handler runs synchronously with the message delivery,
    // which minimises the window during which the shm mmap could
    // be written by the daemon between post and read.
    final metricsPort = RawReceivePort();
    final client = AglHealthClient._(
      lib: lib,
      setMetricsPort: setMetricsPort,
      metricsPort: metricsPort,
    );
    metricsPort.handler = client._onMetricsMessage;
    setMetricsPort(metricsPort.sendPort.nativePort);

    _instance = client;
    return client;
  }

  /// Stream of every decoded [MetricSnapshot] pushed by the C++
  /// plugin. Broadcast — multiple listeners get the same events
  /// without re-triggering the native side.
  ///
  /// If [MetricSnapshot.fromBytes] rejects a payload (layout drift
  /// or a partial write during a seqlock race) the error is added
  /// to the stream rather than thrown; listeners can decide whether
  /// to log, reset, or ignore.
  Stream<MetricSnapshot> get metrics => _metricsController.stream;

  /// Shut down the plugin. Stops the native shm reader, closes the
  /// port, and drops the singleton so subsequent
  /// [AglHealthClient.initialize] rebuilds from scratch.
  ///
  /// Not required for normal process exit — the OS cleans up mmaps
  /// and threads. Provided for tests and hot-reload scenarios.
  Future<void> dispose() async {
    _setMetricsPort(0);
    _metricsPort.close();
    await _metricsController.close();
    if (identical(_instance, this)) _instance = null;
  }

  void _onMetricsMessage(Object? message) {
    if (message is! Uint8List) {
      return;
    }
    try {
      _metricsController.add(MetricSnapshot.fromBytes(message));
    } on FormatException catch (e) {
      _metricsController.addError(e);
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
