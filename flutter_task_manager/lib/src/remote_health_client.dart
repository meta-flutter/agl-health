// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'health_snapshot.dart';
import 'http_metric_snapshot.dart';

/// Fetches metrics from the daemon's HTTP API and security events from
/// its WebSocket endpoint.
///
/// Activate by setting [AGL_HEALTH_REMOTE_URL] in the environment, e.g.:
///   AGL_HEALTH_REMOTE_URL=http://localhost:7777 flutter run -d linux
///
/// The metrics stream polls [GET /metrics] at 1 Hz. The security events
/// stream connects to [ws:///events/stream?subsystem=security] and
/// reconnects automatically on disconnect.
class RemoteHealthClient {
  final String _baseUrl;
  final String _wsUrl;

  final _metricsController =
      StreamController<HealthSnapshot>.broadcast();
  final _securityController =
      StreamController<SecurityEventData>.broadcast();

  final _http = HttpClient();
  Timer? _pollTimer;
  WebSocket? _ws;
  bool _disposed = false;

  RemoteHealthClient._(this._baseUrl, this._wsUrl);

  static RemoteHealthClient initialize(String baseUrl) {
    final wsUrl = baseUrl
        .replaceFirst(RegExp(r'^http'), 'ws')
        .replaceFirst(RegExp(r'^https'), 'wss');
    final client = RemoteHealthClient._(baseUrl, wsUrl);
    client._startPolling();
    client._connectWs();
    return client;
  }

  Stream<HealthSnapshot> get metrics => _metricsController.stream;
  Stream<SecurityEventData> get securityEvents => _securityController.stream;

  Future<void> dispose() async {
    _disposed = true;
    _pollTimer?.cancel();
    _ws?.close();
    _http.close(force: true);
    await _metricsController.close();
    await _securityController.close();
  }

  // ---- metrics polling ----

  void _startPolling() {
    _pollTimer = Timer.periodic(const Duration(seconds: 1), (_) => _poll());
    _poll(); // immediate first fetch
  }

  Future<void> _poll() async {
    if (_disposed) return;
    try {
      final uri = Uri.parse('$_baseUrl/metrics');
      final req = await _http.getUrl(uri);
      final resp = await req.close();
      final body = await resp.transform(utf8.decoder).join();
      if (resp.statusCode != 200) {
        debugPrint('remote: /metrics returned ${resp.statusCode}');
        return;
      }
      final json = jsonDecode(body) as Map<String, dynamic>;
      if (!_disposed) {
        _metricsController.add(HttpMetricSnapshot(json));
      }
    } catch (e) {
      debugPrint('remote: metrics poll error: $e');
    }
  }

  // ---- WebSocket security events ----

  void _connectWs() {
    if (_disposed) return;
    final uri = '$_wsUrl/events/stream?subsystem=security';
    WebSocket.connect(uri).then((ws) {
      if (_disposed) {
        ws.close();
        return;
      }
      _ws = ws;
      ws.listen(
        (data) {
          if (_disposed || data is! String) return;
          try {
            final map = jsonDecode(data) as Map<String, dynamic>;
            if (map['subsystem'] != 'security') return;
            _securityController.add(SecurityEventData(
              pid: _int(map['pid']),
              kind: (map['kind'] as String?) ?? 'Unknown',
              severity: (map['severity'] as String?) ?? 'info',
              comm: (map['comm'] as String?) ?? '',
              uid: _int(map['uid']),
              timestampNs: _int(map['timestamp_ns']),
              arg: _int(map['arg']),
            ));
          } catch (e) {
            debugPrint('remote: security event parse error: $e');
          }
        },
        onDone: () {
          _ws = null;
          _scheduleWsReconnect();
        },
        onError: (Object e) {
          debugPrint('remote: WebSocket error: $e');
          _ws = null;
          _scheduleWsReconnect();
        },
        cancelOnError: true,
      );
    }).catchError((Object e) {
      debugPrint('remote: WebSocket connect error: $e');
      _scheduleWsReconnect();
    });
  }

  void _scheduleWsReconnect() {
    if (_disposed) return;
    Timer(const Duration(seconds: 2), _connectWs);
  }

  static int _int(dynamic v) {
    if (v is int) return v;
    if (v is double) return v.toInt();
    return 0;
  }
}
