// SPDX-License-Identifier: Apache-2.0
//
// Security screen — cumulative counters from shm + live event feed
// from the D-Bus signal channel. Counters update at 1 Hz (shm);
// individual events arrive in real time via com.agl.health.Events
// .SecurityEvent D-Bus signals.

import 'dart:async';
import 'dart:collection';

import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';
import 'package:provider/provider.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'metrics_notifier.dart';
import 'shared_widgets.dart';

class SecurityScreen extends StatefulWidget {
  const SecurityScreen({super.key});

  @override
  State<SecurityScreen> createState() => _SecurityScreenState();
}

class _SecurityScreenState extends State<SecurityScreen> {
  static const _maxEvents = 100;
  final _events = Queue<SecurityEventData>();
  StreamSubscription<SecurityEventData>? _sub;
  bool _pendingRebuild = false;

  @override
  void initState() {
    super.initState();
    // Subscribe to the D-Bus security event stream from the native
    // plugin. The buffer is updated synchronously per event, but the
    // rebuild is coalesced to the next frame (like MetricsNotifier) so a
    // burst of events triggers a single rebuild instead of one per event.
    _sub = AglHealthClient.initialize().securityEvents.listen(
      (event) {
        if (_events.length >= _maxEvents) _events.removeFirst();
        _events.addLast(event);
        if (_pendingRebuild) return;
        _pendingRebuild = true;
        SchedulerBinding.instance.addPostFrameCallback((_) {
          _pendingRebuild = false;
          if (mounted) setState(() {});
        });
      },
      onError: (Object error, StackTrace _) {
        // A malformed event must not tear down the subscription.
        debugPrint('security event stream error: $error');
      },
    );
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Consumer<MetricsNotifier>(
        builder: (context, notifier, _) {
          final snap = notifier.current;
          if (snap == null) {
            return const Center(child: Text('Waiting for data...'));
          }
          final sec = snap.security;
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _CounterGrid(sec: sec),
              const SizedBox(height: 16),
              _DetailCard(sec: sec),
              const SizedBox(height: 16),
              _EventFeed(events: _events),
            ],
          );
        },
      ),
    );
  }
}

// ----- Counter grid (unchanged from Phase 6) -----

class _CounterGrid extends StatelessWidget {
  final SecuritySection sec;
  const _CounterGrid({required this.sec});

  @override
  Widget build(BuildContext context) {
    return Wrap(
      spacing: 10,
      runSpacing: 10,
      children: [
        _CounterTile(
          label: 'ptrace',
          count: sec.ptrace,
          icon: Icons.bug_report,
          color: Colors.redAccent,
          description: 'Debugger attach / injection attempts',
        ),
        _CounterTile(
          label: 'memfd_create',
          count: sec.memfdCreate,
          icon: Icons.memory,
          color: Colors.orangeAccent,
          description: 'Fileless execution indicators',
        ),
        _CounterTile(
          label: 'setuid',
          count: sec.setuid,
          icon: Icons.admin_panel_settings,
          color: Colors.amber,
          description: 'Privilege escalation attempts',
        ),
        _CounterTile(
          label: 'prctl',
          count: sec.prctl,
          icon: Icons.visibility_off,
          color: Colors.deepOrange,
          description: 'Process control calls',
        ),
        _CounterTile(
          label: 'exec_anomaly',
          count: sec.execAnomaly,
          icon: Icons.warning,
          color: Colors.red,
          description: 'Unexpected exec from known services',
        ),
        _CounterTile(
          label: 'capability_use',
          count: sec.capabilityUse,
          icon: Icons.shield,
          color: Colors.blueAccent,
          description: 'CAP_NET_ADMIN, CAP_SYS_ADMIN etc',
        ),
      ],
    );
  }
}

class _CounterTile extends StatelessWidget {
  final String label;
  final int count;
  final IconData icon;
  final Color color;
  final String description;

  const _CounterTile({
    required this.label,
    required this.count,
    required this.icon,
    required this.color,
    required this.description,
  });

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 180,
      child: Card(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    icon,
                    size: 20,
                    color: count > 0 ? color : Colors.white24,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    '$count',
                    style: TextStyle(
                      fontSize: 22,
                      fontWeight: FontWeight.bold,
                      color: count > 0 ? color : Colors.white38,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              Text(
                label,
                style: const TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                description,
                style: const TextStyle(fontSize: 10, color: Colors.white38),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ----- Detail summary -----

class _DetailCard extends StatelessWidget {
  final SecuritySection sec;
  const _DetailCard({required this.sec});

  @override
  Widget build(BuildContext context) {
    return DashCard(
      title: 'Summary',
      children: [
        InfoRow('Total events', '${sec.total}'),
        InfoRow('ptrace', '${sec.ptrace}'),
        InfoRow('memfd_create', '${sec.memfdCreate}'),
        InfoRow('setuid', '${sec.setuid}'),
        InfoRow('prctl', '${sec.prctl}'),
        InfoRow('exec_anomaly', '${sec.execAnomaly}'),
        InfoRow('capability_use', '${sec.capabilityUse}'),
      ],
    );
  }
}

// ----- Live event feed -----

class _EventFeed extends StatelessWidget {
  final Queue<SecurityEventData> events;
  const _EventFeed({required this.events});

  @override
  Widget build(BuildContext context) {
    if (events.isEmpty) {
      return Card(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: const Padding(
          padding: EdgeInsets.all(24),
          child: Column(
            children: [
              Icon(Icons.rss_feed, size: 32, color: Colors.white24),
              SizedBox(height: 8),
              Text(
                'No security events yet\n'
                'Events appear here in real time via D-Bus',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white38, fontSize: 13),
              ),
            ],
          ),
        ),
      );
    }

    return DashCard(
      title: 'Live Events (${events.length})',
      children: [
        // newest first; `reversed` iterates without a second list copy.
        for (final ev in events.toList().reversed) _eventRow(ev),
      ],
    );
  }

  Widget _eventRow(SecurityEventData ev) {
    final severityColor = switch (ev.severity) {
      'critical' => Colors.red,
      'warn' => Colors.amber,
      _ => Colors.white54,
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          Icon(Icons.circle, size: 8, color: severityColor),
          const SizedBox(width: 8),
          SizedBox(
            width: 100,
            child: Text(
              ev.kind,
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            ),
          ),
          SizedBox(
            width: 60,
            child: Text(
              'pid ${ev.pid}',
              style: const TextStyle(fontSize: 11, color: Colors.white54),
            ),
          ),
          Expanded(
            child: Text(
              ev.comm,
              style: const TextStyle(fontSize: 11),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }
}
