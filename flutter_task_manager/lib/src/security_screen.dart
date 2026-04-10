// SPDX-License-Identifier: Apache-2.0
//
// Security screen — cumulative counts of security-relevant syscall
// events detected by the daemon's eBPF probes. Each counter
// corresponds to a specific syscall pattern that is interesting from
// a security perspective (see security.rs in the eBPF crate).
//
// Phase 6 scope: counters from the shm snapshot only. The live
// event feed (showing individual events as they happen with pid,
// comm, severity, and process lineage) will be added when the D-Bus
// signal channel lands in a future pass.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'metrics_notifier.dart';
import 'shared_widgets.dart';

class SecurityScreen extends StatelessWidget {
  const SecurityScreen({super.key});

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
              _EventFeedPlaceholder(),
            ],
          );
        },
      ),
    );
  }
}

// ----- Counter grid -----

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
          description: 'Process control calls (PR_SET_DUMPABLE etc)',
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
                  Icon(icon, size: 20, color: count > 0 ? color : Colors.white24),
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
              Text(label,
                  style: const TextStyle(
                      fontSize: 13, fontWeight: FontWeight.w500)),
              const SizedBox(height: 2),
              Text(description,
                  style:
                      const TextStyle(fontSize: 10, color: Colors.white38)),
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

// ----- Event feed placeholder -----

class _EventFeedPlaceholder extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: const Padding(
        padding: EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(Icons.rss_feed, size: 32, color: Colors.white24),
            SizedBox(height: 8),
            Text(
              'Live event feed\ncoming with D-Bus channel',
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.white38, fontSize: 13),
            ),
          ],
        ),
      ),
    );
  }
}
