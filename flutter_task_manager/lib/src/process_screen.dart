// SPDX-License-Identifier: Apache-2.0
//
// Process list screen — sortable card-style list of top processes
// by CPU time. IVI-optimized with 48dp row height minimum.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'metrics_notifier.dart';
import 'shared_widgets.dart';

class ProcessScreen extends StatelessWidget {
  const ProcessScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Consumer<MetricsNotifier>(
        builder: (context, notifier, _) {
          final snap = notifier.current;
          if (snap == null) {
            return const Center(child: Text('Waiting for data...'));
          }
          final count = snap.processCount;
          if (count == 0) {
            return const Center(
              child: Text(
                'No processes\n(enable --features ebpf on the daemon)',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white38),
              ),
            );
          }
          return ListView.builder(
            padding: const EdgeInsets.all(12),
            itemCount: count + 1, // +1 for header
            itemBuilder: (context, index) {
              if (index == 0) return _header(context);
              final p = snap.process(index - 1);
              return _processRow(context, p);
            },
          );
        },
      ),
    );
  }

  Widget _header(BuildContext context) {
    final style = TextStyle(
      fontSize: 12,
      fontWeight: FontWeight.w600,
      color: Theme.of(context).colorScheme.primary,
    );
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      child: Row(
        children: [
          SizedBox(width: 60, child: Text('PID', style: style)),
          Expanded(flex: 3, child: Text('Name', style: style)),
          SizedBox(width: 90, child: Text('CPU (ns)', style: style)),
          SizedBox(width: 70, child: Text('RSS', style: style)),
          SizedBox(width: 50, child: Text('Thr', style: style)),
          SizedBox(width: 70, child: Text('Read', style: style)),
          SizedBox(width: 70, child: Text('Write', style: style)),
        ],
      ),
    );
  }

  Widget _processRow(BuildContext context, ProcessStatsSection p) {
    return Container(
      height: 48,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: Colors.white10, width: 0.5)),
      ),
      child: Row(
        children: [
          SizedBox(
            width: 60,
            child: Text('${p.pid}', style: const TextStyle(fontSize: 13)),
          ),
          Expanded(
            flex: 3,
            child: Text(
              p.comm.isEmpty ? '?' : p.comm,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 13),
            ),
          ),
          SizedBox(
            width: 90,
            child: Text(
              fmtNs(p.cpuUserNs),
              style: const TextStyle(
                fontSize: 12,
                fontFeatures: [FontFeature.tabularFigures()],
              ),
            ),
          ),
          SizedBox(
            width: 70,
            child: Text(
              fmtBytes(p.memRssBytes),
              style: const TextStyle(fontSize: 12),
            ),
          ),
          SizedBox(
            width: 50,
            child: Text(
              '${p.threadCount}',
              style: const TextStyle(fontSize: 12),
            ),
          ),
          SizedBox(
            width: 70,
            child: Text(
              fmtBytes(p.readBytes),
              style: const TextStyle(fontSize: 12),
            ),
          ),
          SizedBox(
            width: 70,
            child: Text(
              fmtBytes(p.writeBytes),
              style: const TextStyle(fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }
}
