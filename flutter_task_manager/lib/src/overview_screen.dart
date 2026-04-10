// SPDX-License-Identifier: Apache-2.0
//
// Overview screen — 2x2 card grid showing system-wide gauges from
// the daemon's shm channel. All data flows through MetricsNotifier
// which coalesces updates to the vsync boundary.

import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'metrics_notifier.dart';

class OverviewScreen extends StatelessWidget {
  const OverviewScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Consumer<MetricsNotifier>(
          builder: (context, notifier, _) {
            final snap = notifier.current;
            if (snap == null) {
              return const Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    CircularProgressIndicator(),
                    SizedBox(height: 16),
                    Text('Waiting for daemon...'),
                  ],
                ),
              );
            }
            return GridView.count(
              crossAxisCount: 2,
              mainAxisSpacing: 12,
              crossAxisSpacing: 12,
              childAspectRatio: 1.6,
              children: [
                _LoadCard(snap: snap, history: notifier.loadHistory),
                _MemoryCard(snap: snap, history: notifier.memUsedPctHistory),
                _SwapCard(snap: snap),
                _SystemCard(snap: snap),
              ],
            );
          },
        ),
      ),
    );
  }
}

// ----- CPU Load card -----

class _LoadCard extends StatelessWidget {
  final MetricSnapshot snap;
  final List<double> history;
  const _LoadCard({required this.snap, required this.history});

  @override
  Widget build(BuildContext context) {
    final load = snap.load;
    return _DashCard(
      title: 'CPU Load',
      children: [
        Text(
          '${load.load1.toStringAsFixed(2)} / '
          '${load.load5.toStringAsFixed(2)} / '
          '${load.load15.toStringAsFixed(2)}',
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const SizedBox(height: 4),
        Text('1 min / 5 min / 15 min',
            style: Theme.of(context)
                .textTheme
                .bodySmall
                ?.copyWith(color: Colors.white54)),
        const SizedBox(height: 8),
        Expanded(child: _Sparkline(data: history, color: Colors.blueAccent)),
      ],
    );
  }
}

// ----- Memory card -----

class _MemoryCard extends StatelessWidget {
  final MetricSnapshot snap;
  final List<double> history;
  const _MemoryCard({required this.snap, required this.history});

  @override
  Widget build(BuildContext context) {
    final mem = snap.memory;
    final total = mem.totalBytes;
    final used = total > 0 ? total - mem.freeBytes : 0;
    final pct = total > 0 ? used / total : 0.0;

    return _DashCard(
      title: 'Memory',
      children: [
        Text(
          '${_fmtGiB(used)} / ${_fmtGiB(total)}',
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        ClipRRect(
          borderRadius: BorderRadius.circular(4),
          child: LinearProgressIndicator(
            value: pct,
            minHeight: 14,
            backgroundColor: Colors.white12,
            color: pct > 0.9
                ? Colors.redAccent
                : pct > 0.7
                    ? Colors.orangeAccent
                    : Colors.greenAccent,
          ),
        ),
        const SizedBox(height: 4),
        Text('${(pct * 100).toStringAsFixed(1)}% used',
            style: Theme.of(context)
                .textTheme
                .bodySmall
                ?.copyWith(color: Colors.white54)),
        const SizedBox(height: 4),
        Expanded(
            child: _Sparkline(data: history, color: Colors.greenAccent)),
      ],
    );
  }
}

// ----- Swap card -----

class _SwapCard extends StatelessWidget {
  final MetricSnapshot snap;
  const _SwapCard({required this.snap});

  @override
  Widget build(BuildContext context) {
    final mem = snap.memory;
    final total = mem.swapUsedBytes + mem.swapFreeBytes;
    final pct = total > 0 ? mem.swapUsedBytes / total : 0.0;

    return _DashCard(
      title: 'Swap',
      children: [
        Text(
          '${_fmtGiB(mem.swapUsedBytes)} / ${_fmtGiB(total)}',
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        ClipRRect(
          borderRadius: BorderRadius.circular(4),
          child: LinearProgressIndicator(
            value: pct,
            minHeight: 14,
            backgroundColor: Colors.white12,
            color: pct > 0.8 ? Colors.redAccent : Colors.amber,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          '${(pct * 100).toStringAsFixed(1)}% used  |  '
          'cached: ${_fmtGiB(mem.cachedBytes)}',
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: Colors.white54),
        ),
      ],
    );
  }
}

// ----- System info card -----

class _SystemCard extends StatelessWidget {
  final MetricSnapshot snap;
  const _SystemCard({required this.snap});

  @override
  Widget build(BuildContext context) {
    final mem = snap.memory;
    return _DashCard(
      title: 'System',
      children: [
        _InfoRow('Sequence', '${snap.sequence}'),
        _InfoRow('Version', '${snap.version}'),
        _InfoRow('Slab', _fmtGiB(mem.slabBytes)),
        _InfoRow('OOM kills', '${mem.oomKillsTotal}'),
        _InfoRow(
            'PSI mem',
            '${mem.psiSomePct.toStringAsFixed(1)}% some / '
                '${mem.psiFullPct.toStringAsFixed(1)}% full'),
        _InfoRow('Sched p99', '${snap.schedP99Ns} ns'),
      ],
    );
  }
}

// ----- shared widgets -----

class _DashCard extends StatelessWidget {
  final String title;
  final List<Widget> children;
  const _DashCard({required this.title, required this.children});

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 2,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title,
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 6),
            ...children,
          ],
        ),
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;
  const _InfoRow(this.label, this.value);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label,
              style: const TextStyle(fontSize: 12, color: Colors.white54)),
          Text(value, style: const TextStyle(fontSize: 12)),
        ],
      ),
    );
  }
}

class _Sparkline extends StatelessWidget {
  final List<double> data;
  final Color color;
  const _Sparkline({required this.data, required this.color});

  @override
  Widget build(BuildContext context) {
    if (data.length < 2) {
      return const SizedBox.shrink();
    }
    final spots = <FlSpot>[
      for (int i = 0; i < data.length; i++) FlSpot(i.toDouble(), data[i]),
    ];
    return LineChart(
      LineChartData(
        gridData: const FlGridData(show: false),
        titlesData: const FlTitlesData(show: false),
        borderData: FlBorderData(show: false),
        clipData: const FlClipData.all(),
        lineTouchData: const LineTouchData(enabled: false),
        minY: 0,
        lineBarsData: [
          LineChartBarData(
            spots: spots,
            isCurved: true,
            curveSmoothness: 0.2,
            color: color,
            barWidth: 2,
            dotData: const FlDotData(show: false),
            belowBarData: BarAreaData(
              show: true,
              color: color.withValues(alpha: 0.15),
            ),
          ),
        ],
      ),
      duration: Duration.zero, // no animation — data updates every second
    );
  }
}

String _fmtGiB(int bytes) {
  const gib = 1024 * 1024 * 1024;
  const mib = 1024 * 1024;
  if (bytes >= gib) return '${(bytes / gib).toStringAsFixed(1)} GiB';
  if (bytes >= mib) return '${(bytes / mib).toStringAsFixed(0)} MiB';
  return '$bytes B';
}
