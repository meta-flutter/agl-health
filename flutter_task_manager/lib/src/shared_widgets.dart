// SPDX-License-Identifier: Apache-2.0
//
// Reusable widgets shared across Overview, Process, Network, and Disk screens.

import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';

class DashCard extends StatelessWidget {
  final String title;
  final List<Widget> children;
  const DashCard({super.key, required this.title, required this.children});

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
            Text(title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 6),
            ...children,
          ],
        ),
      ),
    );
  }
}

class InfoRow extends StatelessWidget {
  final String label;
  final String value;
  const InfoRow(this.label, this.value, {super.key});

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

class Sparkline extends StatelessWidget {
  final List<double> data;
  final Color color;
  const Sparkline({super.key, required this.data, required this.color});

  @override
  Widget build(BuildContext context) {
    if (data.length < 2) return const SizedBox.shrink();
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
      duration: Duration.zero,
    );
  }
}

/// Chip showing a single counter with a label. Used for TCP state chips
/// and security counters.
class StatChip extends StatelessWidget {
  final String label;
  final int value;
  final Color? color;
  const StatChip(this.label, this.value, {super.key, this.color});

  @override
  Widget build(BuildContext context) {
    return Chip(
      label: Text('$label: $value',
          style: TextStyle(fontSize: 12, color: color ?? Colors.white70)),
      visualDensity: VisualDensity.compact,
      padding: const EdgeInsets.symmetric(horizontal: 4),
    );
  }
}

String fmtBytes(int bytes) {
  const gib = 1024 * 1024 * 1024;
  const mib = 1024 * 1024;
  const kib = 1024;
  if (bytes >= gib) return '${(bytes / gib).toStringAsFixed(1)} GiB';
  if (bytes >= mib) return '${(bytes / mib).toStringAsFixed(1)} MiB';
  if (bytes >= kib) return '${(bytes / kib).toStringAsFixed(1)} KiB';
  return '$bytes B';
}

String fmtNs(int ns) {
  if (ns >= 1000000000) return '${(ns / 1e9).toStringAsFixed(2)} s';
  if (ns >= 1000000) return '${(ns / 1e6).toStringAsFixed(1)} ms';
  if (ns >= 1000) return '${(ns / 1e3).toStringAsFixed(0)} us';
  return '$ns ns';
}
