// SPDX-License-Identifier: Apache-2.0
//
// Scheduler screen — runqueue-wait latency histogram with percentile
// chips and summary stats. All data comes from the SchedSnapshotFixed
// section of the shm MetricSnapshotV3 (aggregated by the daemon's
// eBPF scheduler probes). Updates at 1 Hz via the existing shm
// channel — no Unix socket needed for the histogram view.
//
// The 8-bucket histogram uses the same log-spaced boundaries as the
// kernel-side `bucket_of` function in scheduler.rs:
//   <10us, <100us, <1ms, <10ms, <100ms, <1s, <10s, >=10s

import 'dart:math' as math;

import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'metrics_notifier.dart';
import 'shared_widgets.dart';

/// Colors for each bucket, grading from green (fast) to red (slow).
const _bucketColors = [
  Color(0xFF4CAF50), // <10us  — green
  Color(0xFF8BC34A), // <100us — light green
  Color(0xFFCDDC39), // <1ms   — lime
  Color(0xFFFFEB3B), // <10ms  — yellow
  Color(0xFFFFC107), // <100ms — amber
  Color(0xFFFF9800), // <1s    — orange
  Color(0xFFFF5722), // <10s   — deep orange
  Color(0xFFF44336), // >=10s  — red
];

class SchedulerScreen extends StatelessWidget {
  const SchedulerScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Consumer<MetricsNotifier>(
        builder: (context, notifier, _) {
          final snap = notifier.current;
          if (snap == null) {
            return const Center(child: Text('Waiting for data...'));
          }
          final sched = snap.sched;
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _HistogramCard(sched: sched),
              const SizedBox(height: 12),
              _PercentileRow(sched: sched),
              const SizedBox(height: 12),
              _SummaryCard(sched: sched),
            ],
          );
        },
      ),
    );
  }
}

// ----- Histogram bar chart -----

class _HistogramCard extends StatelessWidget {
  final SchedSection sched;
  const _HistogramCard({required this.sched});

  @override
  Widget build(BuildContext context) {
    final maxVal = sched.buckets.fold<int>(0, math.max);
    return DashCard(
      title: 'Runqueue-Wait Latency Histogram',
      children: [
        SizedBox(
          height: 220,
          child: BarChart(
            BarChartData(
              alignment: BarChartAlignment.spaceAround,
              maxY: maxVal > 0 ? maxVal.toDouble() * 1.15 : 10,
              barTouchData: BarTouchData(
                touchTooltipData: BarTouchTooltipData(
                  getTooltipItem: (group, groupIdx, rod, rodIdx) {
                    return BarTooltipItem(
                      '${SchedSection.bucketLabels[groupIdx]}\n'
                      '${rod.toY.toInt()} events',
                      const TextStyle(fontSize: 12, color: Colors.white),
                    );
                  },
                ),
              ),
              titlesData: FlTitlesData(
                leftTitles: const AxisTitles(
                  sideTitles: SideTitles(showTitles: false),
                ),
                rightTitles: const AxisTitles(
                  sideTitles: SideTitles(showTitles: false),
                ),
                topTitles: const AxisTitles(
                  sideTitles: SideTitles(showTitles: false),
                ),
                bottomTitles: AxisTitles(
                  sideTitles: SideTitles(
                    showTitles: true,
                    reservedSize: 32,
                    getTitlesWidget: (value, meta) {
                      final idx = value.toInt();
                      if (idx < 0 || idx >= SchedSection.bucketLabels.length) {
                        return const SizedBox.shrink();
                      }
                      return Padding(
                        padding: const EdgeInsets.only(top: 6),
                        child: Text(
                          SchedSection.bucketLabels[idx],
                          style: const TextStyle(
                            fontSize: 10,
                            color: Colors.white54,
                          ),
                        ),
                      );
                    },
                  ),
                ),
              ),
              gridData: const FlGridData(show: false),
              borderData: FlBorderData(show: false),
              barGroups: [
                for (int i = 0; i < sched.buckets.length; i++)
                  BarChartGroupData(
                    x: i,
                    barRods: [
                      BarChartRodData(
                        toY: sched.buckets[i].toDouble(),
                        color: _bucketColors[i],
                        width: 24,
                        borderRadius: const BorderRadius.vertical(
                          top: Radius.circular(4),
                        ),
                      ),
                    ],
                  ),
              ],
            ),
            duration: Duration.zero,
          ),
        ),
      ],
    );
  }
}

// ----- Percentile chips -----

class _PercentileRow extends StatelessWidget {
  final SchedSection sched;
  const _PercentileRow({required this.sched});

  @override
  Widget build(BuildContext context) {
    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceAround,
          children: [
            _pctile('p50', sched.p50Ns),
            _pctile('p95', sched.p95Ns),
            _pctile('p99', sched.p99Ns),
            _pctile('max', sched.maxLatencyNs),
          ],
        ),
      ),
    );
  }

  Widget _pctile(String label, int ns) {
    return Column(
      children: [
        Text(
          fmtNs(ns),
          style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: 2),
        Text(
          label,
          style: const TextStyle(fontSize: 12, color: Colors.white54),
        ),
      ],
    );
  }
}

// ----- Summary stats -----

class _SummaryCard extends StatelessWidget {
  final SchedSection sched;
  const _SummaryCard({required this.sched});

  @override
  Widget build(BuildContext context) {
    return DashCard(
      title: 'Summary',
      children: [
        InfoRow('Total events', '${sched.totalCount}'),
        InfoRow('Total latency', fmtNs(sched.totalLatencyNs)),
        InfoRow('Avg latency', fmtNs(sched.avgLatencyNs.round())),
        InfoRow('Max latency', fmtNs(sched.maxLatencyNs)),
        InfoRow(
          'p50 / p95 / p99',
          '${fmtNs(sched.p50Ns)} / ${fmtNs(sched.p95Ns)} / ${fmtNs(sched.p99Ns)}',
        ),
      ],
    );
  }
}
