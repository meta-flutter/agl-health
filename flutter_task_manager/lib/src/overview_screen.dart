// SPDX-License-Identifier: Apache-2.0
//
// Overview screen — scrollable column of cards showing system-wide
// gauges. Includes CPU load, memory, swap, disk I/O, per-core CPU,
// and system info sections. All data from shm via MetricsNotifier.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'metrics_notifier.dart';
import 'shared_widgets.dart';

class OverviewScreen extends StatelessWidget {
  const OverviewScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return SafeArea(
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
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              // Top row: load + memory side by side.
              IntrinsicHeight(
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Expanded(
                        child: _LoadCard(
                            snap: snap, history: notifier.loadHistory)),
                    const SizedBox(width: 12),
                    Expanded(
                        child: _MemoryCard(
                            snap: snap,
                            history: notifier.memUsedPctHistory)),
                  ],
                ),
              ),
              const SizedBox(height: 12),
              // Second row: swap + system info.
              IntrinsicHeight(
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Expanded(child: _SwapCard(snap: snap)),
                    const SizedBox(width: 12),
                    Expanded(child: _SystemCard(snap: snap)),
                  ],
                ),
              ),
              // Disk I/O devices.
              if (snap.blockDeviceCount > 0) ...[
                const SizedBox(height: 12),
                Text('Block Devices',
                    style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 6),
                for (int i = 0; i < snap.blockDeviceCount; i++)
                  _diskTile(snap.blockDevice(i)),
              ],
              // Per-core CPU (if BPF data present).
              if (snap.cpuCount > 0) ...[
                const SizedBox(height: 12),
                Text('CPU Cores (${snap.cpuCount})',
                    style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 6),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    for (int i = 0; i < snap.cpuCount; i++)
                      _cpuChip(snap.cpu(i)),
                  ],
                ),
              ],
            ],
          );
        },
      ),
    );
  }

  Widget _diskTile(BlockStatsSection b) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(
          children: [
            SizedBox(
              width: 60,
              child: Text('${b.deviceMajor}:${b.deviceMinor}',
                  style: const TextStyle(
                      fontSize: 13, fontWeight: FontWeight.w600)),
            ),
            Expanded(
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: [
                  _diskStat('Read', fmtBytes(b.readBytes), '${b.readsCompleted} ops'),
                  _diskStat('Write', fmtBytes(b.writeBytes), '${b.writesCompleted} ops'),
                  _diskStat('R lat', fmtNs(b.readLatencyNs), ''),
                  _diskStat('W lat', fmtNs(b.writeLatencyNs), ''),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _diskStat(String label, String value, String sub) {
    return Column(
      children: [
        Text(value, style: const TextStyle(fontSize: 12)),
        Text(label,
            style: const TextStyle(fontSize: 10, color: Colors.white54)),
        if (sub.isNotEmpty)
          Text(sub,
              style: const TextStyle(fontSize: 9, color: Colors.white30)),
      ],
    );
  }

  Widget _cpuChip(CpuStatsSection c) {
    return Chip(
      label: Text(
        'CPU ${c.cpuId}  irq=${fmtNs(c.irqNs)}  si=${fmtNs(c.softirqNs)}',
        style: const TextStyle(fontSize: 11),
      ),
      visualDensity: VisualDensity.compact,
    );
  }
}

// ----- cards (use shared widgets) -----

class _LoadCard extends StatelessWidget {
  final MetricSnapshot snap;
  final List<double> history;
  const _LoadCard({required this.snap, required this.history});

  @override
  Widget build(BuildContext context) {
    final load = snap.load;
    // Stack layout: sparkline fills the card background, text
    // overlays on top so high-load sparklines aren't clipped.
    return DashCard(title: 'CPU Load', children: [
      Text(
        '${load.load1.toStringAsFixed(2)} / '
        '${load.load5.toStringAsFixed(2)} / '
        '${load.load15.toStringAsFixed(2)}',
        style: Theme.of(context).textTheme.titleLarge,
      ),
      const SizedBox(height: 2),
      Text('1 min / 5 min / 15 min',
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: Colors.white54)),
      const SizedBox(height: 6),
      SizedBox(
          height: 60,
          child: Sparkline(data: history, color: Colors.blueAccent)),
    ]);
  }
}

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
    return DashCard(title: 'Memory', children: [
      Text('${fmtBytes(used)} / ${fmtBytes(total)}',
          style: Theme.of(context).textTheme.titleLarge),
      const SizedBox(height: 6),
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
      const SizedBox(height: 6),
      SizedBox(
          height: 60,
          child: Sparkline(data: history, color: Colors.greenAccent)),
    ]);
  }
}

class _SwapCard extends StatelessWidget {
  final MetricSnapshot snap;
  const _SwapCard({required this.snap});

  @override
  Widget build(BuildContext context) {
    final mem = snap.memory;
    final total = mem.swapUsedBytes + mem.swapFreeBytes;
    final pct = total > 0 ? mem.swapUsedBytes / total : 0.0;
    return DashCard(title: 'Swap', children: [
      Text('${fmtBytes(mem.swapUsedBytes)} / ${fmtBytes(total)}',
          style: Theme.of(context).textTheme.titleLarge),
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
        '${(pct * 100).toStringAsFixed(1)}% used  |  cached: ${fmtBytes(mem.cachedBytes)}',
        style: Theme.of(context)
            .textTheme
            .bodySmall
            ?.copyWith(color: Colors.white54),
      ),
    ]);
  }
}

class _SystemCard extends StatelessWidget {
  final MetricSnapshot snap;
  const _SystemCard({required this.snap});

  @override
  Widget build(BuildContext context) {
    final mem = snap.memory;
    return DashCard(title: 'System', children: [
      InfoRow('Sequence', '${snap.sequence}'),
      InfoRow('Version', '${snap.version}'),
      InfoRow('Slab', fmtBytes(mem.slabBytes)),
      InfoRow('OOM kills', '${mem.oomKillsTotal}'),
      InfoRow(
          'PSI mem',
          '${mem.psiSomePct.toStringAsFixed(1)}% some / '
              '${mem.psiFullPct.toStringAsFixed(1)}% full'),
      InfoRow('Sched p99', fmtNs(snap.schedP99Ns)),
    ]);
  }
}
