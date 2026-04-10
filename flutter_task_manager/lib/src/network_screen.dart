// SPDX-License-Identifier: Apache-2.0
//
// Network screen — TCP state chips + per-interface cards.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'metrics_notifier.dart';
import 'shared_widgets.dart';

class NetworkScreen extends StatelessWidget {
  const NetworkScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Consumer<MetricsNotifier>(
        builder: (context, notifier, _) {
          final snap = notifier.current;
          if (snap == null) {
            return const Center(child: Text('Waiting for data...'));
          }
          return ListView(
            padding: const EdgeInsets.all(12),
            children: [
              _tcpStateRow(context, snap),
              const SizedBox(height: 12),
              ..._ifaceCards(context, snap),
            ],
          );
        },
      ),
    );
  }

  Widget _tcpStateRow(BuildContext context, MetricSnapshot snap) {
    final tcp = snap.tcp;
    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('TCP State', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 4,
              children: [
                StatChip('ESTABLISHED', tcp.established,
                    color: Colors.greenAccent),
                StatChip('LISTEN', tcp.listen, color: Colors.blueAccent),
                StatChip('TIME_WAIT', tcp.timeWait, color: Colors.amber),
                StatChip('CLOSE_WAIT', tcp.closeWait, color: Colors.orange),
                StatChip('SYN_SENT', tcp.synSent),
                StatChip('SYN_RECV', tcp.synRecv),
                StatChip('FIN_WAIT1', tcp.finWait1),
                StatChip('FIN_WAIT2', tcp.finWait2),
              ],
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                _counter('Retransmits', tcp.retransmits),
                _counter('Resets In', tcp.resetsIn),
                _counter('Resets Out', tcp.resetsOut),
                _counter('Listen Overflows', tcp.listenOverflows),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _counter(String label, int value) {
    return Expanded(
      child: Column(
        children: [
          Text('$value',
              style:
                  const TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
          Text(label,
              style: const TextStyle(fontSize: 10, color: Colors.white54)),
        ],
      ),
    );
  }

  List<Widget> _ifaceCards(BuildContext context, MetricSnapshot snap) {
    final count = snap.netIfaceCount;
    if (count == 0) {
      return [
        const Center(
          child: Padding(
            padding: EdgeInsets.all(32),
            child: Text('No network interfaces',
                style: TextStyle(color: Colors.white38)),
          ),
        ),
      ];
    }
    return [
      for (int i = 0; i < count; i++) _ifaceCard(context, snap.netIface(i)),
    ];
  }

  Widget _ifaceCard(BuildContext context, NetIfaceSection iface) {
    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Interface ${iface.ifaceIdx}',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      InfoRow('RX bytes', fmtBytes(iface.rxBytes)),
                      InfoRow('RX packets', '${iface.rxPackets}'),
                      InfoRow('RX drops', '${iface.rxDrops}'),
                      InfoRow('RX errors', '${iface.rxErrors}'),
                    ],
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      InfoRow('TX bytes', fmtBytes(iface.txBytes)),
                      InfoRow('TX packets', '${iface.txPackets}'),
                      InfoRow('TX drops', '${iface.txDrops}'),
                      InfoRow('TX errors', '${iface.txErrors}'),
                    ],
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
