// SPDX-License-Identifier: Apache-2.0
//
// AGL system health IVI task manager.
//
// Phase 3: Overview screen with live memory/load data from the shm
// channel. Bottom nav skeleton with 5 tabs; only Overview is
// functional. Remaining tabs populated in Phases 4-6.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:agl_health_native/agl_health_native.dart';

import 'src/metrics_notifier.dart';
import 'src/network_screen.dart';
import 'src/overview_screen.dart';
import 'src/process_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize the native plugin. The library path resolves via
  // AGL_HEALTH_NATIVE_LIB env var, or the smoke-test relative
  // path, or LD_LIBRARY_PATH. If the daemon isn't running the
  // stream just stays empty — no crash.
  final client = AglHealthClient.initialize();
  final notifier = MetricsNotifier();

  // Wire the shm stream into the notifier. The subscription lives
  // for the app's lifetime; no cancel needed.
  client.metrics.listen(
    notifier.update,
    onError: (Object err) {
      debugPrint('metrics stream error: $err');
    },
  );

  runApp(
    ChangeNotifierProvider<MetricsNotifier>.value(
      value: notifier,
      child: const AglHealthApp(),
    ),
  );
}

class AglHealthApp extends StatelessWidget {
  const AglHealthApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AGL System Health',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        colorSchemeSeed: const Color(0xFF2196F3),
        useMaterial3: true,
        textTheme: const TextTheme(
          bodyLarge: TextStyle(fontSize: 16),
          bodyMedium: TextStyle(fontSize: 14),
          titleLarge: TextStyle(fontSize: 20, fontWeight: FontWeight.w600),
          titleMedium: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
        ),
      ),
      home: const _Shell(),
    );
  }
}

class _Shell extends StatefulWidget {
  const _Shell();

  @override
  State<_Shell> createState() => _ShellState();
}

class _ShellState extends State<_Shell> {
  int _tabIndex = 0;

  static const _tabs = <_TabInfo>[
    _TabInfo(icon: Icons.dashboard, label: 'Overview'),
    _TabInfo(icon: Icons.list_alt, label: 'Processes'),
    _TabInfo(icon: Icons.lan, label: 'Network'),
    _TabInfo(icon: Icons.schedule, label: 'Scheduler'),
    _TabInfo(icon: Icons.security, label: 'Security'),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: IndexedStack(
        index: _tabIndex,
        children: [
          const OverviewScreen(),
          const ProcessScreen(),
          const NetworkScreen(),
          _placeholder('Scheduler', 'Phase 5'),
          _placeholder('Security', 'Phase 6'),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        height: 64,
        selectedIndex: _tabIndex,
        onDestinationSelected: (i) => setState(() => _tabIndex = i),
        destinations: [
          for (final tab in _tabs)
            NavigationDestination(icon: Icon(tab.icon), label: tab.label),
        ],
      ),
    );
  }

  Widget _placeholder(String title, String phase) {
    return Center(
      child: Text(
        '$title\ncoming in $phase',
        textAlign: TextAlign.center,
        style: Theme.of(context)
            .textTheme
            .titleLarge
            ?.copyWith(color: Colors.white38),
      ),
    );
  }
}

class _TabInfo {
  final IconData icon;
  final String label;
  const _TabInfo({required this.icon, required this.label});
}
