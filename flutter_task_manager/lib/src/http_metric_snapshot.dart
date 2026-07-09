// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

import 'package:agl_health_native/agl_health_native.dart';

import 'health_snapshot.dart';

/// [HealthSnapshot] backed by a JSON response from [GET /metrics].
class HttpMetricSnapshot implements HealthSnapshot {
  final Map<String, dynamic> _json;

  const HttpMetricSnapshot(this._json);

  // HTTP responses carry no sequence counter or version field.
  @override
  int get sequence => 0;

  @override
  int get version => 1;

  @override
  int get timestampNsWall => _int(_json['timestamp_ns']);

  @override
  MemorySection get memory {
    final m = _json['memory'] as Map<String, dynamic>;
    return MemorySection(
      totalBytes: _int(m['total_bytes']),
      freeBytes: _int(m['free_bytes']),
      cachedBytes: _int(m['cached_bytes']),
      bufferedBytes: _int(m['buffered_bytes']),
      slabBytes: _int(m['slab_bytes']),
      swapUsedBytes: _int(m['swap_used_bytes']),
      swapFreeBytes: _int(m['swap_free_bytes']),
      pageFaultsMinor: _int(m['page_faults_minor']),
      pageFaultsMajor: _int(m['page_faults_major']),
      psiSomeX100: _int(m['psi_some_pct_x100']),
      psiFullX100: _int(m['psi_full_pct_x100']),
      oomKillsTotal: _int(m['oom_kills_total']),
    );
  }

  @override
  LoadSection get load {
    final l = _json['load'] as Map<String, dynamic>;
    return LoadSection(
      load1: _double(l['load_1']),
      load5: _double(l['load_5']),
      load15: _double(l['load_15']),
    );
  }

  @override
  SchedSection get sched => _parseSched(_json['sched'] as Map<String, dynamic>);

  @override
  int get schedP99Ns => sched.p99Ns;

  @override
  TcpStateSection get tcp {
    final t = _json['tcp'] as Map<String, dynamic>;
    return TcpStateSection(
      established: _int(t['established']),
      synSent: _int(t['syn_sent']),
      synRecv: _int(t['syn_recv']),
      finWait1: _int(t['fin_wait1']),
      finWait2: _int(t['fin_wait2']),
      timeWait: _int(t['time_wait']),
      closeWait: _int(t['close_wait']),
      listen: _int(t['listen']),
      listenOverflows: _int(t['listen_overflows']),
      retransmits: _int(t['retransmits']),
      resetsIn: _int(t['resets_in']),
      resetsOut: _int(t['resets_out']),
    );
  }

  @override
  SecuritySection get security {
    final s = _json['security'] as Map<String, dynamic>;
    return SecuritySection(
      ptrace: _int(s['ptrace']),
      memfdCreate: _int(s['memfd_create']),
      prctl: _int(s['prctl']),
      setuid: _int(s['setuid']),
      execAnomaly: _int(s['exec_anomaly']),
      capabilityUse: _int(s['capability_use']),
    );
  }

  @override
  int get cpuCount {
    final cores = _json['cpu_cores'];
    return cores is List ? cores.length : 0;
  }

  @override
  CpuStatsSection cpu(int i) {
    final c = (_json['cpu_cores'] as List)[i] as Map<String, dynamic>;
    return CpuStatsSection(
      cpuId: _int(c['cpu_id']),
      userNs: _int(c['user_ns']),
      systemNs: _int(c['system_ns']),
      iowaitNs: _int(c['iowait_ns']),
      irqNs: _int(c['irq_ns']),
      softirqNs: _int(c['softirq_ns']),
      idleNs: _int(c['idle_ns']),
      ctxSwitches: _int(c['ctx_switches']),
    );
  }

  @override
  int get netIfaceCount {
    final ifaces = _json['net_ifaces'];
    return ifaces is List ? ifaces.length : 0;
  }

  @override
  NetIfaceSection netIface(int i) {
    final n = (_json['net_ifaces'] as List)[i] as Map<String, dynamic>;
    return NetIfaceSection(
      ifaceIdx: _int(n['iface_idx']),
      rxBytes: _int(n['rx_bytes']),
      txBytes: _int(n['tx_bytes']),
      rxPackets: _int(n['rx_packets']),
      txPackets: _int(n['tx_packets']),
      rxDrops: _int(n['rx_drops']),
      txDrops: _int(n['tx_drops']),
      rxErrors: _int(n['rx_errors']),
      txErrors: _int(n['tx_errors']),
    );
  }

  @override
  int get blockDeviceCount {
    final block = _json['block'];
    return block is List ? block.length : 0;
  }

  @override
  BlockStatsSection blockDevice(int i) {
    final b = (_json['block'] as List)[i] as Map<String, dynamic>;
    return BlockStatsSection(
      deviceMajor: _int(b['device_major']),
      deviceMinor: _int(b['device_minor']),
      readsCompleted: _int(b['reads_completed']),
      writesCompleted: _int(b['writes_completed']),
      readBytes: _int(b['read_bytes']),
      writeBytes: _int(b['write_bytes']),
      readLatencyNs: _int(b['read_latency_ns']),
      writeLatencyNs: _int(b['write_latency_ns']),
      ioInflight: _int(b['io_inflight']),
      ioTicksMs: _int(b['io_ticks_ms']),
    );
  }

  @override
  int get processCount {
    final procs = _json['top_processes'];
    return procs is List ? procs.length : 0;
  }

  @override
  ProcessStatsSection process(int i) {
    final p = (_json['top_processes'] as List)[i] as Map<String, dynamic>;
    return ProcessStatsSection(
      pid: _int(p['pid']),
      ppid: _int(p['ppid']),
      uid: _int(p['uid']),
      threadCount: _int(p['thread_count']),
      cpuUserNs: _int(p['cpu_user_ns']),
      cpuSystemNs: _int(p['cpu_system_ns']),
      memRssBytes: _int(p['mem_rss_bytes']),
      memVmsBytes: _int(p['mem_vms_bytes']),
      voluntaryCtxSw: _int(p['voluntary_ctx_sw']),
      involuntaryCtxSw: _int(p['involuntary_ctx_sw']),
      readBytes: _int(p['read_bytes']),
      writeBytes: _int(p['write_bytes']),
      pageFaultsMinor: _int(p['page_faults_minor']),
      pageFaultsMajor: _int(p['page_faults_major']),
      startTimeNs: _int(p['start_time_ns']),
      openFds: _int(p['open_fds']),
      comm: _commFromJson(p['comm']),
    );
  }

  @override
  int get schedCpuCount {
    final perCpu = _json['sched_per_cpu'];
    return perCpu is List ? perCpu.length : 0;
  }

  @override
  SchedSection schedPerCpu(int i) {
    final entry = (_json['sched_per_cpu'] as List)[i] as Map<String, dynamic>;
    return _parseSched(entry);
  }

  // ---- helpers ----

  static SchedSection _parseSched(Map<String, dynamic> s) {
    final hist = s['histogram'] as Map<String, dynamic>;
    final rawBuckets = hist['buckets'] as List;
    return SchedSection(
      buckets: rawBuckets.map(_int).toList(),
      totalCount: _int(hist['total_count']),
      totalLatencyNs: _int(hist['total_latency_ns']),
      maxLatencyNs: _int(hist['max_latency_ns']),
      p50Ns: _int(s['p50_ns']),
      p95Ns: _int(s['p95_ns']),
      p99Ns: _int(s['p99_ns']),
    );
  }

  // comm in top_processes is serialized as [u8; 16] — a JSON array of ints.
  static String _commFromJson(dynamic field) {
    if (field is String) return field;
    final bytes = (field as List).cast<int>();
    final end = bytes.indexOf(0);
    return String.fromCharCodes(end < 0 ? bytes : bytes.sublist(0, end));
  }

  static int _int(dynamic v) {
    if (v is int) return v;
    if (v is double) return v.toInt();
    return 0;
  }

  static double _double(dynamic v) {
    if (v is double) return v;
    if (v is int) return v.toDouble();
    return 0.0;
  }
}
