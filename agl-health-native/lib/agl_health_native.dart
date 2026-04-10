/// Public API surface for the `agl_health_native` Flutter native
/// plugin.
///
/// Phase 2 exposes only the metrics (shm) channel. Phases 5 and 6
/// will add `events` and `security` streams from the Unix socket
/// and D-Bus channels respectively; they'll be exported here
/// alongside the metrics stream via the same `AglHealthClient`.
library;

export 'src/health_client.dart' show AglHealthClient;
export 'src/metrics_channel.dart'
    show
        MetricSnapshot,
        MemorySection,
        LoadSection,
        CpuStatsSection,
        ProcessStatsSection,
        NetIfaceSection,
        BlockStatsSection,
        TcpStateSection;
