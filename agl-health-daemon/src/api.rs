//! HTTP REST + WebSocket API surface for the daemon.
//!
//! Every route in this module reads from `AppState.snapshot`, the
//! `SharedSnapshot` that the aggregator refreshes once per second. Before
//! the aggregator has run (or when the daemon is built without the `ebpf`
//! feature) the snapshot is `MetricSnapshot::default()` — zero-valued JSON,
//! which is a valid and unambiguous "no data yet" response.
//!
//! Routes for subsystems whose data is not yet collected
//! (CPU per-core stats, per-process stats, security event feed) still
//! return a `{ ready: false }` placeholder so the URL shape is stable
//! for the Flutter client and integration tests.

use agl_health_common::metrics::{
    BlockStats, CgroupNetBytes, CpuStats, MemorySnapshot, NetIfaceStats, ProcessStats,
    SecurityEventCounts, TcpStateSnapshot,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::events::WireEvent;
use crate::metrics::{LoadSnapshot, MetricSnapshot, SchedSnapshot};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        // Live snapshot-backed endpoints.
        .route("/metrics", get(get_metrics))
        .route("/metrics/memory", get(get_memory))
        .route("/metrics/scheduler", get(get_scheduler))
        .route("/metrics/network", get(get_network))
        .route("/metrics/disk", get(get_disk))
        .route("/metrics/process", get(get_process))
        .route("/metrics/cpu", get(get_cpu))
        .route("/metrics/security", get(get_security))
        .route("/metrics/network/cgroup", get(get_network_cgroup))
        // Live event stream.
        .route("/events/stream", get(events_stream))
}

async fn get_metrics(State(state): State<AppState>) -> Json<MetricSnapshot> {
    Json(state.snapshot.read().await.clone())
}

async fn get_memory(State(state): State<AppState>) -> Json<MemorySnapshot> {
    Json(state.snapshot.read().await.memory)
}

async fn get_scheduler(State(state): State<AppState>) -> Json<SchedSnapshot> {
    Json(state.snapshot.read().await.sched.clone())
}

#[derive(Serialize)]
struct NetworkResponse {
    ifaces: Vec<NetIfaceStats>,
    tcp: TcpStateSnapshot,
}

async fn get_network(State(state): State<AppState>) -> Json<NetworkResponse> {
    let snap = state.snapshot.read().await;
    Json(NetworkResponse {
        ifaces: snap.net_ifaces.clone(),
        tcp: snap.tcp,
    })
}

async fn get_disk(State(state): State<AppState>) -> Json<Vec<BlockStats>> {
    Json(state.snapshot.read().await.block.clone())
}

/// Query parameters for `/metrics/process`. `limit` trims the already-
/// sorted top-N slice the aggregator publishes.
#[derive(Debug, Deserialize, Default)]
struct ProcessQuery {
    limit: Option<usize>,
}

/// Default number of processes returned when `?limit=` is omitted. Matches
/// §6.1 of the implementation plan.
const DEFAULT_PROCESS_LIMIT: usize = 100;

async fn get_process(
    Query(q): Query<ProcessQuery>,
    State(state): State<AppState>,
) -> Json<Vec<ProcessStats>> {
    let limit = q.limit.unwrap_or(DEFAULT_PROCESS_LIMIT);
    let mut out = {
        let snap = state.snapshot.read().await;
        let mut v = snap.top_processes.clone();
        if v.len() > limit {
            v.truncate(limit);
        }
        v
    };
    // Overlay /proc-sourced supplements (VmRSS, VmSize, Threads) that the
    // BPF pipeline doesn't track. Missing pids in the cache leave the
    // corresponding fields at whatever the aggregator wrote (usually 0).
    {
        let facts = state.pid_facts.read().await;
        for p in out.iter_mut() {
            if let Some(f) = facts.get(&p.pid) {
                p.mem_rss_bytes = f.mem_rss_bytes;
                p.mem_vms_bytes = f.mem_vms_bytes;
                p.thread_count = f.thread_count;
            }
        }
    }
    Json(out)
}

/// `GET /metrics/cpu` response shape. Combines system-wide load averages
/// (from `/proc/loadavg`, via the proc tier) with per-core scheduling
/// class time from the `cpu.rs` eBPF probes. `cores` is empty until the
/// eBPF loader has seen the first aggregator tick.
#[derive(Serialize)]
struct CpuResponse {
    load: LoadSnapshot,
    cores: Vec<CpuStats>,
}

async fn get_cpu(State(state): State<AppState>) -> Json<CpuResponse> {
    let snap = state.snapshot.read().await;
    Json(CpuResponse {
        load: snap.load.clone(),
        cores: snap.cpu_cores.clone(),
    })
}

/// `GET /metrics/security` - cumulative counts of security-relevant
/// syscall events. Live event feed lives on the WebSocket at
/// `/events/stream?subsystem=security`.
async fn get_security(State(state): State<AppState>) -> Json<SecurityEventCounts> {
    Json(state.snapshot.read().await.security)
}

/// Query parameters for `/metrics/network/cgroup`. `limit` trims the
/// already-sorted top-N slice the aggregator publishes.
#[derive(Debug, Deserialize, Default)]
struct CgroupQuery {
    limit: Option<usize>,
}

/// Default number of cgroups returned when `?limit=` is omitted.
const DEFAULT_CGROUP_LIMIT: usize = 50;

/// `GET /metrics/network/cgroup?limit=N` - top cgroups by
/// cumulative rx+tx bytes since the daemon started. Values are
/// monotonic counters; rate-of-change is the client's responsibility.
///
/// Historical windowed queries (e.g. "top consumers over last 30s")
/// are a follow-up pass - see the saved project memory on bandwidth
/// tracking.
async fn get_network_cgroup(
    Query(q): Query<CgroupQuery>,
    State(state): State<AppState>,
) -> Json<Vec<CgroupNetBytes>> {
    let limit = q.limit.unwrap_or(DEFAULT_CGROUP_LIMIT);
    let snap = state.snapshot.read().await;
    let mut out = snap.cgroup_net_top.clone();
    if out.len() > limit {
        out.truncate(limit);
    }
    Json(out)
}

// -------- /events/stream -----------------------------------------------

/// Query parameters for the WebSocket event stream. Both are optional.
///
/// * `subsystem` is a comma-separated list; only events whose subsystem is
///   in the list are forwarded. Unknown names are silently ignored.
/// * `pid` restricts the stream to a single pid. Events with no pid
///   (currently every `network` event) are dropped when this filter is set.
#[derive(Debug, Deserialize, Default)]
struct StreamQuery {
    subsystem: Option<String>,
    pid: Option<u32>,
}

struct EventFilter {
    subsystems: Option<Vec<String>>,
    pid: Option<u32>,
}

impl From<StreamQuery> for EventFilter {
    fn from(q: StreamQuery) -> Self {
        let subsystems = q.subsystem.map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>()
        });
        EventFilter {
            subsystems,
            pid: q.pid,
        }
    }
}

impl EventFilter {
    fn matches(&self, ev: &WireEvent) -> bool {
        if let Some(subs) = &self.subsystems {
            if !subs.iter().any(|s| s == ev.subsystem()) {
                return false;
            }
        }
        if let Some(pid) = self.pid {
            match ev.pid() {
                Some(p) if p == pid => {}
                _ => return false,
            }
        }
        true
    }
}

async fn events_stream(
    Query(q): Query<StreamQuery>,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let filter: EventFilter = q.into();
    let rx = state.events.subscribe();
    ws.on_upgrade(move |socket| handle_events_socket(socket, rx, filter))
}

async fn handle_events_socket(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<WireEvent>,
    filter: EventFilter,
) {
    loop {
        match rx.recv().await {
            Ok(event) => {
                if !filter.matches(&event) {
                    continue;
                }
                let json = match serde_json::to_string(&event) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "event serialization failed");
                        continue;
                    }
                };
                if socket.send(Message::Text(json.into())).await.is_err() {
                    // Client disconnected.
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                debug!(skipped = n, "WebSocket subscriber fell behind");
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}
