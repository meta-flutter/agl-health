//! `agl-health-daemon` - userspace half of the AGL system health observability
//! stack.
//!
//! Responsibilities (full implementation per §4.3 of the plan):
//!   1. Load the embedded eBPF object, attach all programs to their
//!      tracepoints/kprobes, obtain map handles.
//!   2. Drain ring buffers into a tokio broadcast channel for fan-out.
//!   3. Poll BPF HashMaps once per second to build a `MetricSnapshot`.
//!   4. Publish the snapshot through an axum REST + WebSocket API and a
//!      POSIX shared memory segment.
//!
//! Currently implemented: tracing, /health, placeholder /metrics/*, signal
//! handling, and (behind the `ebpf` cargo feature) the full loader +
//! ring buffer drain tasks. The aggregator and WS fan-out land next.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod aggregator;
mod api;
mod bandwidth;
mod cgroup_names;
mod dbus_publisher;
mod events;
mod loader;
mod metrics;
mod proc_tier;
mod shm;
mod time_base;

use crate::bandwidth::{BandwidthWindow, SharedBandwidthWindow};
use crate::cgroup_names::CgroupNameCache;
use crate::events::{EventBus, EVENT_CHANNEL_CAPACITY};
use crate::metrics::{MetricSnapshot, SharedSnapshot};
use crate::proc_tier::{CpuUtilCache, PidFactsCache};
use crate::time_base::TimeBase;

/// Shared application state. Cloned into every axum handler.
#[derive(Clone)]
struct AppState {
    started: Instant,
    bpf: Arc<loader::LoadSummary>,
    snapshot: SharedSnapshot,
    events: EventBus,
    /// Per-pid supplements from `/proc/<pid>/status`.
    pid_facts: PidFactsCache,
    /// Rolling bandwidth window for cgroup network queries.
    bandwidth: SharedBandwidthWindow,
    /// Cgroup ID → name cache for the API overlay.
    cgroup_names: CgroupNameCache,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_s: u64,
    /// Names of eBPF programs successfully attached at startup.
    programs_loaded: Vec<&'static str>,
    /// Names of BPF maps currently being drained.
    maps_loaded: Vec<&'static str>,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        uptime_s: state.started.elapsed().as_secs(),
        programs_loaded: state.bpf.programs.clone(),
        maps_loaded: state.bpf.maps.clone(),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // Capture the CLOCK_MONOTONIC -> wall-clock offset once, before any
    // subsystem emits a timestamp. Every `timestamp_ns` field in every
    // output path (events, snapshots, shm header) flows through this
    // struct so every value uses the same time base. See time_base.rs
    // for the rationale.
    let time_base = TimeBase::capture();
    info!("time base captured");

    // Shared metric snapshot, refreshed once per second by the aggregator
    // when the `ebpf` feature is enabled. Without the feature the snapshot
    // stays at its default zero state and the /metrics endpoints return
    // zero-valued JSON (a valid "no data yet" response).
    let snapshot: SharedSnapshot =
        Arc::new(tokio::sync::RwLock::new(MetricSnapshot::default()));

    // Per-pid /proc supplements. Cache is written by proc_tier and read
    // by the /metrics/process handler - see proc_tier.rs for the writer
    // discipline that keeps it from colliding with the eBPF aggregator.
    let pid_facts: PidFactsCache = Arc::new(tokio::sync::RwLock::new(Default::default()));
    let cpu_util: CpuUtilCache = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    proc_tier::start(snapshot.clone(), pid_facts.clone());
    proc_tier::spawn_cpu_stat_task(cpu_util.clone());

    // v3 shm publisher (Phase 1). Single writer task that reads from
    // the shared snapshot and pid_facts cache and publishes into
    // /dev/shm/agl-health-metrics under a seqlock. Unconditional on
    // the `ebpf` feature — without eBPF the segment just carries the
    // /proc tier's memory + load fields, which is still useful for
    // verifying the Flutter consumer path end-to-end.
    if let Err(e) = shm::spawn_writer(
        std::path::PathBuf::from(shm::DEFAULT_SHM_PATH),
        snapshot.clone(),
        pid_facts.clone(),
        cpu_util.clone(),
        time_base,
    ) {
        warn!(error = %e, "shm publisher disabled - /metrics/* REST path still works");
    }

    // Event bus. Unconditional so the /events/stream WebSocket endpoint
    // compiles without the ebpf feature - it just never produces events.
    // Every WebSocket subscriber gets its own Receiver via bus.subscribe().
    let (events_tx, _events_rx): (EventBus, _) =
        tokio::sync::broadcast::channel(EVENT_CHANNEL_CAPACITY);

    // D-Bus publisher for security events. Subscribes to the same
    // broadcast bus the WebSocket uses. Connection failure is non-fatal.
    dbus_publisher::spawn_publisher(events_tx.clone());

    // Rolling bandwidth window for /metrics/network/cgroup?window= queries.
    let bw_window: SharedBandwidthWindow =
        Arc::new(tokio::sync::RwLock::new(BandwidthWindow::new()));

    // Cgroup ID → name resolver (walks /sys/fs/cgroup every 30s).
    let cgroup_names = cgroup_names::spawn_resolver();

    // Attempt to load the eBPF object.
    let (bpf_summary, _bpf_guard) = match loader::load(snapshot.clone(), events_tx.clone(), time_base, bw_window.clone()) {
        Ok(loaded) => {
            info!(
                programs = loaded.summary.programs.len(),
                maps = loaded.summary.maps.len(),
                "eBPF loader ready"
            );
            (loaded.summary.clone(), Some(loaded))
        }
        Err(e) => {
            warn!(error = %e, "eBPF loader disabled - running API-only");
            (loader::LoadSummary::default(), None)
        }
    };

    let state = AppState {
        started: Instant::now(),
        bpf: Arc::new(bpf_summary),
        snapshot,
        events: events_tx,
        pid_facts,
        bandwidth: bw_window,
        cgroup_names,
    };

    let app = Router::new()
        .route("/health", get(health))
        .merge(api::router())
        .with_state(state);

    // Bind address. Defaults to loopback so the unauthenticated API is
    // not reachable off-host; `AGL_HEALTH_LISTEN` lets a deployment
    // override it (e.g. to a different loopback port). A bad value is a
    // startup error rather than a panic.
    //
    // NOTE: the API is currently unauthenticated. It exposes per-pid /
    // per-cgroup data from a privileged daemon, so it must stay bound to
    // loopback (or move to a mode-restricted Unix socket) until an auth
    // layer is added. See SECURITY_REVIEW notes.
    let listen = std::env::var("AGL_HEALTH_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:7777".to_string());
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid AGL_HEALTH_LISTEN address: {listen:?}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    info!(%addr, "agl-health-daemon listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum server exited with error")?;

    info!("agl-health-daemon shut down cleanly");
    // `_bpf_guard` drops here, detaching all attached programs.
    Ok(())
}

/// Resolves when either SIGINT (Ctrl-C) or SIGTERM (systemd stop) is received.
async fn shutdown_signal() {
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGTERM handler");
            return;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGINT handler");
            return;
        }
    };
    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM, shutting down"),
        _ = sigint.recv() => info!("received SIGINT, shutting down"),
    }
}
