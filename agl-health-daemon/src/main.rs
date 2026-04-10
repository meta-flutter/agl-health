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
mod dbus_publisher;
mod events;
mod loader;
mod metrics;
mod proc_tier;
mod shm;
mod time_base;

use crate::events::{EventBus, EVENT_CHANNEL_CAPACITY};
use crate::metrics::{MetricSnapshot, SharedSnapshot};
use crate::proc_tier::PidFactsCache;
use crate::time_base::TimeBase;

/// Shared application state. Cloned into every axum handler.
#[derive(Clone)]
struct AppState {
    started: Instant,
    bpf: Arc<loader::LoadSummary>,
    snapshot: SharedSnapshot,
    events: EventBus,
    /// Per-pid supplements from `/proc/<pid>/status`. The
    /// `/metrics/process` handler overlays these onto each returned
    /// `ProcessStats` so clients see memory and thread data even when
    /// the BPF side can't provide it.
    pid_facts: PidFactsCache,
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
    proc_tier::start(snapshot.clone(), pid_facts.clone());

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

    // Attempt to load the eBPF object. On systems without the `ebpf` feature
    // this returns an error immediately (expected) and we continue with an
    // empty summary. With the feature, a per-program attach failure is
    // logged and tolerated; only a total load failure leaves the daemon
    // running API-only.
    let (bpf_summary, _bpf_guard) = match loader::load(snapshot.clone(), events_tx.clone(), time_base) {
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
    };

    let app = Router::new()
        .route("/health", get(health))
        .merge(api::router())
        .with_state(state);

    // TODO: once the loader lands, bind a Unix domain socket at
    // /run/agl-health.sock as the primary transport; TCP is for development.
    let addr: SocketAddr = "127.0.0.1:7777".parse().expect("valid socket addr");
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
