//! D-Bus signal publisher for low-frequency security events.
//!
//! Connects to the session bus (for dev) or system bus (for
//! production AGL deployments) and registers the `com.agl.health`
//! service at `/com/agl/health`. Subscribes to the daemon's
//! existing `EventBus` and emits a D-Bus signal for each
//! `WireEvent::Security` that passes through.
//!
//! The signal format matches the interface definition in
//! `agl-health-native/interfaces/com.agl.health.xml`:
//!
//! ```text
//! signal com.agl.health.Events.SecurityEvent(
//!     pid:          u32,
//!     kind:         string,   // "Ptrace", "MemfdCreate", etc
//!     severity:     string,   // "info", "warn", "critical"
//!     comm:         string,
//!     uid:          u32,
//!     timestamp_ns: u64,
//!     arg:          u64,
//! )
//! ```
//!
//! Other AGL services can subscribe to the same signals via
//! `dbus-monitor` or their own D-Bus proxy. This is the primary
//! motivation for using D-Bus over the Unix socket channel for
//! security events — ecosystem integration, not performance.
//!
//! Connection failure is non-fatal. If D-Bus is unavailable (minimal
//! container, missing policy file, etc.), the publisher logs a
//! warning and the daemon continues running with the REST/WebSocket
//! and shm channels still functional.

use tokio::sync::broadcast;
use tracing::{info, warn};
use zbus::{connection, interface, object_server::SignalEmitter, Connection};

use crate::events::{EventBus, WireEvent};

/// D-Bus well-known service name.
const BUS_NAME: &str = "com.agl.health";
/// D-Bus object path.
const OBJECT_PATH: &str = "/com/agl/health";

/// Empty struct that serves as the `zbus` interface object.
/// The actual signal emission is driven by the publisher task,
/// not by method calls on this object.
struct HealthEvents;

#[interface(name = "com.agl.health.Events")]
impl HealthEvents {
    /// SecurityEvent signal. Emitted for each ptrace, memfd_create,
    /// setuid, or prctl(PR_SET_DUMPABLE=0) syscall detected by the
    /// eBPF security probes.
    #[zbus(signal)]
    async fn security_event(
        ctxt: &SignalEmitter<'_>,
        pid: u32,
        kind: &str,
        severity: &str,
        comm: &str,
        uid: u32,
        timestamp_ns: u64,
        arg: u64,
    ) -> zbus::Result<()>;
}

/// Spawn the D-Bus publisher task. Returns immediately.
///
/// Tries session bus first (works without a policy file on dev
/// hosts). Production AGL deployments with the policy file
/// installed at `/etc/dbus-1/system.d/com.agl.health.conf` should
/// switch to system bus.
pub fn spawn_publisher(bus: EventBus) {
    tokio::spawn(async move {
        match try_connect_and_run(bus).await {
            Ok(()) => {} // unreachable under normal operation
            Err(e) => warn!(error = %e, "D-Bus publisher exited"),
        }
    });
}

async fn try_connect_and_run(bus: EventBus) -> Result<(), Box<dyn std::error::Error>> {
    // Try session bus (dev), then system bus (production).
    let conn = match connect_session().await {
        Ok(c) => {
            info!("D-Bus publisher connected to session bus");
            c
        }
        Err(session_err) => match connect_system().await {
            Ok(c) => {
                info!("D-Bus publisher connected to system bus");
                c
            }
            Err(system_err) => {
                warn!(
                    session_error = %session_err,
                    system_error = %system_err,
                    "D-Bus publisher disabled — could not connect to session or system bus"
                );
                return Ok(());
            }
        },
    };

    // Register the interface object at the well-known path.
    conn.object_server()
        .at(OBJECT_PATH, HealthEvents)
        .await?;

    // Request the well-known name. This may fail on the system bus
    // if the policy file isn't installed — non-fatal, we can still
    // emit signals on the connection.
    match conn.request_name(BUS_NAME).await {
        Ok(_) => info!(name = BUS_NAME, "D-Bus name acquired"),
        Err(e) => warn!(
            name = BUS_NAME,
            error = %e,
            "could not acquire D-Bus name (signals still work, but \
             consumers must match by sender rather than well-known name)"
        ),
    }

    // Subscribe to the broadcast bus and forward security events
    // as D-Bus signals.
    let mut rx = bus.subscribe();
    let ctxt = SignalEmitter::new(&conn, OBJECT_PATH)?;

    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Err(e) = emit_if_security(&ctxt, &event).await {
                    warn!(error = %e, "D-Bus signal emission failed");
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "D-Bus publisher fell behind broadcast");
            }
            Err(broadcast::error::RecvError::Closed) => {
                info!("broadcast bus closed — D-Bus publisher exiting");
                return Ok(());
            }
        }
    }
}

async fn emit_if_security(
    ctxt: &SignalEmitter<'_>,
    event: &WireEvent,
) -> zbus::Result<()> {
    match event {
        WireEvent::Security {
            kind,
            severity,
            pid,
            uid,
            comm,
            timestamp_ns,
            arg,
            ..
        } => {
            HealthEvents::security_event(
                ctxt,
                *pid,
                kind,
                severity,
                comm,
                *uid,
                *timestamp_ns,
                *arg,
            )
            .await
        }
        _ => Ok(()), // Only security events go to D-Bus.
    }
}

async fn connect_session() -> zbus::Result<Connection> {
    connection::Builder::session()?.build().await
}

async fn connect_system() -> zbus::Result<Connection> {
    connection::Builder::system()?.build().await
}
