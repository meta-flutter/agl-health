// SPDX-License-Identifier: Apache-2.0
//
// Exported C ABI for the agl-health Flutter native plugin.
//
// Dart FFI can only resolve C-linkage symbols, so every function
// exported from `libagl_health_native.so` that Dart calls appears here
// inside `extern "C"`.
//
// Phase 2 exposes only the metrics (shm) channel. Phases 5 and 6 will
// add:
//
//   void agl_health_set_events_port(int64_t port);   // Unix socket
//   void agl_health_set_security_port(int64_t port); // D-Bus signals
//   void agl_health_set_frame_interval_us(int64_t us);
//
// Returning `intptr_t` from the initializer matches the idiom used by
// the Dart documentation examples, even though we only ever return 0
// or -1 for now.

#ifndef AGL_HEALTH_PLUGIN_H
#define AGL_HEALTH_PLUGIN_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define AGL_HEALTH_EXPORT __attribute__((visibility("default")))
#else
#define AGL_HEALTH_EXPORT
#endif

/// Initialize the Dart DL API inside this shared library.
///
/// Must be called exactly once from Dart during plugin bring-up, with
/// the opaque pointer obtained from
/// `NativeApi.initializeApiDLData` on the Dart side. Calling any
/// other exported function before this will segfault inside
/// `Dart_PostCObject_DL`.
///
/// Returns 0 on success, non-zero on failure (the underlying
/// `Dart_InitializeApiDL` returning a non-zero error code).
AGL_HEALTH_EXPORT intptr_t agl_health_init(void* initialize_api_dl_data);

/// Register the Dart send port that the metrics (shm) channel will
/// post `MetricSnapshotV3` payloads to.
///
/// Pass the `nativePort` of a `RawReceivePort`'s `sendPort`. The
/// first call starts the shm reader background thread; subsequent
/// calls update the port (existing thread picks up the change on its
/// next tick via an atomic store).
///
/// Passing 0 stops the reader (used during shutdown / hot reload).
AGL_HEALTH_EXPORT void agl_health_set_metrics_port(int64_t port);

#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // AGL_HEALTH_PLUGIN_H
