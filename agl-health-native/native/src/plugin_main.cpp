// SPDX-License-Identifier: Apache-2.0
//
// Exported C ABI entry points for the agl-health Flutter native
// plugin. See `include/agl_health_plugin.h` for the public contract.
//
// Phase 2 maintains a single global `ShmReader` lazily constructed
// on the first `agl_health_set_metrics_port` call. Later phases will
// promote this to a plugin-wide `PluginState` owning ShmReader +
// DbusSubscriber + SocketReader, all sharing a single asio
// io_context thread.

#include "agl_health_plugin.h"
#include "shm_reader.hpp"

#include <memory>
#include <mutex>
#include <string>

#include "dart_api_dl.h"

namespace {

/// Default shm segment path. Matches the daemon's `shm::DEFAULT_SHM_PATH`.
constexpr const char* kDefaultShmPath = "/dev/shm/agl-health-metrics";

/// Plugin-wide singleton state. Guarded by `g_state_mutex` because
/// Dart may call the exported functions from multiple isolates in
/// principle (though in practice the smoke test and the Flutter app
/// only ever call them from the root isolate).
std::mutex g_state_mutex;
std::unique_ptr<agl_health::ShmReader> g_shm_reader;
bool g_api_dl_initialized = false;

}  // namespace

extern "C" {

AGL_HEALTH_EXPORT intptr_t agl_health_init(void* initialize_api_dl_data) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (g_api_dl_initialized) {
        return 0;  // already good
    }
    intptr_t rc = Dart_InitializeApiDL(initialize_api_dl_data);
    if (rc != 0) {
        return rc;
    }
    g_api_dl_initialized = true;
    return 0;
}

AGL_HEALTH_EXPORT void agl_health_set_metrics_port(int64_t port) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_api_dl_initialized) {
        // Defensive: Dart called set_port before init. There's
        // nothing useful we can do -- Dart_PostCObject_DL will
        // segfault. Silently drop.
        return;
    }

    if (port == 0) {
        // Pause the reader but do NOT destroy it. The mmap must
        // stay alive for the full plugin lifetime because Dart may
        // still hold Uint8List references backed by the mmap from
        // previous posts (ExternalTypedData with a no-op finalizer).
        // Destroying the mmap while Dart holds those references
        // causes SIGSEGV in the Dart VM the next time it touches
        // the buffer.
        if (g_shm_reader) {
            g_shm_reader->set_port(0);
        }
        return;
    }

    if (!g_shm_reader) {
        try {
            g_shm_reader = std::make_unique<agl_health::ShmReader>(
                std::string(kDefaultShmPath));
        } catch (const std::exception&) {
            // Daemon not running / shm layout mismatch / permission
            // denied. Leave g_shm_reader null; Dart will just never
            // receive snapshots. The smoke test reports this as
            // "no snapshots received" which is actionable.
            return;
        }
        g_shm_reader->set_port(static_cast<Dart_Port_DL>(port));
        g_shm_reader->start();
    } else {
        g_shm_reader->set_port(static_cast<Dart_Port_DL>(port));
    }
}

}  // extern "C"
