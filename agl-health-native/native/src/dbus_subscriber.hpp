// SPDX-License-Identifier: Apache-2.0
//
// DbusSubscriber: registers signal handlers on com.agl.health for
// SecurityEvent signals and posts each received event to a Dart port
// via Dart_PostCObject_DL.

#ifndef AGL_HEALTH_DBUS_SUBSCRIBER_HPP
#define AGL_HEALTH_DBUS_SUBSCRIBER_HPP

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <sdbus-c++/sdbus-c++.h>
#include "dart_api_dl.h"

namespace agl_health {

/// D-Bus well-known service name. Must match the Rust daemon's
/// `dbus_publisher::BUS_NAME`.
constexpr const char* kDbusServiceName = "com.agl.health";
constexpr const char* kDbusObjectPath = "/com/agl/health";
constexpr const char* kDbusInterfaceName = "com.agl.health.Events";

class DbusSubscriber {
 public:
  /// Create a subscriber. Does NOT connect yet — `start()` spawns a
  /// thread that connects (system bus, with a session-bus fallback for
  /// development) and retries until the bus/daemon is available, so the
  /// app can start before the daemon and survive a daemon restart.
  /// Never throws.
  DbusSubscriber();
  ~DbusSubscriber();

  DbusSubscriber(const DbusSubscriber&) = delete;
  DbusSubscriber& operator=(const DbusSubscriber&) = delete;

  /// Start the sdbus-cpp async event loop (spawns an internal thread).
  /// Idempotent.
  void start();

  /// Stop the event loop. Blocks until the internal thread exits.
  void stop();

  /// Update the Dart port that SecurityEvent signals are posted to.
  /// Passing 0 pauses posts. Thread-safe.
  void set_port(Dart_Port_DL port);

 private:
  /// Connect + register the signal handler. Returns true on success.
  /// Never throws (swallows sdbus errors and returns false to retry).
  bool connect();
  /// Connect-with-retry loop run on `thread_`; blocks in the sdbus
  /// event loop while connected and reconnects if it drops.
  void run_loop();
  void on_security_event_typed(uint32_t pid,
                               const std::string& kind,
                               const std::string& severity,
                               const std::string& comm,
                               uint32_t uid,
                               uint64_t timestamp_ns,
                               uint64_t arg);

  /// Guards the `conn_`/`proxy_` pointers, which are assigned/reset by
  /// `run_loop` and read by `stop()` (to call `leaveEventLoop`).
  std::mutex state_mutex_;
  std::unique_ptr<sdbus::IConnection> conn_;
  std::unique_ptr<sdbus::IProxy> proxy_;
  std::atomic<Dart_Port_DL> port_{0};
  std::atomic<bool> running_{false};
  std::thread thread_;
};

}  // namespace agl_health

#endif  // AGL_HEALTH_DBUS_SUBSCRIBER_HPP
