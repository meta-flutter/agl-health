// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

#include "dbus_subscriber.hpp"

#include <chrono>
#include <cstring>

namespace agl_health {

DbusSubscriber::DbusSubscriber() = default;

DbusSubscriber::~DbusSubscriber() {
  stop();
}

void DbusSubscriber::start() {
  if (running_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  thread_ = std::thread([this] { run_loop(); });
}

void DbusSubscriber::stop() {
  if (!running_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  // Unblock enterEventLoop() if the loop is currently connected. The
  // pointer is read under the mutex; run_loop only resets conn_ AFTER
  // enterEventLoop returns, which can't happen until this call lands,
  // so there is no use-after-free here.
  {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (conn_) {
      conn_->leaveEventLoop();
    }
  }
  // Join before any member is destroyed so no signal callback can run
  // against a half-destroyed object.
  if (thread_.joinable()) {
    thread_.join();
  }
}

bool DbusSubscriber::connect() {
  try {
    std::unique_ptr<sdbus::IConnection> conn;
    // Prefer the system bus, whose policy restricts ownership of
    // com.agl.health to the privileged daemon — that is what makes a
    // received SecurityEvent trustworthy. Fall back to the session
    // bus for development.
    try {
      conn = sdbus::createSystemBusConnection();
    } catch (const sdbus::Error&) {
      conn = sdbus::createSessionBusConnection();
    }
    // Creating the proxy against the well-known service name installs
    // a match rule keyed on that name, so the bus daemon only delivers
    // signals from its current owner and re-routes automatically when
    // the owner changes (daemon restart).
    auto proxy = sdbus::createProxy(*conn, sdbus::ServiceName{kDbusServiceName},
                                    sdbus::ObjectPath{kDbusObjectPath});
    proxy->uponSignal("SecurityEvent")
        .onInterface(kDbusInterfaceName)
        .call([this](uint32_t pid, const std::string& kind,
                     const std::string& severity, const std::string& comm,
                     uint32_t uid, uint64_t timestamp_ns, uint64_t arg) {
          on_security_event_typed(pid, kind, severity, comm, uid, timestamp_ns,
                                  arg);
        });
    {
      std::lock_guard<std::mutex> lk(state_mutex_);
      conn_ = std::move(conn);
      proxy_ = std::move(proxy);
    }
    return true;
  } catch (const sdbus::Error&) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    proxy_.reset();
    conn_.reset();
    return false;
  }
}

void DbusSubscriber::run_loop() {
  using namespace std::chrono_literals;
  while (running_.load(std::memory_order_acquire)) {
    if (!connect()) {
      // Bus or daemon not available yet — retry until it is.
      std::this_thread::sleep_for(1s);
      continue;
    }
    // Blocks here dispatching signal callbacks until stop() calls
    // leaveEventLoop() or the connection drops.
    conn_->enterEventLoop();
    // Returned: tear down this connection. If running_ is still set
    // the loop reconnects (e.g. the daemon restarted).
    {
      std::lock_guard<std::mutex> lk(state_mutex_);
      proxy_.reset();
      conn_.reset();
    }
  }
}

void DbusSubscriber::set_port(Dart_Port_DL port) {
  port_.store(port, std::memory_order_release);
}

void DbusSubscriber::on_security_event_typed(uint32_t pid,
                                             const std::string& kind,
                                             const std::string& severity,
                                             const std::string& comm,
                                             uint32_t uid,
                                             uint64_t timestamp_ns,
                                             uint64_t arg) {
  Dart_Port_DL port = port_.load(std::memory_order_acquire);
  if (port == 0)
    return;

  // This runs on the sdbus-cpp event-loop thread. An exception
  // escaping into that C++/C boundary would std::terminate the
  // process, so contain anything thrown while building/posting.
  try {
    // Build a Dart_CObject array matching the Dart
    // SecurityEventData constructor order. We use typed CObjects
    // for each field rather than a single blob so the Dart side
    // can decode without manual byte offset calculations.
    Dart_CObject c_pid{};
    c_pid.type = Dart_CObject_kInt32;
    c_pid.value.as_int32 = static_cast<int32_t>(pid);

    Dart_CObject c_uid{};
    c_uid.type = Dart_CObject_kInt32;
    c_uid.value.as_int32 = static_cast<int32_t>(uid);

    Dart_CObject c_timestamp{};
    c_timestamp.type = Dart_CObject_kInt64;
    c_timestamp.value.as_int64 = static_cast<int64_t>(timestamp_ns);

    Dart_CObject c_arg{};
    c_arg.type = Dart_CObject_kInt64;
    c_arg.value.as_int64 = static_cast<int64_t>(arg);

    Dart_CObject c_kind{};
    c_kind.type = Dart_CObject_kString;
    c_kind.value.as_string = const_cast<char*>(kind.c_str());

    Dart_CObject c_severity{};
    c_severity.type = Dart_CObject_kString;
    c_severity.value.as_string = const_cast<char*>(severity.c_str());

    Dart_CObject c_comm{};
    c_comm.type = Dart_CObject_kString;
    c_comm.value.as_string = const_cast<char*>(comm.c_str());

    // Pack into an array CObject. Dart receives this as a List.
    Dart_CObject* elements[] = {
        &c_pid, &c_kind, &c_severity, &c_comm, &c_uid, &c_timestamp, &c_arg,
    };

    Dart_CObject message{};
    message.type = Dart_CObject_kArray;
    message.value.as_array.length = 7;
    message.value.as_array.values = elements;

    Dart_PostCObject_DL(port, &message);
  } catch (...) {
    // Drop the event rather than crash the event-loop thread.
  }
}

}  // namespace agl_health
