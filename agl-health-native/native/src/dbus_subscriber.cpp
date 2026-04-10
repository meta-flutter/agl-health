// SPDX-License-Identifier: Apache-2.0

#include "dbus_subscriber.hpp"

#include <cstring>

namespace agl_health {

DbusSubscriber::DbusSubscriber() {
    // Session bus for dev; production AGL uses system bus (requires
    // the policy file at /etc/dbus-1/system.d/com.agl.health.conf).
    conn_ = sdbus::createSessionBusConnection();

    // sdbus-cpp v2.x: strong-typed ServiceName/ObjectPath.
    // The IConnection& overload runs the event loop on the
    // connection we manage ourselves via enterEventLoopAsync().
    proxy_ = sdbus::createProxy(
        *conn_,
        sdbus::ServiceName{kDbusServiceName},
        sdbus::ObjectPath{kDbusObjectPath});

    // sdbus-cpp v2.x: public API uses the builder pattern.
    // Typed args are deserialized by sdbus-cpp automatically —
    // the lambda receives decoded values, not a raw Signal.
    proxy_->uponSignal("SecurityEvent")
           .onInterface(kDbusInterfaceName)
           .call([this](uint32_t pid,
                        std::string kind,
                        std::string severity,
                        std::string comm,
                        uint32_t uid,
                        uint64_t timestamp_ns,
                        uint64_t arg) {
               on_security_event_typed(pid, kind, severity, comm,
                                       uid, timestamp_ns, arg);
           });
}

DbusSubscriber::~DbusSubscriber() {
    stop();
}

void DbusSubscriber::start() {
    if (running_) return;
    running_ = true;
    // enterEventLoopAsync spawns an internal thread managed by
    // sdbus-cpp. Signal handler callbacks fire on that thread.
    conn_->enterEventLoopAsync();
}

void DbusSubscriber::stop() {
    if (!running_) return;
    running_ = false;
    conn_->leaveEventLoop();
}

void DbusSubscriber::set_port(Dart_Port_DL port) {
    port_.store(port, std::memory_order_release);
}

void DbusSubscriber::on_security_event_typed(
    uint32_t pid,
    const std::string& kind,
    const std::string& severity,
    const std::string& comm,
    uint32_t uid,
    uint64_t timestamp_ns,
    uint64_t arg) {
    Dart_Port_DL port = port_.load(std::memory_order_acquire);
    if (port == 0) return;

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
        &c_pid, &c_kind, &c_severity, &c_comm,
        &c_uid, &c_timestamp, &c_arg,
    };

    Dart_CObject message{};
    message.type = Dart_CObject_kArray;
    message.value.as_array.length = 7;
    message.value.as_array.values = elements;

    Dart_PostCObject_DL(port, &message);
}

}  // namespace agl_health
