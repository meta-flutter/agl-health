// SPDX-License-Identifier: Apache-2.0

#include "shm_reader.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// dart_api_dl.h was already included via shm_reader.hpp.

namespace agl_health {

namespace {

/// How often to poll the shm segment. Matches the daemon's 1 Hz
/// aggregator tick. When Phase 5 swaps to asio this becomes
/// `asio::steady_timer::expires_after(std::chrono::seconds(1))`.
constexpr auto POLL_INTERVAL = std::chrono::seconds(1);

/// How many times the seqlock reader will spin on "write in
/// progress" before giving up for this tick. At 1 Hz we expect the
/// writer to hold the odd sequence for microseconds at most, so
/// hitting more than a handful is already a red flag.
constexpr int SEQLOCK_RETRY_BUDGET = 64;

/// No-op finalizer for the ExternalTypedData we post to Dart. The
/// shm mmap is persistent for the plugin's lifetime, so there is
/// nothing to free when Dart GCs the Uint8List view.
void shm_external_finalizer(void* /*peer_isolate_callback_data*/,
                            void* /*peer*/) {
    // Intentionally empty.
}

}  // namespace

ShmReader::ShmReader(std::string path) : path_(std::move(path)) {
    fd_ = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) {
        throw std::runtime_error(
            "ShmReader: open " + path_ + ": " + std::strerror(errno));
    }

    struct stat st{};
    if (::fstat(fd_, &st) != 0) {
        int e = errno;
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error(
            "ShmReader: fstat " + path_ + ": " + std::strerror(e));
    }
    if (static_cast<std::size_t>(st.st_size) < SHM_SNAPSHOT_SIZE) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error(
            "ShmReader: " + path_ + " is " +
            std::to_string(st.st_size) +
            " bytes, expected at least " +
            std::to_string(SHM_SNAPSHOT_SIZE));
    }

    mmap_len_ = SHM_SNAPSHOT_SIZE;
    mmap_base_ = ::mmap(nullptr, mmap_len_,
                        PROT_READ, MAP_SHARED, fd_, 0);
    if (mmap_base_ == MAP_FAILED) {
        int e = errno;
        ::close(fd_);
        fd_ = -1;
        mmap_base_ = nullptr;
        throw std::runtime_error(
            "ShmReader: mmap " + path_ + ": " + std::strerror(e));
    }

    // Best-effort magic/version check. Accept an all-zero header
    // (daemon hasn't published yet) and let the first tick pick up
    // the real values. Reject mismatched non-zero magic as a hard
    // layout incompatibility.
    const auto* base = static_cast<const std::uint8_t*>(mmap_base_);
    std::uint64_t magic = 0;
    std::memcpy(&magic, base, sizeof(magic));
    if (magic != 0 && magic != SHM_MAGIC) {
        ::munmap(mmap_base_, mmap_len_);
        ::close(fd_);
        fd_ = -1;
        mmap_base_ = nullptr;
        throw std::runtime_error("ShmReader: magic mismatch");
    }
}

ShmReader::~ShmReader() {
    stop();
    if (mmap_base_ && mmap_base_ != MAP_FAILED) {
        ::munmap(mmap_base_, mmap_len_);
        mmap_base_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

void ShmReader::start() {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;  // already running
    }
    thread_ = std::thread([this] { poll_loop(); });
}

void ShmReader::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    if (thread_.joinable()) {
        thread_.join();
    }
}

void ShmReader::set_port(Dart_Port_DL port) {
    port_.store(port, std::memory_order_release);
}

void ShmReader::poll_loop() {
    while (running_.load(std::memory_order_acquire)) {
        // Sleep first so a `stop()` immediately after `start()` on
        // an empty segment is a zero-cost shutdown.
        std::this_thread::sleep_for(POLL_INTERVAL);
        if (!running_.load(std::memory_order_acquire)) {
            break;
        }
        post_snapshot();
    }
}

void ShmReader::post_snapshot() {
    Dart_Port_DL port = port_.load(std::memory_order_acquire);
    if (port == 0 || mmap_base_ == nullptr) {
        return;
    }

    // Seqlock read: spin until the sequence is even (stable),
    // record it, then post. We intentionally do NOT copy the
    // payload -- the whole point of ExternalTypedData is that the
    // Dart Uint8List references the mmap directly. The daemon
    // writing while Dart reads is a theoretical torn-read risk
    // (~microseconds per 1 second tick, probability ~10^-6). Per
    // the v3 plan §3.6 this is accepted.
    auto* base = static_cast<std::uint8_t*>(mmap_base_);
    auto* seq_ptr = reinterpret_cast<std::uint64_t*>(base + SHM_SEQ_OFFSET);
    auto seq_atomic = std::atomic_ref<std::uint64_t>(*seq_ptr);

    std::uint64_t seq = 0;
    bool stable = false;
    for (int i = 0; i < SEQLOCK_RETRY_BUDGET; ++i) {
        seq = seq_atomic.load(std::memory_order_acquire);
        if ((seq & 1) == 0) {
            stable = true;
            break;
        }
        std::this_thread::yield();
    }
    if (!stable) {
        return;  // pathological: daemon stuck mid-write, skip tick
    }
    // seq == 0 means the daemon has never published (or it's a
    // fresh empty segment). Still post -- the Dart side can check
    // the magic/version before decoding.

    // Re-check stability after grabbing the pointer. If the writer
    // updated between our load and now, skip this tick rather than
    // post a possibly-torn snapshot. This is "best-effort" because
    // we have no synchronization with Dart actually reading the
    // bytes — see the comment above.
    std::uint64_t seq2 = seq_atomic.load(std::memory_order_acquire);
    if (seq2 != seq) {
        return;
    }

    Dart_CObject obj{};
    obj.type = Dart_CObject_kExternalTypedData;
    obj.value.as_external_typed_data.type = Dart_TypedData_kUint8;
    obj.value.as_external_typed_data.length =
        static_cast<intptr_t>(SHM_SNAPSHOT_SIZE);
    obj.value.as_external_typed_data.data = base;
    obj.value.as_external_typed_data.peer = nullptr;
    obj.value.as_external_typed_data.callback = &shm_external_finalizer;

    Dart_PostCObject_DL(port, &obj);
}

}  // namespace agl_health
