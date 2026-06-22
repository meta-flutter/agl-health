// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

#include "shm_reader.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace agl_health {

namespace {

constexpr auto POLL_INTERVAL = std::chrono::seconds(1);
constexpr int SEQLOCK_RETRY_BUDGET = 64;

}  // namespace

ShmReader::ShmReader(std::string path) : path_(std::move(path)) {
  // Lazy initialization: don't open/mmap here. The poll_loop
  // will call try_connect() on each tick until the shm segment
  // appears. This lets the Flutter app start before the daemon.
}

ShmReader::~ShmReader() {
  stop();
  disconnect();
}

void ShmReader::start() {
  if (running_.exchange(true, std::memory_order_acq_rel)) {
    return;
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
    std::this_thread::sleep_for(POLL_INTERVAL);
    if (!running_.load(std::memory_order_acquire)) {
      break;
    }

    // If not connected yet, try to open the shm segment.
    // This handles the "Flutter starts before daemon" case:
    // we retry every tick until the file appears.
    if (mmap_base_ == nullptr) {
      try_connect();
      if (mmap_base_ == nullptr) {
        continue;  // Still not available, try next tick.
      }
    }

    post_snapshot();
  }
}

bool ShmReader::try_connect() {
  fd_ = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd_ < 0) {
    return false;  // File doesn't exist yet — daemon not running.
  }

  struct stat st{};
  if (::fstat(fd_, &st) != 0 ||
      static_cast<std::size_t>(st.st_size) < SHM_SNAPSHOT_SIZE) {
    ::close(fd_);
    fd_ = -1;
    return false;  // File exists but wrong size — stale or truncated.
  }

  mmap_len_ = SHM_SNAPSHOT_SIZE;
  mmap_base_ = ::mmap(nullptr, mmap_len_, PROT_READ, MAP_SHARED, fd_, 0);
  if (mmap_base_ == MAP_FAILED) {
    ::close(fd_);
    fd_ = -1;
    mmap_base_ = nullptr;
    return false;
  }

  // Re-stat AFTER mapping to close the TOCTOU window between the
  // earlier fstat and mmap: if the file was truncated shorter in
  // between, the mapping now covers a hole and touching it would
  // SIGBUS. Reject and retry next tick.
  struct stat st2{};
  if (::fstat(fd_, &st2) != 0 ||
      static_cast<std::size_t>(st2.st_size) < SHM_SNAPSHOT_SIZE) {
    disconnect();
    return false;
  }

  // Best-effort magic check. Accept all-zero (daemon hasn't
  // published yet). Reject wrong non-zero magic (layout mismatch).
  const auto* base = static_cast<const std::uint8_t*>(mmap_base_);
  std::uint64_t magic = 0;
  std::memcpy(&magic, base, sizeof(magic));
  if (magic != 0 && magic != SHM_MAGIC) {
    disconnect();
    return false;
  }

  return true;
}

void ShmReader::disconnect() {
  if (mmap_base_ && mmap_base_ != MAP_FAILED) {
    ::munmap(mmap_base_, mmap_len_);
    mmap_base_ = nullptr;
  }
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

void ShmReader::post_snapshot() {
  Dart_Port_DL port = port_.load(std::memory_order_acquire);
  if (port == 0 || mmap_base_ == nullptr) {
    return;
  }

  auto* base = static_cast<std::uint8_t*>(mmap_base_);
  auto* seq_ptr = reinterpret_cast<std::uint64_t*>(base + SHM_SEQ_OFFSET);
  auto seq_atomic = std::atomic_ref<std::uint64_t>(*seq_ptr);

  // Full seqlock read: copy the body into our owned buffer between two
  // reads of the sequence and accept only if it stayed even and equal.
  // Copying (rather than handing Dart a pointer into the live mmap) is
  // what makes the read safe — the writer rewrites the same bytes every
  // tick, so an external view would tear once the isolate consumed it
  // lazily.
  if (snapshot_buf_.size() != SHM_SNAPSHOT_SIZE) {
    snapshot_buf_.resize(SHM_SNAPSHOT_SIZE);
  }

  std::uint64_t seq = 0;
  bool stable = false;
  for (int i = 0; i < SEQLOCK_RETRY_BUDGET; ++i) {
    std::uint64_t s1 = seq_atomic.load(std::memory_order_acquire);
    if (s1 & 1) {
      std::this_thread::yield();  // writer mid-update
      continue;
    }
    std::atomic_thread_fence(std::memory_order_acquire);
    std::memcpy(snapshot_buf_.data(), base, SHM_SNAPSHOT_SIZE);
    std::atomic_thread_fence(std::memory_order_acquire);
    std::uint64_t s2 = seq_atomic.load(std::memory_order_acquire);
    if (s1 == s2) {
      seq = s1;
      stable = true;
      break;
    }
    // Torn read (writer ran during the copy) — retry.
  }
  if (!stable) {
    return;
  }

  // Skip re-posting an unchanged snapshot: saves ~70 KB copy + an
  // isolate wakeup every idle tick.
  if (seq != 0 && seq == last_posted_seq_) {
    return;
  }
  last_posted_seq_ = seq;

  // Post a COPY (kTypedData), which the VM serializes into the message
  // synchronously, so snapshot_buf_ is free to be reused next tick.
  Dart_CObject obj{};
  obj.type = Dart_CObject_kTypedData;
  obj.value.as_typed_data.type = Dart_TypedData_kUint8;
  obj.value.as_typed_data.length = static_cast<intptr_t>(SHM_SNAPSHOT_SIZE);
  obj.value.as_typed_data.values = snapshot_buf_.data();

  Dart_PostCObject_DL(port, &obj);
}

}  // namespace agl_health
