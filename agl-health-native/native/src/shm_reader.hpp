// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0
//
// ShmReader: mmaps /dev/shm/agl-health-metrics read-only, spins a
// background std::thread that seqlock-reads the segment at 1 Hz and
// posts the stable snapshot pointer to Dart via
// Dart_PostCObject_DL(Dart_CObject_kExternalTypedData).
//
// Phase 2 scope: one channel, one thread. When Phase 5 adds asio for
// the Unix socket channel, this class will be rewritten to share the
// plugin-wide io_context via an asio::steady_timer instead of the
// current std::thread + std::this_thread::sleep_for loop. The public
// API (start / stop / set_port) stays the same across that change.

#ifndef AGL_HEALTH_SHM_READER_HPP
#define AGL_HEALTH_SHM_READER_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "dart_api_dl.h"

namespace agl_health {

/// Byte offset of `ShmHeader.sequence` inside `MetricSnapshotV3`.
///
/// This MUST match the Rust-side constant derived from nested
/// `offset_of!(MetricSnapshotV3, header)` +
/// `offset_of!(ShmHeader, sequence)`. The Rust side is the source of
/// truth; if this drifts, the seqlock breaks silently. Keeping both
/// numbers as named constants in their respective source files is
/// the best we have until a shared codegen'd header exists
/// (Phase 4 or later).
///
/// Current layout (Phase 0/1):
///   ShmHeader @ 0:
///     magic            u64 @ 0
///     version          u32 @ 8
///     _pad0            u32 @ 12
///     sequence         u64 @ 16   <-- here
///     timestamp_ns_wall u64 @ 24
///     snapshot_size    u32 @ 32
///     _pad1            u32 @ 36
///     _reserved        [u8; 24] @ 40
///     (total 64 bytes)
constexpr std::size_t SHM_SEQ_OFFSET = 16;

/// Expected snapshot size in bytes. Must match
/// `MetricSnapshotV3::SIZE` on the Rust side. Reader validates this
/// at open time so a mismatch fails loud rather than producing
/// garbage.
constexpr std::size_t SHM_SNAPSHOT_SIZE = 70552;

/// Expected magic constant in `ShmHeader.magic` (ASCII "AGL_HELT").
constexpr std::uint64_t SHM_MAGIC = 0x41474C5F48454C54ULL;

/// Expected header version.
constexpr std::uint32_t SHM_VERSION = 1;

class ShmReader {
 public:
  /// Construct with a path but do NOT open/mmap yet. The poll
  /// loop calls `try_connect()` on each tick until the shm segment
  /// appears. This lets the Flutter app start before the daemon
  /// without throwing or failing permanently.
  explicit ShmReader(std::string path);
  ~ShmReader();

  ShmReader(const ShmReader&) = delete;
  ShmReader& operator=(const ShmReader&) = delete;

  /// Start the polling thread. Idempotent (no-op if already
  /// running). Thread loops at 1 Hz, performs a seqlock read,
  /// and posts to the currently-registered Dart port.
  void start();

  /// Stop the polling thread and join. Blocks until the thread
  /// exits. Idempotent.
  void stop();

  /// Update the destination Dart port. Passing 0 pauses posts.
  /// Safe to call from any thread (stored via `atomic<int64_t>`).
  void set_port(Dart_Port_DL port);

 private:
  void poll_loop();
  bool try_connect();
  void disconnect();
  void post_snapshot();

  std::string path_;
  int fd_{-1};
  void* mmap_base_{nullptr};
  std::size_t mmap_len_{0};

  /// Reusable destination for the seqlock copy. The snapshot is copied
  /// out of the live mmap into this owned buffer under the seqlock and
  /// the *copy* is posted to Dart, so a writer rewriting the segment on
  /// the next tick can never tear a read the Dart isolate is consuming.
  std::vector<std::uint8_t> snapshot_buf_;
  /// Even sequence value of the last snapshot posted, so we can skip
  /// re-posting (and re-copying ~70 KB) when nothing has changed.
  std::uint64_t last_posted_seq_{0};

  std::atomic<Dart_Port_DL> port_{0};
  std::atomic<bool> running_{false};
  std::thread thread_;
};

}  // namespace agl_health

#endif  // AGL_HEALTH_SHM_READER_HPP
