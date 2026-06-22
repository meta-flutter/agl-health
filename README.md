# agl-health

eBPF-based system health and security observability for Automotive Grade
Linux. A Rust/[aya](https://aya-rs.dev) kernel probe suite feeds a userspace
daemon that streams live CPU, scheduler, memory, block I/O, network,
per-cgroup bandwidth, and security-syscall telemetry to a Flutter dashboard
over POSIX shared memory and D-Bus.

## Architecture

```
  kernel ── eBPF probes (agl-health-ebpf, Rust/aya, no_std)
              │  ring buffers + per-CPU maps
              ▼
  userspace ─ agl-health-daemon (Rust)
              │  • drains events, polls maps once per second
              │  • /proc tier for memory + load + per-CPU utilization
              │  • POSIX shm  ── /dev/shm/agl-health-metrics (seqlock)
              │  • D-Bus      ── com.agl.health security event signals
              │  • REST + WebSocket ── 127.0.0.1:7777
              ▼
  client ──── agl-health-native (C++ FFI plugin) ── Flutter app
              (flutter_task_manager), run on ivi-homescreen
```

The wire layout of the shared-memory snapshot is shared between the writer
and readers through `agl-health-common`, and the cross-language field
offsets are guarded by the `v3_offsets_dump` test.

### Repository layout

| Path | Description |
| --- | --- |
| `agl-health-common` | Shared event/metric types and the shm layout |
| `agl-health-ebpf` | Kernel-side eBPF programs (nightly, `no_std`) |
| `agl-health-daemon` | Userspace loader, aggregator, shm/D-Bus/REST publishers |
| `agl-health-native` | C++ Flutter FFI plugin (shm reader + D-Bus subscriber) |
| `flutter_task_manager` | Flutter dashboard UI |
| `xtask` | Build orchestration (`cargo xtask ...`) |
| `third_party/sdbus-cpp` | D-Bus C++ bindings (git submodule) |

## Prerequisites

Clone with submodules:

```sh
git submodule update --init --recursive
```

**Rust / eBPF**

- A stable Rust toolchain for the host crates and a nightly toolchain with
  `rust-src` for the eBPF crate. Both are pinned via `rust-toolchain.toml`
  files and selected automatically.
- `bpf-linker`: `cargo install bpf-linker`
- To *load* the eBPF programs at runtime: Linux 5.5+ built with
  `CONFIG_DEBUG_INFO_BTF=y` (for the BTF tracepoints) and `CAP_BPF` +
  `CAP_PERFMON` (or root).

**C++ native plugin**

- A C++23 compiler (clang or gcc) and CMake ≥ 3.21.
- The Dart SDK headers (`dart_api_dl.h`/`.c`), taken from the Flutter-bundled
  Dart SDK by default.

**Flutter / Dart**

- The Flutter SDK (Dart ≥ 3.10).

**ivi-homescreen (drm-kms-egl backend)**

Host development packages: `libdrm`, `gbm`, `libegl`, `libgles2`,
`libinput`, `libxkbcommon`, `libseat`, `libudev`, and
`libdisplay-info` ≥ 0.2.0.

## Building

### eBPF + daemon

The eBPF crate compiles to `bpfel-unknown-none` and its object is embedded
into the daemon at build time. The `xtask` helper drives both stages:

```sh
cargo xtask build-ebpf                         # eBPF object only
cargo build -p agl-health-daemon --features ebpf
```

The daemon also builds *without* eBPF, in which case it serves only the
`/proc`-sourced memory, load, and per-CPU data and needs no special
toolchain or privileges:

```sh
cargo build -p agl-health-daemon               # no eBPF
```

Run the test suite (includes the shm layout contract):

```sh
cargo test
```

### Native plugin

```sh
cd agl-health-native/native
cmake -B build
cmake --build build          # produces libagl_health_native.so
```

### Flutter

```sh
cd flutter_task_manager
flutter pub get
flutter analyze
```

## Running the daemon

With eBPF (root or `CAP_BPF`+`CAP_PERFMON`):

```sh
sudo RUST_LOG=info target/debug/agl-health-daemon
```

Without eBPF (no privileges; `/proc` data only):

```sh
RUST_LOG=info target/debug/agl-health-daemon
```

The daemon publishes:

- shared memory at `/dev/shm/agl-health-metrics`,
- D-Bus signals on `com.agl.health` (system bus in production, with a
  development fallback to the session bus),
- a REST + WebSocket API on `127.0.0.1:7777` (override with
  `AGL_HEALTH_LISTEN`).

Inspect the live shared-memory snapshot at any time:

```sh
target/debug/agl-health-shm-dump
```

## Running the app on ivi-homescreen with emb_cli

The dashboard runs on
[ivi-homescreen](https://github.com/toyota-connected/ivi-homescreen),
built and assembled with
[emb_cli](https://github.com/toyota-connected/emb_cli). `emb` provisions a
workspace (Flutter SDK, engine, and the embedder source) and emits a
`setup_env.sh`; source it before invoking `emb`.

Build the `drm-kms-egl` embedder for the host and assemble a runnable bundle
that includes the release AOT app:

```sh
source setup_env.sh

emb cross app/ivi-homescreen \
    --target local --build --backend drm-kms-egl \
    --app /path/to/agl-health/flutter_task_manager --mode release
```

`emb` prints the runnable bundle directory (`runnable/`, containing
`homescreen`, `data/`, and `lib/`). The C++ plugin is loaded at runtime via
the `AGL_HEALTH_NATIVE_LIB` environment variable, so build it (above) and
point the embedder at it.

The `drm-kms-egl` backend needs DRM master, so run it from a free virtual
terminal with nothing else holding the display. `--drm-no-seat` opens the
DRM device directly instead of going through libseat:

```sh
cd <runnable-dir>
export AGL_HEALTH_NATIVE_LIB=/path/to/agl-health/agl-health-native/native/build/libagl_health_native.so
./homescreen --bundle . --drm-no-seat
```

Start the daemon (see above) so the app has live data; the shm reader
retries until the segment appears, so the app may be started in either
order.

## License

Apache License 2.0. See [LICENSE](LICENSE).
