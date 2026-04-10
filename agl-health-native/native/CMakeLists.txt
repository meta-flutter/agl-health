# C++23 native plugin for the AGL health Flutter app.
#
# Phase 2 scope: one channel only -- the POSIX shared memory metrics
# reader. No asio, no glaze, no sdbus-cpp. Those come in later phases:
#
#   Phase 5 adds asio + glaze for the Unix socket / high-freq event
#   channel, at which point the current std::thread polling loop in
#   shm_reader.cpp is replaced with an asio steady_timer sharing the
#   plugin-wide io_context.
#
#   Phase 6 adds sdbus-cpp for the D-Bus security / OOM signal channel.
#
# Building standalone (for the shm_smoke.dart test):
#
#   . /mnt/raid10/workspace-automation/setup_env.sh
#   cd agl-health-native/native
#   cmake -B build
#   cmake --build build
#
# `DART_SDK_DIR` defaults to the Flutter-bundled Dart SDK if not set
# explicitly. The Flutter build hook (Phase 3, hook/build.dart) will
# pass it in from `buildConfig`.
cmake_minimum_required(VERSION 3.21)
# C is enabled so CMake compiles dart_api_dl.c as a C translation unit
# rather than silently skipping it. Without this, the _DL function
# pointers stay as unresolved symbols and the resulting .so fails to
# load at runtime with "undefined symbol: Dart_PostCObject_DL".
project(agl_health_native CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Dart SDK headers (dart_api_dl.h + dart_api_dl.c) must be compiled
# into this shared object so Dart_InitializeApiDL / Dart_PostCObject_DL
# are callable from our code. Default points at the Flutter-bundled
# Dart SDK on the dev host; override via `-DDART_SDK_DIR=...` for
# cross-compile or Yocto builds.
set(DART_SDK_DIR
    "/mnt/raid10/workspace-automation/flutter/bin/cache/dart-sdk"
    CACHE PATH "Path to the Dart SDK containing include/dart_api_dl.{h,c}")

if(NOT EXISTS "${DART_SDK_DIR}/include/dart_api_dl.h")
    message(FATAL_ERROR
        "DART_SDK_DIR=${DART_SDK_DIR} does not contain include/dart_api_dl.h. "
        "Set -DDART_SDK_DIR to the Dart SDK root (for the Flutter bundle, "
        "that is <flutter>/bin/cache/dart-sdk).")
endif()

add_library(agl_health_native SHARED
    src/plugin_main.cpp
    src/shm_reader.cpp
    "${DART_SDK_DIR}/include/dart_api_dl.c"
)

target_include_directories(agl_health_native PRIVATE
    include
    "${DART_SDK_DIR}/include"
    # agl-health-common's generated types would normally live here too,
    # but for Phase 2 we only touch the shm segment via byte offsets;
    # see shm_reader.cpp for the hardcoded SEQ_OFFSET constant (which
    # matches the Rust-side offset_of! output).
)

target_compile_options(agl_health_native PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

# The Dart SDK's dart_api_dl.c casts between void* and function pointers,
# which is valid POSIX but triggers -Wpedantic in strict ISO C mode.
# Suppress pedantic warnings for that file only.
set_source_files_properties("${DART_SDK_DIR}/include/dart_api_dl.c"
    PROPERTIES COMPILE_OPTIONS "-Wno-pedantic"
)

set_target_properties(agl_health_native PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
)

# Exported C ABI symbols are marked with __attribute__((visibility("default")))
# in agl_health_plugin.h; everything else stays hidden.
target_compile_definitions(agl_health_native PRIVATE
    AGL_HEALTH_PLUGIN_EXPORTS
)

# std::thread and atomics need pthread on Linux.
find_package(Threads REQUIRED)
target_link_libraries(agl_health_native PRIVATE Threads::Threads)
