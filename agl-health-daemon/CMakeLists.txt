# SPDX-FileCopyrightText: 2026 AGL Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Thin CMake wrapper so emb can cross-compile the Rust daemon.
# emb provisions the toolchain and sysroot, then invokes
# cmake configure + cmake --build here.  This file bridges to cargo.
#
# emb calls only cmake --build (not cmake --install), so the binary must
# land inside CMAKE_BINARY_DIR for _artifactFor() to find it.  We copy
# it there under bin/agl-health-daemon — matching package.bin in emb.yaml.
#
# Using project(NONE) avoids C-language compiler detection, which would
# try to link a test program with the cross compiler before our custom
# flags are in scope and would mark CMAKE_C_COMPILER as broken.
# CMAKE_C_COMPILER and CMAKE_SYSROOT are plain cache variables set by the
# toolchain file and are available regardless of language enablement.
#
# Supported cross targets (not handled by emb — register before building):
#   rustup target add aarch64-unknown-linux-gnu
#   rustup target add x86_64-unknown-linux-gnu
#   rustup target add riscv64gc-unknown-linux-gnu

cmake_minimum_required(VERSION 3.21)
project(agl-health-daemon NONE)

# Workspace root is one level above this file (agl-health-daemon/../).
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH _ws_root)

# Enable eBPF programs embedded in the daemon.
# Prerequisites: rustup toolchain install nightly --component rust-src
#                rustup target add bpfel-unknown-none --toolchain nightly
# Pass -DENABLE_EBPF=ON on the cmake command line, or set it as a define
# in emb.yaml (cross.defines or per-target defines).
option(ENABLE_EBPF "Embed eBPF programs in the daemon (requires nightly + rust-src)" ON)

set(_cargo_args -p agl-health-daemon --release)
set(_env_args "")
if(ENABLE_EBPF)
    list(APPEND _cargo_args --features ebpf)
else()
    # build.rs skips the eBPF sub-workspace when this is set.
    list(APPEND _env_args "AGL_HEALTH_SKIP_EBPF_BUILD=1")
endif()

if(CMAKE_CROSSCOMPILING)
    # Map CMAKE_SYSTEM_PROCESSOR → (Rust target triple, Debian multiarch tuple).
    # CMAKE_SYSTEM_PROCESSOR is the *target* processor set by the toolchain file.
    set(_proc "${CMAKE_SYSTEM_PROCESSOR}")
    if(_proc STREQUAL "aarch64")
        set(_rust_target  "aarch64-unknown-linux-gnu")
        set(_multiarch    "aarch64-linux-gnu")
    elseif(_proc MATCHES "^(x86_64|amd64)$")
        set(_rust_target  "x86_64-unknown-linux-gnu")
        set(_multiarch    "x86_64-linux-gnu")
    elseif(_proc MATCHES "^riscv64")
        set(_rust_target  "riscv64gc-unknown-linux-gnu")
        set(_multiarch    "riscv64-linux-gnu")
    else()
        message(FATAL_ERROR
            "Unsupported cross target processor '${_proc}'. "
            "Add a mapping in CMakeLists.txt and a rustup target add entry.")
    endif()

    # Debian sysroots place C startup objects (Scrt1.o, crti.o) under the
    # multiarch subdirectory.  Add -B/-L so the linker finds them; omitting
    # these causes "cannot find Scrt1.o".
    set(_sysroot "${CMAKE_SYSROOT}")
    set(_ma  "${_sysroot}/usr/lib/${_multiarch}")
    set(_ma2 "${_sysroot}/lib/${_multiarch}")

    # CARGO_TARGET_<UPPER_TRIPLE>_* — upper-case, hyphens → underscores.
    string(TOUPPER "${_rust_target}" _rust_target_upper)
    string(REPLACE "-" "_" _rust_target_upper "${_rust_target_upper}")

    string(JOIN " " _rustflags
        "-C link-arg=--sysroot=${_sysroot}"
        "-C link-arg=-B${_ma}"
        "-C link-arg=-L${_ma}"
        "-C link-arg=-L${_ma2}"
    )
    list(APPEND _env_args
        "CARGO_TARGET_${_rust_target_upper}_LINKER=${CMAKE_C_COMPILER}"
        "CARGO_TARGET_${_rust_target_upper}_RUSTFLAGS=${_rustflags}"
    )
    list(APPEND _cargo_args --target "${_rust_target}")
    set(_cargo_bin
        "${_ws_root}/target/${_rust_target}/release/agl-health-daemon")
else()
    set(_cargo_bin "${_ws_root}/target/release/agl-health-daemon")
endif()

# Destination inside the cmake build dir — matches package.bin in emb.yaml.
set(_dest_bin "${CMAKE_BINARY_DIR}/bin/agl-health-daemon")

add_custom_target(agl-health-daemon-cargo ALL
    COMMAND ${CMAKE_COMMAND} -E env ${_env_args}
        cargo build ${_cargo_args}
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/bin"
    COMMAND ${CMAKE_COMMAND} -E copy "${_cargo_bin}" "${_dest_bin}"
    WORKING_DIRECTORY "${_ws_root}"
    COMMENT "cargo build agl-health-daemon"
    VERBATIM
)
