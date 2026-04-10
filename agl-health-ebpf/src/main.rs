//! Kernel-side eBPF programs for the AGL system health daemon.
//!
//! This crate compiles to `bpfel-unknown-none` and its object files are
//! embedded into the userspace daemon via `include_bytes_aligned!` at build
//! time. It shares the `agl-health-common` crate with the daemon so that
//! every event/metric struct has a single source of truth.
//!
//! Programs are grouped into one Rust module per subsystem. Each module
//! declares its own tracepoint / kprobe entry points with the appropriate
//! `aya_ebpf` macros. `main.rs` only wires the modules together and
//! provides the mandatory `#![no_main]` panic handler.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

mod block;
mod cpu;
mod fileio;
mod memory;
mod netproc;
mod network;
mod offsets;
mod process;
mod scheduler;
mod security;
mod stats;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    unsafe_op_in_unsafe_fn,
    clippy::all
)]
mod vmlinux;

/// The BPF verifier rejects unwinding code paths, so we must abort on panic.
/// The infinite loop is unreachable in practice - any panic inside a BPF
/// program is a bug that should be fixed before the program is loaded.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
