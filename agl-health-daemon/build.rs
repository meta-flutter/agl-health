// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Build script for `agl-health-daemon`.
//!
//! When the `ebpf` cargo feature is enabled, this script drives the eBPF
//! sub-workspace (`../agl-health-ebpf`) to produce a BPF ELF object for the
//! `bpfel-unknown-none` target, then copies the resulting file into
//! `OUT_DIR` under a stable name so `loader.rs` can `include_bytes!` it.
//!
//! Design notes:
//!
//! * We invoke `cargo` directly rather than calling `aya-build` because our
//!   eBPF crate lives in its own sub-workspace (excluded from the host
//!   workspace to isolate nightly + `build-std`). Cargo-metadata-based
//!   discovery therefore can't see it, and shelling out is simpler.
//!
//! * The child `cargo` inherits the host's `RUSTUP_TOOLCHAIN` env var unless
//!   we scrub it. If we don't, the nightly pin in
//!   `agl-health-ebpf/rust-toolchain.toml` is ignored and the build fails on
//!   the `-Z build-std=core` flag. The `xtask` binary uses the same trick.
//!
//! * We pass an explicit `CARGO_TARGET_DIR` under `OUT_DIR` so the inner
//!   build does not contend with the outer build for the root
//!   `target/` directory's lock.
//!
//! When the feature is disabled this script does nothing beyond telling
//! cargo when to re-run.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

const EBPF_CRATE: &str = "agl-health-ebpf";
const EBPF_TARGET: &str = "bpfel-unknown-none";

fn main() -> Result<()> {
    // Always rerun if the build script itself changes.
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() {
        // Nothing to do: loader.rs will compile with an empty EBPF_OBJ.
        return Ok(());
    }

    // Escape hatch for CI / local type-checking without bpf-linker installed.
    // Writes an empty stub object into OUT_DIR so `include_bytes!` succeeds;
    // loader.rs then fails fast at runtime with "eBPF object is empty".
    println!("cargo:rerun-if-env-changed=AGL_HEALTH_SKIP_EBPF_BUILD");
    if std::env::var_os("AGL_HEALTH_SKIP_EBPF_BUILD").is_some() {
        let out_dir = PathBuf::from(env_var("OUT_DIR")?);
        let dest = out_dir.join("agl-health-ebpf.bin");
        std::fs::write(&dest, b"")
            .with_context(|| format!("write stub {}", dest.display()))?;
        println!("cargo:warning=AGL_HEALTH_SKIP_EBPF_BUILD set - using empty stub object");
        return Ok(());
    }

    let manifest_dir = PathBuf::from(env_var("CARGO_MANIFEST_DIR")?);
    let workspace_root = manifest_dir
        .parent()
        .context("daemon crate has no parent directory")?
        .to_path_buf();
    let ebpf_dir = workspace_root.join(EBPF_CRATE);
    if !ebpf_dir.join("Cargo.toml").is_file() {
        bail!(
            "{EBPF_CRATE}/Cargo.toml not found at {}",
            ebpf_dir.display()
        );
    }

    // Re-run stage 1 if any file under the eBPF crate changes.
    println!("cargo:rerun-if-changed={}", ebpf_dir.display());

    let out_dir = PathBuf::from(env_var("OUT_DIR")?);
    let ebpf_target_dir = out_dir.join("ebpf-target");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .arg("build")
        .arg("--release")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target")
        .arg(EBPF_TARGET)
        .arg("--target-dir")
        .arg(&ebpf_target_dir);
    // See "Design notes" above: scrub env vars cargo/rustup set for the
    // parent build that would override the eBPF sub-workspace's toolchain
    // and target-dir selection.
    for var in [
        "RUSTUP_TOOLCHAIN",
        // RUSTC / RUSTC_WRAPPER leak the parent's stable rustc into the
        // child cargo, which resolves to nightly cargo via rust-toolchain.toml
        // and then tries to invoke the inherited stable rustc with `-Z`.
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO",
        "CARGO_MANIFEST_DIR",
        "CARGO_PKG_NAME",
        "CARGO_PKG_VERSION",
        "CARGO_TARGET_DIR",
    ] {
        cmd.env_remove(var);
    }

    let status = cmd
        .status()
        .context("failed to spawn cargo for the eBPF build")?;
    if !status.success() {
        bail!(
            "eBPF build failed ({status}). Install bpf-linker with \
             `cargo install bpf-linker` if that is what failed."
        );
    }

    // The aya-ebpf build emits a single ELF named after the crate under
    // target/<target>/release/<crate>. Copy it to a stable path inside
    // OUT_DIR for `include_bytes!`.
    let built = ebpf_target_dir
        .join(EBPF_TARGET)
        .join("release")
        .join(EBPF_CRATE);
    if !built.is_file() {
        bail!(
            "expected eBPF object not found at {}",
            built.display()
        );
    }
    let dest = out_dir.join("agl-health-ebpf.bin");
    copy_file(&built, &dest)?;

    // Communicate the path to loader.rs via env!. The const is already
    // concat!(env!("OUT_DIR"), "/agl-health-ebpf.bin") so no extra var is
    // strictly required, but export a friendly name for diagnostics.
    println!("cargo:rustc-env=AGL_HEALTH_EBPF_OBJ={}", dest.display());
    Ok(())
}

fn env_var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    std::fs::copy(src, dst)
        .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
    Ok(())
}
