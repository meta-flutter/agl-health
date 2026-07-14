// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Build orchestration for the agl-health workspace.
//!
//! Aya requires a two-stage build:
//!
//!   1. `agl-health-ebpf` is compiled for the `bpfel-unknown-none` target,
//!      producing BPF bytecode objects.
//!   2. `agl-health-daemon` is then built for the host (or a cross target),
//!      embedding the bytecode via `include_bytes_aligned!` at compile time.
//!
//! This xtask binary wraps those stages behind simple subcommands so the
//! root-level `cargo xtask ...` alias (see `.cargo/config.toml`) is the only
//! build entry point developers need to know.
//!
//! Subcommands:
//!   * `build-ebpf`  - stage 1 only
//!   * `build`       - stage 1 + stage 2
//!   * `run`         - stage 1 + stage 2 + `sudo target/<profile>/agl-health-daemon`
//!   * `clean`       - `cargo clean` on both stages
//!
//! The eBPF and daemon crates may not exist yet (they are scaffolded in later
//! steps). When a referenced crate is missing this tool prints a clear
//! warning and skips that stage rather than failing the whole build, so the
//! workspace stays buildable as crates land one by one.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

/// Name of the eBPF crate (stage 1 target).
const EBPF_CRATE: &str = "agl-health-ebpf";
/// Name of the userspace daemon crate (stage 2 target).
const DAEMON_CRATE: &str = "agl-health-daemon";
/// Target triple for all eBPF programs - little-endian, no host OS.
const EBPF_TARGET: &str = "bpfel-unknown-none";

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Build orchestration for the agl-health workspace",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Stage 1: compile the eBPF crate to BPF bytecode.
    BuildEbpf(BuildOpts),
    /// Stage 1 + Stage 2: compile eBPF and the userspace daemon.
    Build(BuildOpts),
    /// Build everything then launch the daemon under sudo.
    Run(RunOpts),
    /// `cargo clean` for both stages.
    Clean,
    /// Generate `agl-health-ebpf/src/vmlinux.rs` from the host's BTF.
    /// Requires `aya-tool` (install with `cargo install aya-tool`) and
    /// a kernel built with `CONFIG_DEBUG_INFO_BTF=y` so
    /// `/sys/kernel/btf/vmlinux` exists. Run this once per development
    /// host, then commit the result - the file is stable across minor
    /// kernel revisions.
    GenVmlinux(GenVmlinuxOpts),
}

#[derive(Parser)]
struct BuildOpts {
    /// Build profile for the userspace daemon (stage 2 only).
    #[arg(long, value_enum, default_value_t = Profile::Debug)]
    profile: Profile,
    /// Optional target triple for the userspace daemon (cross-compile).
    /// The eBPF stage always targets `bpfel-unknown-none` regardless.
    #[arg(long)]
    target: Option<String>,
    /// Enable kernel-5-4 compatibility mode: passes `--features kernel-5-4`
    /// to both the eBPF and daemon build stages.
    #[arg(long)]
    kernel_5_4: bool,
}

#[derive(Parser)]
struct GenVmlinuxOpts {
    /// Path to a pre-generated vmlinux C header to use as input instead of
    /// the running host's `/sys/kernel/btf/vmlinux`. Use this to generate
    /// `vmlinux.rs` for a kernel other than the host, e.g.:
    ///   cargo xtask gen-vmlinux --header btf/generated/vmlinux_5.4.219-perf.h
    #[arg(long)]
    header: Option<PathBuf>,
}

#[derive(Parser)]
struct RunOpts {
    #[command(flatten)]
    build: BuildOpts,
    /// Extra arguments forwarded to the daemon binary.
    #[arg(last = true)]
    args: Vec<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Profile {
    Debug,
    Release,
}

impl Profile {
    fn as_str(self) -> &'static str {
        match self {
            Profile::Debug => "debug",
            Profile::Release => "release",
        }
    }

    fn cargo_flag(self) -> Option<&'static str> {
        match self {
            Profile::Debug => None,
            Profile::Release => Some("--release"),
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::BuildEbpf(opts) => build_ebpf(&opts),
        Cmd::Build(opts) => {
            build_ebpf(&opts)?;
            build_daemon(&opts)
        }
        Cmd::Run(opts) => {
            build_ebpf(&opts.build)?;
            build_daemon(&opts.build)?;
            run_daemon(&opts)
        }
        Cmd::Clean => clean(),
        Cmd::GenVmlinux(opts) => gen_vmlinux(&opts),
    }
}

/// Absolute path of the workspace root (directory containing this xtask crate).
fn workspace_root() -> Result<PathBuf> {
    // xtask's Cargo.toml lives at <root>/xtask/Cargo.toml, so CARGO_MANIFEST_DIR
    // of this binary gives us <root>/xtask. Its parent is the workspace root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .parent()
        .map(Path::to_path_buf)
        .context("xtask manifest dir has no parent - workspace layout broken")
}

/// Return `Some(path)` to the crate directory if it exists, otherwise `None`.
fn crate_dir(name: &str) -> Result<Option<PathBuf>> {
    let root = workspace_root()?;
    let dir = root.join(name);
    if dir.join("Cargo.toml").is_file() {
        Ok(Some(dir))
    } else {
        Ok(None)
    }
}

fn build_ebpf(opts: &BuildOpts) -> Result<()> {
    let Some(ebpf_dir) = crate_dir(EBPF_CRATE)? else {
        eprintln!(
            "xtask: skipping stage 1 - {EBPF_CRATE}/Cargo.toml does not exist yet. \
             This is expected until the eBPF crate is scaffolded."
        );
        return Ok(());
    };

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .arg("build")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target")
        .arg(EBPF_TARGET);
    // eBPF code is always built with release-like optimization because the
    // verifier rejects most debug-mode code; we honor --profile for parity but
    // still default to release for stage 1.
    if matches!(opts.profile, Profile::Release) {
        cmd.arg("--release");
    } else {
        cmd.arg("--release");
    }
    if opts.kernel_5_4 {
        cmd.arg("--features").arg("kernel-5-4");
    }
    status(cmd, "cargo build (eBPF stage)")
}

fn build_daemon(opts: &BuildOpts) -> Result<()> {
    if crate_dir(DAEMON_CRATE)?.is_none() {
        eprintln!(
            "xtask: skipping stage 2 - {DAEMON_CRATE}/Cargo.toml does not exist yet. \
             This is expected until the daemon crate is scaffolded."
        );
        return Ok(());
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("-p").arg(DAEMON_CRATE);
    if let Some(flag) = opts.profile.cargo_flag() {
        cmd.arg(flag);
    }
    if let Some(target) = &opts.target {
        cmd.arg("--target").arg(target);
    }
    let mut features = vec!["ebpf"];
    if opts.kernel_5_4 {
        features.push("kernel-5-4");
    }
    cmd.arg("--features").arg(features.join(","));
    status(cmd, "cargo build (daemon stage)")
}

fn run_daemon(opts: &RunOpts) -> Result<()> {
    let Some(_) = crate_dir(DAEMON_CRATE)? else {
        bail!("cannot run: {DAEMON_CRATE} has not been scaffolded yet");
    };

    let root = workspace_root()?;
    let mut bin = root.join("target");
    if let Some(target) = &opts.build.target {
        bin.push(target);
    }
    bin.push(opts.build.profile.as_str());
    bin.push(DAEMON_CRATE);

    if !bin.is_file() {
        bail!(
            "daemon binary not found at {} - did stage 2 build succeed?",
            bin.display()
        );
    }

    // eBPF program loading requires CAP_BPF + CAP_PERFMON (or root on older
    // kernels). Wrap with sudo for development convenience; production
    // deployments should grant capabilities via systemd unit instead.
    let mut cmd = Command::new("sudo");
    cmd.arg("-E").arg(&bin).args(&opts.args);
    status(cmd, "run daemon")
}

fn clean() -> Result<()> {
    let root = workspace_root()?;
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root).arg("clean");
    status(cmd, "cargo clean")
}

/// Kernel types to emit into `vmlinux.rs`. Keep the list small and only
/// add types that a probe actually needs - every additional type
/// expands the generated file and slows incremental ebpf rebuilds.
const VMLINUX_TYPES: &[&str] = &[
    "task_struct",
    "sock",
    "sock_common",
    "inet_sock",
];

const VMLINUX_OUTPUT: &str = "agl-health-ebpf/src/vmlinux.rs";

/// Generate `agl-health-ebpf/src/vmlinux.rs` from the host's BTF via
/// `aya-tool generate`. This is a **developer** command, not part of the
/// normal build - the generated file is committed to the repo so
/// end-users never need `aya-tool`, `bpftool`, or host BTF available.
fn gen_vmlinux(opts: &GenVmlinuxOpts) -> Result<()> {
    let root = workspace_root()?;
    let out_path = root.join(VMLINUX_OUTPUT);

    let mut cmd = Command::new("aya-tool");
    cmd.arg("generate");
    for t in VMLINUX_TYPES {
        cmd.arg(t);
    }

    // Resolve the BTF source. With --header, aya-tool reads a pre-generated
    // vmlinux C header directly (no bpftool needed). Without it, aya-tool
    // falls back to /sys/kernel/btf/vmlinux via bpftool, which requires the
    // running kernel to have CONFIG_DEBUG_INFO_BTF=y and bpftool installed.
    let source_desc: String = match &opts.header {
        Some(p) => {
            // Allow relative paths resolved against the workspace root so
            // callers can write `--header btf/generated/...` without an
            // absolute path.
            let resolved = if p.is_absolute() { p.clone() } else { root.join(p) };
            if !resolved.is_file() {
                bail!("--header {}: file not found", resolved.display());
            }
            cmd.arg("--header").arg(&resolved);
            resolved.display().to_string()
        }
        None => {
            let host = Path::new("/sys/kernel/btf/vmlinux");
            if !host.exists() {
                bail!(
                    "{} is missing - rebuild the host kernel with CONFIG_DEBUG_INFO_BTF=y, \
                     or supply a header file with --header",
                    host.display()
                );
            }
            // No extra flag needed; aya-tool defaults to the host BTF.
            host.display().to_string()
        }
    };

    // aya-tool writes the generated bindings to stdout, so we capture
    // stdout explicitly rather than letting it merge with our own.
    cmd.stdout(std::process::Stdio::piped());
    clean_cargo_env(&mut cmd);

    let output = cmd
        .output()
        .context("failed to spawn `aya-tool generate` - install with `cargo install aya-tool`")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("aya-tool generate failed ({}): {stderr}", output.status);
    }

    std::fs::write(&out_path, &output.stdout)
        .with_context(|| format!("write {}", out_path.display()))?;
    eprintln!(
        "xtask: wrote {} ({} bytes) covering {} types from {}",
        out_path.display(),
        output.stdout.len(),
        VMLINUX_TYPES.len(),
        source_desc,
    );
    Ok(())
}

/// Strip environment variables that cargo/rustup set for the xtask process
/// and would otherwise leak into spawned child cargo invocations. Most
/// importantly `RUSTUP_TOOLCHAIN`: if inherited, the child cargo uses the
/// xtask's host toolchain (stable) and ignores the `rust-toolchain.toml` in
/// the eBPF crate directory, which breaks the two-stage build.
fn clean_cargo_env(cmd: &mut Command) {
    for var in [
        "RUSTUP_TOOLCHAIN",
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
}

/// Run a command, inheriting stdio, and convert non-zero exits into errors
/// tagged with a human-readable stage name.
fn status(mut cmd: Command, label: &str) -> Result<()> {
    clean_cargo_env(&mut cmd);
    let exit = cmd
        .status()
        .with_context(|| format!("failed to spawn `{label}`"))?;
    if !exit.success() {
        bail!("`{label}` failed with {exit}");
    }
    Ok(())
}
