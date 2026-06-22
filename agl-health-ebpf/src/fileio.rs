// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-pid file I/O byte accounting.
//!
//! Hooks `vfs_read` and `vfs_write` on entry. Both take the same
//! signature:
//!
//! ```c
//! ssize_t vfs_read (struct file *file, char __user *buf, size_t count, loff_t *pos);
//! ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos);
//! ```
//!
//! We accumulate the `count` argument into `PROCESS_STATS[pid]`.
//! This slightly overestimates on short reads (where the caller
//! requested more than the file had), but avoids needing a kretprobe
//! with entry/exit pairing and keeps the program small. A future pass
//! can switch to `#[kretprobe]` for exact byte counts from the return
//! value.

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::kprobe, programs::ProbeContext};

/// `kprobe:vfs_read` - accumulate the requested byte count.
#[kprobe]
pub fn vfs_read(ctx: ProbeContext) -> u32 {
    let count: usize = ctx.arg(2).unwrap_or(0);
    if count == 0 {
        return 0;
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(p) = crate::stats::upsert(pid) {
        // SAFETY: pointer into a HashMap slot that lives for the
        // duration of this program; preemption is disabled.
        unsafe {
            (*p).pid = pid;
            (*p).read_bytes = (*p).read_bytes.wrapping_add(count as u64);
        }
    }
    0
}

/// `kprobe:vfs_write` - accumulate the requested byte count.
#[kprobe]
pub fn vfs_write(ctx: ProbeContext) -> u32 {
    let count: usize = ctx.arg(2).unwrap_or(0);
    if count == 0 {
        return 0;
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(p) = crate::stats::upsert(pid) {
        unsafe {
            (*p).pid = pid;
            (*p).write_bytes = (*p).write_bytes.wrapping_add(count as u64);
        }
    }
    0
}
