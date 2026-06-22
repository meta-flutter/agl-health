// SPDX-FileCopyrightText: 2026 AGL Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup ID → name resolver.
//!
//! Walks `/sys/fs/cgroup` (cgroup v2 unified hierarchy) recursively,
//! stat-ing each directory to get its inode number. The inode is the
//! `cgroup_id` that `bpf_get_current_cgroup_id()` returns in the
//! kernel-side cgroup_skb programs.
//!
//! The mapping is cached in an `Arc<RwLock<HashMap<u64, String>>>`
//! and refreshed every 30 seconds by a tokio task. Cgroup creation
//! and deletion are relatively infrequent on an IVI system, so the
//! 30s staleness window is acceptable — a newly-started service
//! will initially appear as its numeric cgroup_id, then get a name
//! on the next refresh.
//!
//! The "name" is the cgroup path relative to `/sys/fs/cgroup/`, e.g.
//! `system.slice/sshd.service` or `user.slice/user-1000.slice`.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, warn};

/// Path of the cgroup v2 unified hierarchy root.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// How often to re-scan the cgroup tree. 30 seconds is a good
/// balance between freshness (new services show a name within
/// half a minute) and cost (one recursive directory walk).
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Shared handle to the name cache. Read by the API layer, written
/// by the refresh task.
pub type CgroupNameCache = Arc<RwLock<HashMap<u64, String>>>;

/// Spawn the cgroup name refresh task. Returns the shared cache
/// handle that the API layer should clone into its state.
pub fn spawn_resolver() -> CgroupNameCache {
    let cache: CgroupNameCache = Arc::new(RwLock::new(HashMap::new()));
    let cache_clone = cache.clone();
    tokio::spawn(async move {
        let mut ticker = interval(REFRESH_INTERVAL);
        loop {
            ticker.tick().await;
            let names = scan_cgroup_tree();
            let count = names.len();
            *cache_clone.write().await = names;
            debug!(count, "cgroup name cache refreshed");
        }
    });
    cache
}

/// Walk `/sys/fs/cgroup` and build the inode → relative-path map.
fn scan_cgroup_tree() -> HashMap<u64, String> {
    let root = Path::new(CGROUP_ROOT);
    let mut map = HashMap::new();
    if !root.is_dir() {
        warn!(path = CGROUP_ROOT, "cgroup root not found");
        return map;
    }
    walk_dir(root, root, &mut map, 0);
    map
}

/// Maximum directory nesting to descend into. The real cgroup tree is
/// only a handful of levels deep; this is a guard against a symlink loop
/// or a maliciously-deep mount turning the recursion into a stack
/// overflow.
const MAX_DEPTH: usize = 32;

fn walk_dir(dir: &Path, root: &Path, map: &mut HashMap<u64, String>, depth: usize) {
    if depth > MAX_DEPTH {
        warn!(path = %dir.display(), "cgroup walk depth limit reached - subtree skipped");
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    // Stat the current directory itself.
    if let Ok(meta) = std::fs::metadata(dir) {
        let ino = meta.ino();
        let rel = dir
            .strip_prefix(root)
            .unwrap_or(dir)
            .to_string_lossy()
            .into_owned();
        let name = if rel.is_empty() {
            "(root)".to_string()
        } else {
            rel
        };
        map.insert(ino, name);
    }
    for entry in entries.flatten() {
        // Use the DirEntry file type, which does NOT follow symlinks, so
        // a symlink pointing back up the tree can't create an infinite
        // loop. Real cgroup entries are genuine directories.
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => walk_dir(&entry.path(), root, map, depth + 1),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_finds_root() {
        let map = scan_cgroup_tree();
        // On any system with cgroup v2, the root inode should be present.
        if Path::new(CGROUP_ROOT).is_dir() {
            assert!(
                !map.is_empty(),
                "cgroup tree scan found no entries"
            );
            assert!(
                map.values().any(|v| v == "(root)"),
                "cgroup root entry missing"
            );
        }
    }
}
