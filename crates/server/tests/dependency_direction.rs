//! Enforces the PLAN.md §7/§12 "server is blind" architecture rule: `wonton-server` must never
//! be able to receive a DEK or private key, which is guaranteed at compile time by forbidding
//! `wonton-crypto` anywhere in its dependency graph (normal, dev, or build). This walks the real
//! `Cargo.toml` files of `wonton-server` and every workspace path-dependency reachable from it,
//! so the test actually fails the moment someone adds the edge — it does not just assert a
//! hard-coded belief about the graph.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

const FORBIDDEN: &str = "wonton-crypto";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Returns the set of dependency crate names declared in any of
/// `[dependencies]` / `[dev-dependencies]` / `[build-dependencies]`, plus the filesystem path of
/// each `path = "..."` workspace-internal dependency (resolved relative to `crate_dir`).
fn direct_deps(crate_dir: &Path) -> (BTreeSet<String>, Vec<PathBuf>) {
    let manifest = std::fs::read_to_string(crate_dir.join("Cargo.toml"))
        .expect("crate Cargo.toml must be readable");
    let doc: toml::Value = manifest.parse().expect("crate Cargo.toml must be valid TOML");

    let mut names = BTreeSet::new();
    let mut path_deps = Vec::new();

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = doc.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, spec) in table {
            names.insert(name.clone());
            if let Some(rel_path) = spec.get("path").and_then(toml::Value::as_str) {
                path_deps.push(crate_dir.join(rel_path));
            }
        }
    }

    (names, path_deps)
}

/// Walks the full transitive closure of workspace-internal (`path = "..."`) dependencies
/// starting from `wonton-server`'s own `Cargo.toml`, across every dependency kind, and asserts
/// `wonton-crypto` is never named — directly or transitively.
#[test]
fn server_never_depends_on_wonton_crypto_directly_or_transitively() {
    let start = manifest_dir();
    let mut queue: VecDeque<PathBuf> = VecDeque::from([start]);
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    let mut all_dep_names: BTreeSet<String> = BTreeSet::new();

    while let Some(dir) = queue.pop_front() {
        let canon = dir.canonicalize().unwrap_or(dir.clone());
        if !visited.insert(canon) {
            continue;
        }
        let (names, path_deps) = direct_deps(&dir);
        all_dep_names.extend(names);
        queue.extend(path_deps);
    }

    assert!(
        !all_dep_names.contains(FORBIDDEN),
        "wonton-server's dependency graph must never contain `{FORBIDDEN}` (server-blindness \
         rule, PLAN.md §7/§12) — found it. The server must never be able to hold or receive a \
         DEK or private key.",
    );
}
