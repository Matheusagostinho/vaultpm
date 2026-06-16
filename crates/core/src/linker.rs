//! Materialise the resolved graph into a pnpm-style **isolated** `node_modules`.
//!
//! ## Layout (phase 4)
//!
//! ```text
//! node_modules/
//! ├── .vault/                          ← virtual store
//! │   └── <name>@<ver>/node_modules/
//! │       ├── <name>/                  ← real files (hard-linked from the store)
//! │       └── <dep>  → ../../<dep>@<ver>/node_modules/<dep>   (symlink)
//! └── <root>  → .vault/<root>@<ver>/node_modules/<root>       (symlink)
//! ```
//!
//! Because Node resolves a package's dependencies relative to its *realpath*,
//! each package can only `require` the dependencies it actually declared — there
//! is no accidental hoisting, and multiple versions coexist cleanly.

use crate::error::Result;
use crate::resolver::Resolution;
use crate::store::Store;
use std::path::{Path, PathBuf};

/// Build the isolated `node_modules` for the resolved graph.
pub fn link_all(store: &Store, resolution: &Resolution, project_dir: &Path) -> Result<()> {
    let project_abs =
        std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let node_modules = project_abs.join("node_modules");
    let virtual_store = node_modules.join(".vault");

    // Clean slate for a deterministic install.
    if node_modules.exists() {
        std::fs::remove_dir_all(&node_modules)?;
    }
    std::fs::create_dir_all(&virtual_store)?;

    // 1. Materialise every package's files into the virtual store.
    for pkg in resolution.packages.values() {
        let pkg_root = virtual_store
            .join(sanitize(&pkg.id()))
            .join("node_modules")
            .join(&pkg.name);
        std::fs::create_dir_all(&pkg_root)?;
        let index = store.read_index(&pkg.name, &pkg.version)?;
        store.materialize(&index, &pkg_root)?;
    }

    // 2. Wire each package's dependency symlinks (done after all dirs exist).
    //    `alias` is the import name; `real_id` is the actual resolved package.
    for pkg in resolution.packages.values() {
        let deps_base = virtual_store.join(sanitize(&pkg.id())).join("node_modules");
        for (alias, real_id) in &pkg.deps {
            let Some(real) = resolution.packages.get(real_id) else {
                continue;
            };
            let target = virtual_store
                .join(sanitize(real_id))
                .join("node_modules")
                .join(&real.name);
            symlink(&target, &deps_base.join(alias))?;
        }
    }

    // 3. Top-level symlinks for the direct dependencies.
    for (alias, real_id) in &resolution.roots {
        let Some(real) = resolution.packages.get(real_id) else {
            continue;
        };
        let target = virtual_store
            .join(sanitize(real_id))
            .join("node_modules")
            .join(&real.name);
        symlink(&target, &node_modules.join(alias))?;
    }

    // 4. Link executables (`bin` fields) into the relevant `.bin` directories.
    link_bins(&virtual_store, &node_modules, resolution)?;

    Ok(())
}

/// Create `.bin/<cmd>` symlinks so installed package executables are runnable.
///
/// - A package's *direct* dependencies get their bins in that package's
///   `node_modules/.bin` (inside the virtual store).
/// - The project's *direct* dependencies also get their bins in the top-level
///   `node_modules/.bin`.
fn link_bins(virtual_store: &Path, node_modules: &Path, resolution: &Resolution) -> Result<()> {
    // Per-package: each node's dependencies' bins go in its own `.bin`.
    for pkg in resolution.packages.values() {
        let bin_dir = virtual_store
            .join(sanitize(&pkg.id()))
            .join("node_modules")
            .join(".bin");
        for real_id in pkg.deps.values() {
            let Some(real) = resolution.packages.get(real_id) else {
                continue;
            };
            let dep_pkg_dir = virtual_store
                .join(sanitize(real_id))
                .join("node_modules")
                .join(&real.name);
            link_package_bins(&dep_pkg_dir, &real.name, &bin_dir)?;
        }
    }

    // Top level: the project's direct dependencies' bins.
    let top_bin = node_modules.join(".bin");
    for real_id in resolution.roots.values() {
        let Some(real) = resolution.packages.get(real_id) else {
            continue;
        };
        let pkg_dir = virtual_store
            .join(sanitize(real_id))
            .join("node_modules")
            .join(&real.name);
        link_package_bins(&pkg_dir, &real.name, &top_bin)?;
    }
    Ok(())
}

/// Link a single package's declared executables into `bin_dir`.
fn link_package_bins(pkg_dir: &Path, pkg_name: &str, bin_dir: &Path) -> Result<()> {
    for (cmd, rel) in read_bins(pkg_dir, pkg_name) {
        let target = pkg_dir.join(&rel);
        if !target.exists() {
            continue;
        }
        // Executables must be... executable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&target) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&target, perms);
            }
        }
        symlink(&target, &bin_dir.join(&cmd))?;
    }
    Ok(())
}

/// Parse a package's `bin` field. It is either a string (the command takes the
/// package's unscoped name) or a map of `command -> relative path`.
fn read_bins(pkg_dir: &Path, pkg_name: &str) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(pkg_dir.join("package.json")) else {
        return vec![];
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return vec![];
    };
    match json.get("bin") {
        Some(serde_json::Value::String(path)) => {
            let cmd = pkg_name.rsplit('/').next().unwrap_or(pkg_name);
            vec![(cmd.to_string(), path.clone())]
        }
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .filter_map(|(cmd, p)| p.as_str().map(|s| (cmd.clone(), s.to_string())))
            .collect(),
        _ => vec![],
    }
}

/// pnpm-style directory key: `@scope/name@1.0.0` → `@scope+name@1.0.0`.
fn sanitize(id: &str) -> String {
    id.replace('/', "+")
}

/// Create a symlink at `link` pointing to the absolute `target`, creating parent
/// directories (scoped names need an intermediate `@scope/` dir) and replacing
/// any stale link.
fn symlink(target: &Path, link: &PathBuf) -> Result<()> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(target, link)?;
    Ok(())
}
