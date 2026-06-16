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
    for pkg in resolution.packages.values() {
        let deps_base = virtual_store.join(sanitize(&pkg.id())).join("node_modules");
        for (dep_name, dep_version) in &pkg.deps {
            let dep_id = format!("{dep_name}@{dep_version}");
            let target = virtual_store
                .join(sanitize(&dep_id))
                .join("node_modules")
                .join(dep_name);
            symlink(&target, &deps_base.join(dep_name))?;
        }
    }

    // 3. Top-level symlinks for the direct dependencies.
    for (name, version) in &resolution.roots {
        let id = format!("{name}@{version}");
        let target = virtual_store
            .join(sanitize(&id))
            .join("node_modules")
            .join(name);
        symlink(&target, &node_modules.join(name))?;
    }

    Ok(())
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
