//! Materialise resolved packages into the project's `node_modules`.
//!
//! ## MVP strategy (phase 1)
//!
//! A flat `node_modules/<name>` layout, hard-linked from the store. This is the
//! classic "hoisted" layout. The pnpm-style isolated layout (a virtual store at
//! `node_modules/.vault` with symlinks) is tracked for phase 2 in `ROADMAP.md`.

use crate::error::Result;
use crate::resolver::Resolution;
use crate::store::Store;
use std::path::Path;

/// Link every resolved package into `<project>/node_modules/<name>`.
pub fn link_all(store: &Store, resolution: &Resolution, project_dir: &Path) -> Result<()> {
    let node_modules = project_dir.join("node_modules");
    std::fs::create_dir_all(&node_modules)?;

    for pkg in resolution.packages.values() {
        // Scoped names create an intermediate `@scope` directory.
        let dest = node_modules.join(&pkg.name);
        // Clear any previous contents so re-installs are deterministic.
        if dest.exists() {
            std::fs::remove_dir_all(&dest)?;
        }
        std::fs::create_dir_all(&dest)?;

        let index = store.read_index(&pkg.name, &pkg.version)?;
        store.materialize(&index, &dest)?;
    }

    Ok(())
}
