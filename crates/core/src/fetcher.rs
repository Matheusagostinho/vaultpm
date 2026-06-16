//! Download, verify and extract tarballs into the content-addressable store.

use crate::audit::integrity;
use crate::error::{Result, VaultError};
use crate::registry::Registry;
use crate::resolver::ResolvedPackage;
use crate::store::{FileEntry, PackageIndex, Store};
use flate2::read::GzDecoder;
use std::io::Read;
use tar::Archive;

/// Ensure a resolved package is present in the store, downloading and verifying
/// it if necessary. Returns `true` if a network download happened.
pub async fn ensure_in_store(
    registry: &Registry,
    store: &Store,
    pkg: &ResolvedPackage,
) -> Result<bool> {
    if store.has_package(&pkg.name, &pkg.version) {
        return Ok(false);
    }

    let bytes = registry.download_tarball(&pkg.meta.dist.tarball).await?;

    // Integrity verification + gunzip/untar are CPU-bound; run them on the
    // blocking pool so they don't stall the async runtime and many packages
    // extract truly in parallel. Integrity stays fail-closed.
    let store_for_extract = store.clone();
    let pkg = pkg.clone();
    let index = tokio::task::spawn_blocking(move || -> Result<PackageIndex> {
        integrity::verify(
            &pkg.name,
            &pkg.version,
            &bytes,
            pkg.meta.dist.integrity.as_deref(),
            pkg.meta.dist.shasum.as_deref(),
        )?;
        extract_to_store(&store_for_extract, &pkg, &bytes)
    })
    .await
    .map_err(|e| VaultError::Resolution {
        name: "extract".into(),
        reason: format!("extraction task failed: {e}"),
    })??;

    store.write_index(&index)?;
    Ok(true)
}

/// Decompress a gzipped tarball and write each file into the CAS, returning the
/// package index. npm tarballs wrap everything under a top-level `package/`
/// directory which we strip.
fn extract_to_store(store: &Store, pkg: &ResolvedPackage, bytes: &[u8]) -> Result<PackageIndex> {
    let gz = GzDecoder::new(bytes);
    let mut archive = Archive::new(gz);
    let mut files = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let header = entry.header();
        if !header.entry_type().is_file() {
            continue;
        }

        let path = entry.path()?.to_path_buf();
        let rel = strip_package_prefix(&path);
        if rel.is_empty() {
            continue;
        }

        let mode = header.mode().unwrap_or(0o644);
        let executable = mode & 0o111 != 0;

        let mut buf = Vec::with_capacity(header.size().unwrap_or(0) as usize);
        entry.read_to_end(&mut buf)?;

        let hash = store.put_object(&buf)?;
        files.push(FileEntry {
            path: rel,
            hash,
            executable,
        });
    }

    if files.is_empty() {
        return Err(VaultError::Resolution {
            name: pkg.id(),
            reason: "tarball contained no files".into(),
        });
    }

    Ok(PackageIndex {
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        files,
    })
}

/// Strip the leading `package/` segment that npm tarballs use. Some packages
/// use a different top-level dir, so we strip whatever the first component is.
fn strip_package_prefix(path: &std::path::Path) -> String {
    let mut comps = path.components();
    comps.next(); // drop the first segment ("package" by convention)
    comps
        .as_path()
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn strips_leading_package_dir() {
        assert_eq!(
            strip_package_prefix(Path::new("package/lib/index.js")),
            "lib/index.js"
        );
        assert_eq!(
            strip_package_prefix(Path::new("package/package.json")),
            "package.json"
        );
    }
}
