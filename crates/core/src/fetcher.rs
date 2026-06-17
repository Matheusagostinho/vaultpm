//! Download, verify and extract tarballs into the content-addressable store.
//!
//! The tarball is **streamed to a temp file while its SHA-512/SHA-1 are computed
//! incrementally** — so we never hold the whole `.tgz` in memory (important at
//! high concurrency). Integrity is then verified **before** extraction, exactly
//! as a security-first package manager must: nothing is extracted until the
//! bytes are proven authentic.

use crate::audit::integrity;
use crate::error::{Result, VaultError};
use crate::registry::Registry;
use crate::resolver::ResolvedPackage;
use crate::store::{FileEntry, PackageIndex, Store};
use flate2::read::GzDecoder;
use futures::StreamExt;
use sha1::Sha1;
use sha2::{Digest, Sha512};
use std::io::Read;
use tar::Archive;
use tokio::io::AsyncWriteExt;

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

    // 1. Stream the tarball to a temp file, hashing as bytes arrive.
    let tmp = store.new_temp_path()?;
    let (sha512, sha1) = match stream_to_file(registry, &pkg.meta.dist.tarball, &tmp).await {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };

    // 2. Verify integrity BEFORE extracting (fail-closed). On mismatch the
    //    bytes are discarded and nothing enters the trusted store layout.
    if let Err(e) = integrity::verify_precomputed(
        &pkg.name,
        &pkg.version,
        &sha512,
        &sha1,
        pkg.meta.dist.integrity.as_deref(),
        pkg.meta.dist.shasum.as_deref(),
    ) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // 3. Extract from the verified temp file on the blocking pool.
    let store_for_extract = store.clone();
    let pkg_clone = pkg.clone();
    let tmp_for_extract = tmp.clone();
    let join = tokio::task::spawn_blocking(move || -> Result<PackageIndex> {
        let file = std::fs::File::open(&tmp_for_extract)?;
        extract_to_store(&store_for_extract, &pkg_clone, file)
    })
    .await;

    // Always remove the temp tarball, regardless of how extraction ended.
    let _ = std::fs::remove_file(&tmp);

    let index = join.map_err(|e| VaultError::Resolution {
        name: pkg.id(),
        reason: format!("extraction task failed: {e}"),
    })??;
    store.write_index(&index)?;
    Ok(true)
}

/// Stream an HTTP body to `dest`, returning the `(sha512, sha1)` digests of the
/// raw bytes. Never buffers the whole response in memory.
async fn stream_to_file(
    registry: &Registry,
    url: &str,
    dest: &std::path::Path,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let resp = registry.tarball_response(url).await?;
    let mut file = tokio::fs::File::create(dest).await?;
    let mut sha512 = Sha512::new();
    let mut sha1 = Sha1::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        sha512.update(&chunk);
        sha1.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    Ok((sha512.finalize().to_vec(), sha1.finalize().to_vec()))
}

/// Decompress a gzipped tarball and write each file into the CAS, returning the
/// package index. npm tarballs wrap everything under a top-level `package/`
/// directory which we strip.
fn extract_to_store<R: Read>(
    store: &Store,
    pkg: &ResolvedPackage,
    reader: R,
) -> Result<PackageIndex> {
    let gz = GzDecoder::new(reader);
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
