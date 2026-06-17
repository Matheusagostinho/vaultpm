//! Global content-addressable store (`~/.vault/store`).
//!
//! Every file of every package is stored exactly once, keyed by the SHA-256 of
//! its contents. A package's layout is recorded in an *index* file mapping each
//! relative path to the hash of its bytes. Materialising a package into a
//! project's `node_modules` then becomes a set of hard links from the store —
//! so ten projects depending on `lodash@4.17.21` share a single copy on disk.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Layout version of the on-disk store. Bumped on breaking changes.
const STORE_VERSION: &str = "v1";

/// A single file entry within a package index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the package root (the tarball's `package/` prefix is
    /// stripped).
    pub path: String,
    /// SHA-256 hex digest of the file contents (the CAS key).
    pub hash: String,
    /// Whether the file is executable.
    #[serde(default)]
    pub executable: bool,
}

/// The recorded layout of one extracted package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIndex {
    pub name: String,
    pub version: String,
    pub files: Vec<FileEntry>,
}

/// Handle to the on-disk store.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open (creating if needed) the store at `~/.vault/store`, or at an
    /// explicit override path.
    pub fn open(override_path: Option<&str>) -> Result<Self> {
        let root = match override_path {
            Some(p) => expand_tilde(p),
            None => default_store_root(),
        };
        std::fs::create_dir_all(root.join(STORE_VERSION).join("files"))?;
        std::fs::create_dir_all(root.join(STORE_VERSION).join("index"))?;
        Ok(Self { root })
    }

    /// The store's root directory (`~/.vault/store` by default).
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// A unique temp file path under the store (same filesystem as the CAS, so
    /// streamed downloads stay local). The caller is responsible for cleanup.
    pub fn new_temp_path(&self) -> Result<PathBuf> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = self.root.join(STORE_VERSION).join("tmp");
        std::fs::create_dir_all(&dir)?;
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        Ok(dir.join(format!("dl-{}-{n}.tgz", std::process::id())))
    }

    fn files_dir(&self) -> PathBuf {
        self.root.join(STORE_VERSION).join("files")
    }

    fn index_path(&self, name: &str, version: &str) -> PathBuf {
        // Scoped names contain `/`; flatten to keep a single directory level.
        let safe = format!("{name}@{version}").replace('/', "+");
        self.root
            .join(STORE_VERSION)
            .join("index")
            .join(format!("{safe}.json"))
    }

    /// Path to a JSON metadata file under `<store>/v1/<kind>/<key>.json`.
    /// Used by the audit cache and maintainer-tracking. The parent directory is
    /// created on demand by writers.
    pub fn meta_path(&self, kind: &str, key: &str) -> PathBuf {
        let safe = key.replace('/', "+");
        self.root
            .join(STORE_VERSION)
            .join(kind)
            .join(format!("{safe}.json"))
    }

    /// Read and deserialize a metadata file, if present and valid.
    pub fn read_meta<T: serde::de::DeserializeOwned>(&self, kind: &str, key: &str) -> Option<T> {
        let text = std::fs::read_to_string(self.meta_path(kind, key)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Serialize and write a metadata file, creating its directory.
    pub fn write_meta<T: serde::Serialize>(&self, kind: &str, key: &str, value: &T) -> Result<()> {
        let path = self.meta_path(kind, key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string(value)?)?;
        Ok(())
    }

    /// Path inside the CAS for a given content hash (sharded by first 2 chars).
    fn object_path(&self, hash: &str) -> PathBuf {
        let (shard, rest) = hash.split_at(2);
        self.files_dir().join(shard).join(rest)
    }

    /// Whether this package has already been extracted into the store.
    pub fn has_package(&self, name: &str, version: &str) -> bool {
        self.index_path(name, version).exists()
    }

    /// Read a previously written package index.
    pub fn read_index(&self, name: &str, version: &str) -> Result<PackageIndex> {
        let text = std::fs::read_to_string(self.index_path(name, version))?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Hash `bytes`, write them into the CAS if absent, and return the hex hash.
    pub fn put_object(&self, bytes: &[u8]) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = hex::encode(hasher.finalize());
        let dest = self.object_path(&hash);
        if !dest.exists() {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Write to a **uniquely-named** temp file then atomically rename it
            // into place. The unique name is essential: many packages contain
            // byte-identical files (same hash), and parallel extraction would
            // otherwise race on a shared `<hash>.tmp`. If another thread wins
            // the race the rename simply replaces an identical object.
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let tmp = dest.with_extension(format!(
                "tmp-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&tmp, bytes)?;
            if std::fs::rename(&tmp, &dest).is_err() {
                // Another writer placed the (identical) object first.
                let _ = std::fs::remove_file(&tmp);
            }
        }
        Ok(hash)
    }

    /// Write the package index after all objects are stored.
    pub fn write_index(&self, index: &PackageIndex) -> Result<()> {
        let path = self.index_path(&index.name, &index.version);
        let text = serde_json::to_string(index)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Garbage-collect CAS objects no longer referenced by any package index.
    /// Returns `(objects_removed, bytes_freed)`.
    pub fn prune(&self) -> Result<(usize, u64)> {
        // Collect every hash referenced by a stored package index.
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
        let index_dir = self.root.join(STORE_VERSION).join("index");
        if let Ok(entries) = std::fs::read_dir(&index_dir) {
            for entry in entries.flatten() {
                if let Ok(text) = std::fs::read_to_string(entry.path()) {
                    if let Ok(index) = serde_json::from_str::<PackageIndex>(&text) {
                        for f in index.files {
                            referenced.insert(f.hash);
                        }
                    }
                }
            }
        }

        // Walk the CAS and remove any object not in the referenced set. Objects
        // modified within a short grace window are skipped, so we don't delete a
        // file a concurrent install just wrote but hasn't linked yet.
        const GRACE: std::time::Duration = std::time::Duration::from_secs(60);
        let now = std::time::SystemTime::now();
        let mut removed = 0usize;
        let mut freed = 0u64;
        let files_dir = self.files_dir();
        if let Ok(shards) = std::fs::read_dir(&files_dir) {
            for shard in shards.flatten() {
                let shard_name = shard.file_name();
                let Some(shard_str) = shard_name.to_str() else {
                    continue;
                };
                if let Ok(objects) = std::fs::read_dir(shard.path()) {
                    for obj in objects.flatten() {
                        let hash = format!("{shard_str}{}", obj.file_name().to_string_lossy());
                        if referenced.contains(&hash) {
                            continue;
                        }
                        let meta = match obj.metadata() {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        // Skip recently-written objects (concurrency safety).
                        if let Ok(modified) = meta.modified() {
                            if now.duration_since(modified).unwrap_or(GRACE) < GRACE {
                                continue;
                            }
                        }
                        if std::fs::remove_file(obj.path()).is_ok() {
                            removed += 1;
                            freed += meta.len();
                        }
                    }
                }
            }
        }
        Ok((removed, freed))
    }

    /// Hard-link (falling back to copy) every file of a package into `dest_dir`.
    pub fn materialize(&self, index: &PackageIndex, dest_dir: &Path) -> Result<()> {
        for entry in &index.files {
            let dest = dest_dir.join(&entry.path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let src = self.object_path(&entry.hash);
            // Replace any stale destination.
            let _ = std::fs::remove_file(&dest);
            if std::fs::hard_link(&src, &dest).is_err() {
                // Cross-device or unsupported FS → copy instead.
                std::fs::copy(&src, &dest)?;
            }
            #[cfg(unix)]
            if entry.executable {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dest)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dest, perms)?;
            }
        }
        Ok(())
    }
}

fn default_store_root() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".vault")
        .join("store")
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_object_is_content_addressed() {
        let dir = std::env::temp_dir().join(format!("vault-store-test-{}", std::process::id()));
        let store = Store::open(Some(dir.to_str().unwrap())).unwrap();
        let h1 = store.put_object(b"hello world").unwrap();
        let h2 = store.put_object(b"hello world").unwrap();
        assert_eq!(h1, h2, "same content → same hash");
        assert!(store.object_path(&h1).exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
