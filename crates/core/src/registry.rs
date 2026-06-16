//! Minimal npm registry client.
//!
//! We fetch the full "packument" (the document at `https://registry.npmjs.org/<name>`)
//! and pick the best matching version locally. The packument is cached per
//! process so resolving a large graph only hits the network once per package.

use crate::error::{Result, VaultError};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";

/// The subset of a packument we care about.
#[derive(Debug, Clone, Deserialize)]
pub struct Packument {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: HashMap<String, String>,
    #[serde(default)]
    pub versions: HashMap<String, VersionMeta>,
    /// `time[version] = ISO timestamp`; also has `created` / `modified`.
    #[serde(default)]
    pub time: HashMap<String, String>,
}

/// Per-version metadata from the packument.
#[derive(Debug, Clone, Deserialize)]
pub struct VersionMeta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub dependencies: HashMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: HashMap<String, String>,
    #[serde(default)]
    pub scripts: HashMap<String, String>,
    pub dist: Dist,
}

/// The `dist` block carrying the tarball URL and integrity hashes.
#[derive(Debug, Clone, Deserialize)]
pub struct Dist {
    pub tarball: String,
    #[serde(default)]
    pub shasum: Option<String>,
    #[serde(default)]
    pub integrity: Option<String>,
}

/// A registry client with an in-memory packument cache.
#[derive(Clone)]
pub struct Registry {
    client: reqwest::Client,
    base_url: String,
    cache: Arc<Mutex<HashMap<String, Arc<Packument>>>>,
}

impl Registry {
    /// Build a registry client pointed at the default npm registry.
    pub fn new() -> Self {
        Self::with_url(DEFAULT_REGISTRY)
    }

    /// Build a registry client for a custom base URL (useful for tests/mirrors).
    pub fn with_url(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("vault/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build reqwest client");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Fetch (and cache) the packument for a package name.
    pub async fn packument(&self, name: &str) -> Result<Arc<Packument>> {
        if let Some(hit) = self.cache.lock().await.get(name).cloned() {
            return Ok(hit);
        }
        // Scoped packages (`@scope/name`) must keep the `/` un-encoded.
        let url = format!("{}/{}", self.base_url, name);
        tracing::debug!("GET {url}");
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(VaultError::Resolution {
                name: name.to_string(),
                reason: format!("registry returned HTTP {}", resp.status()),
            });
        }
        let packument: Packument = resp.json().await?;
        let packument = Arc::new(packument);
        self.cache
            .lock()
            .await
            .insert(name.to_string(), packument.clone());
        Ok(packument)
    }

    /// Download a tarball and return its raw bytes.
    pub async fn download_tarball(&self, url: &str) -> Result<bytes::Bytes> {
        tracing::debug!("GET tarball {url}");
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(VaultError::Resolution {
                name: url.to_string(),
                reason: format!("tarball download returned HTTP {}", resp.status()),
            });
        }
        Ok(resp.bytes().await?)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
