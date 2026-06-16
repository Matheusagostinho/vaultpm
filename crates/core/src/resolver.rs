//! Dependency resolution.
//!
//! ## Model (phase 4)
//!
//! npm lets **multiple versions of the same package coexist**, so Vault builds a
//! *per-version dependency graph* rather than forcing one version per name (the
//! Cargo/PubGrub model). Each `(name, range)` requirement is resolved to the
//! highest published version satisfying it; identical requirements are deduped
//! via a range cache. The resulting graph is materialised by the linker into a
//! pnpm-style isolated `node_modules/.vault` layout, so every package sees
//! exactly the dependencies it declared — no accidental hoisting.
//!
//! Full PubGrub-style backtracking (to minimise duplicate versions when ranges
//! *could* overlap) remains a future optimisation; it matters far less for npm
//! than for single-version ecosystems.

use crate::error::{Result, VaultError};
use crate::registry::{Packument, Registry, VersionMeta};
use node_semver::{Range, Version};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// A fully resolved package pinned to one concrete version, with its own
/// dependencies resolved to concrete versions.
#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub meta: VersionMeta,
    /// `depName -> resolved version` for this package's runtime dependencies.
    pub deps: BTreeMap<String, String>,
}

impl ResolvedPackage {
    /// `name@version` identifier — the store, lockfile and virtual-store key.
    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// A non-fatal note surfaced during resolution.
#[derive(Debug, Clone)]
pub struct ResolutionWarning {
    pub name: String,
    pub message: String,
}

/// The resolved dependency graph.
#[derive(Debug, Default)]
pub struct Resolution {
    /// Every resolved package keyed by `name@version`.
    pub packages: BTreeMap<String, ResolvedPackage>,
    /// Top-level (direct) dependencies: `name -> resolved version`.
    pub roots: BTreeMap<String, String>,
    pub warnings: Vec<ResolutionWarning>,
}

/// Resolve top-level requirements into a per-version dependency graph.
pub async fn resolve(registry: &Registry, roots: &BTreeMap<String, String>) -> Result<Resolution> {
    let mut res = Resolution::default();
    let mut range_cache: HashMap<(String, String), String> = HashMap::new();
    let mut work: VecDeque<String> = VecDeque::new();

    // Resolve direct dependencies first.
    for (name, range) in roots {
        let version = resolve_range(registry, &mut range_cache, name, range).await?;
        res.roots.insert(name.clone(), version.clone());
        let id = format!("{name}@{version}");
        if !res.packages.contains_key(&id) {
            insert_node(registry, &mut res, name, &version).await?;
            work.push_back(id);
        }
    }

    // Resolve the transitive graph.
    while let Some(id) = work.pop_front() {
        let deps: Vec<(String, String)> = res.packages[&id]
            .meta
            .dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let mut resolved_deps = BTreeMap::new();
        for (dep_name, dep_range) in deps {
            let dep_version =
                resolve_range(registry, &mut range_cache, &dep_name, &dep_range).await?;
            let dep_id = format!("{dep_name}@{dep_version}");
            resolved_deps.insert(dep_name.clone(), dep_version.clone());
            if !res.packages.contains_key(&dep_id) {
                insert_node(registry, &mut res, &dep_name, &dep_version).await?;
                work.push_back(dep_id);
            }
        }

        // Optional dependencies: best-effort. A resolution/fetch failure must
        // not break the install (npm semantics).
        let opt_deps: Vec<(String, String)> = res.packages[&id]
            .meta
            .optional_dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (dep_name, dep_range) in opt_deps {
            match resolve_range(registry, &mut range_cache, &dep_name, &dep_range).await {
                Ok(dep_version) => {
                    let dep_id = format!("{dep_name}@{dep_version}");
                    resolved_deps.insert(dep_name.clone(), dep_version.clone());
                    if !res.packages.contains_key(&dep_id)
                        && insert_node(registry, &mut res, &dep_name, &dep_version)
                            .await
                            .is_ok()
                    {
                        work.push_back(dep_id);
                    }
                }
                Err(_) => res.warnings.push(ResolutionWarning {
                    name: dep_name.clone(),
                    message: "optional dependency skipped (could not resolve)".into(),
                }),
            }
        }

        res.packages.get_mut(&id).unwrap().deps = resolved_deps;
    }

    Ok(res)
}

/// Resolve `(name, range)` to a concrete version, caching identical requests.
async fn resolve_range(
    registry: &Registry,
    cache: &mut HashMap<(String, String), String>,
    name: &str,
    range: &str,
) -> Result<String> {
    let key = (name.to_string(), range.to_string());
    if let Some(v) = cache.get(&key) {
        return Ok(v.clone());
    }
    let packument = registry.packument(name).await?;
    let version = pick_version(name, range, &packument)?;
    cache.insert(key, version.clone());
    Ok(version)
}

/// Fetch a version's metadata and insert it as a graph node (deps filled later).
async fn insert_node(
    registry: &Registry,
    res: &mut Resolution,
    name: &str,
    version: &str,
) -> Result<()> {
    let packument = registry.packument(name).await?;
    let meta = packument
        .versions
        .get(version)
        .ok_or_else(|| VaultError::Resolution {
            name: name.to_string(),
            reason: format!("version {version} missing from packument"),
        })?
        .clone();
    res.packages.insert(
        format!("{name}@{version}"),
        ResolvedPackage {
            name: name.to_string(),
            version: version.to_string(),
            meta,
            deps: BTreeMap::new(),
        },
    );
    Ok(())
}

/// Choose the highest version satisfying `range_str`. Dist-tags such as
/// `latest` are honoured, as is an exact-version request.
fn pick_version(name: &str, range_str: &str, packument: &Packument) -> Result<String> {
    if let Some(tagged) = packument.dist_tags.get(range_str) {
        return Ok(tagged.clone());
    }

    let want_any = range_str.is_empty() || range_str == "*" || range_str == "latest";
    if want_any {
        if let Some(latest) = packument.dist_tags.get("latest") {
            return Ok(latest.clone());
        }
    }

    let range = Range::parse(range_str).map_err(|e| VaultError::Resolution {
        name: name.to_string(),
        reason: format!("invalid version range `{range_str}`: {e}"),
    })?;

    let mut best: Option<Version> = None;
    for v in packument.versions.keys() {
        let Ok(parsed) = Version::parse(v) else {
            continue;
        };
        if !parsed.pre_release.is_empty() && !range_str.contains('-') {
            continue;
        }
        if range.satisfies(&parsed) {
            best = Some(match best {
                Some(cur) if cur >= parsed => cur,
                _ => parsed,
            });
        }
    }

    best.map(|v| v.to_string())
        .ok_or_else(|| VaultError::Resolution {
            name: name.to_string(),
            reason: format!("no published version satisfies `{range_str}`"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range_satisfied(range_str: &str, version: &str) -> bool {
        match (Range::parse(range_str), Version::parse(version)) {
            (Ok(r), Ok(v)) => r.satisfies(&v),
            _ => false,
        }
    }

    #[test]
    fn caret_range_is_satisfied() {
        assert!(range_satisfied("^1.2.0", "1.5.1"));
        assert!(!range_satisfied("^1.2.0", "2.0.0"));
    }

    #[test]
    fn picks_highest_satisfying_version() {
        use crate::registry::{Dist, VersionMeta};
        let mut versions = std::collections::HashMap::new();
        for v in ["1.0.0", "1.2.0", "1.9.3", "2.0.0"] {
            versions.insert(
                v.to_string(),
                VersionMeta {
                    name: "demo".into(),
                    version: v.into(),
                    dependencies: Default::default(),
                    optional_dependencies: Default::default(),
                    scripts: Default::default(),
                    dist: Dist {
                        tarball: String::new(),
                        shasum: None,
                        integrity: None,
                    },
                },
            );
        }
        let packument = Packument {
            name: "demo".into(),
            dist_tags: Default::default(),
            versions,
            time: Default::default(),
            maintainers: vec![],
        };
        assert_eq!(pick_version("demo", "^1.0.0", &packument).unwrap(), "1.9.3");
        assert_eq!(pick_version("demo", "1.2.0", &packument).unwrap(), "1.2.0");
    }
}
