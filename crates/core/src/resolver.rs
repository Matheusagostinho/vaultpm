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
use std::collections::BTreeMap;

/// A fully resolved package pinned to one concrete version, with its own
/// dependencies resolved to concrete versions.
#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub meta: VersionMeta,
    /// `aliasName -> resolved package id` (`name@version`). The alias is the
    /// name this package imports the dependency under, which can differ from
    /// the real package name for npm aliases (`"x": "npm:y@^1"`).
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
    /// Top-level (direct) dependencies: `aliasName -> resolved package id`.
    pub roots: BTreeMap<String, String>,
    pub warnings: Vec<ResolutionWarning>,
}

/// Max concurrent registry requests during resolution (network-bound).
const RESOLVE_CONCURRENCY: usize = 24;

/// One dependency requirement to resolve: which package wants it, under what
/// import alias, the real package + range, and whether it is optional.
struct DepReq {
    parent: String,
    alias: String,
    real_name: String,
    real_range: String,
    optional: bool,
}

/// Resolve top-level requirements into a per-version dependency graph.
///
/// Resolution is **concurrent and level-ordered**: every requirement in the
/// current BFS frontier is resolved in parallel (bounded by
/// [`RESOLVE_CONCURRENCY`]), then applied, then the next frontier is expanded.
/// Packument fetches for the same package coalesce via the registry's
/// singleflight cache, so the network is hit at most once per package.
pub async fn resolve(registry: &Registry, roots: &BTreeMap<String, String>) -> Result<Resolution> {
    use futures::stream::{self, StreamExt};
    let mut res = Resolution::default();

    // Resolve the direct dependencies concurrently.
    let root_reqs: Vec<(String, String, String)> = roots
        .iter()
        .map(|(alias, spec)| {
            let (rn, rr) = parse_dep_spec(alias, spec);
            (alias.clone(), rn, rr)
        })
        .collect();
    let root_results: Vec<(String, String, Result<String>)> = stream::iter(root_reqs)
        .map(|(alias, real_name, real_range)| {
            let reg = registry.clone();
            async move {
                let v = resolve_range(&reg, &real_name, &real_range).await;
                (alias, real_name, v)
            }
        })
        .buffer_unordered(RESOLVE_CONCURRENCY)
        .collect()
        .await;

    let mut frontier: Vec<String> = Vec::new();
    for (alias, real_name, version) in root_results {
        let version = version?;
        let id = format!("{real_name}@{version}");
        res.roots.insert(alias, id.clone());
        if !res.packages.contains_key(&id) {
            insert_node(registry, &mut res, &real_name, &version).await?;
            frontier.push(id);
        }
    }

    // Expand the graph one level at a time, resolving each level in parallel.
    while !frontier.is_empty() {
        let mut reqs: Vec<DepReq> = Vec::new();
        for id in &frontier {
            let pkg = &res.packages[id];
            for (alias, spec) in &pkg.meta.dependencies {
                let (real_name, real_range) = parse_dep_spec(alias, spec);
                reqs.push(DepReq {
                    parent: id.clone(),
                    alias: alias.clone(),
                    real_name,
                    real_range,
                    optional: false,
                });
            }
            for (alias, spec) in &pkg.meta.optional_dependencies {
                let (real_name, real_range) = parse_dep_spec(alias, spec);
                reqs.push(DepReq {
                    parent: id.clone(),
                    alias: alias.clone(),
                    real_name,
                    real_range,
                    optional: true,
                });
            }
        }

        // Resolve every requirement of this level concurrently.
        let resolved: Vec<(DepReq, Result<String>)> = stream::iter(reqs)
            .map(|req| {
                let reg = registry.clone();
                async move {
                    let v = resolve_range(&reg, &req.real_name, &req.real_range).await;
                    (req, v)
                }
            })
            .buffer_unordered(RESOLVE_CONCURRENCY)
            .collect()
            .await;

        // Apply results sequentially (packuments are already cached, so
        // `insert_node` does no network I/O here).
        let mut next: Vec<String> = Vec::new();
        for (req, version) in resolved {
            match version {
                Ok(version) => {
                    let dep_id = format!("{}@{version}", req.real_name);
                    if !res.packages.contains_key(&dep_id) {
                        match insert_node(registry, &mut res, &req.real_name, &version).await {
                            Ok(()) => next.push(dep_id.clone()),
                            Err(e) if req.optional => {
                                res.warnings.push(ResolutionWarning {
                                    name: req.alias.clone(),
                                    message: format!("optional dependency skipped ({e})"),
                                });
                                continue;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    res.packages
                        .get_mut(&req.parent)
                        .unwrap()
                        .deps
                        .insert(req.alias, dep_id);
                }
                Err(_) if req.optional => res.warnings.push(ResolutionWarning {
                    name: req.alias,
                    message: "optional dependency skipped (could not resolve)".into(),
                }),
                Err(e) => return Err(e),
            }
        }
        next.sort();
        next.dedup();
        frontier = next;
    }

    Ok(res)
}

/// Resolve a dependency spec into `(real_package_name, version_range)`,
/// unwrapping npm aliases of the form `npm:<name>@<range>` (e.g.
/// `"string-width-cjs": "npm:string-width@^4.2.0"`).
fn parse_dep_spec(alias: &str, spec: &str) -> (String, String) {
    if let Some(rest) = spec.strip_prefix("npm:") {
        // `rest` is `name@range`; the name may be scoped (`@scope/name`).
        if let Some(stripped) = rest.strip_prefix('@') {
            if let Some(at) = stripped.find('@') {
                let (name, range) = stripped.split_at(at);
                return (format!("@{name}"), range[1..].to_string());
            }
            return (rest.to_string(), "*".to_string());
        }
        if let Some((name, range)) = rest.split_once('@') {
            return (name.to_string(), range.to_string());
        }
        return (rest.to_string(), "*".to_string());
    }
    (alias.to_string(), spec.to_string())
}

/// Resolve `(name, range)` to a concrete version. The packument fetch is
/// deduplicated by the registry's singleflight cache.
async fn resolve_range(registry: &Registry, name: &str, range: &str) -> Result<String> {
    let packument = registry.packument(name).await?;
    pick_version(name, range, &packument)
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

/// Warn about unmet peer dependencies. A peer is "met" when *some* resolved
/// package of that name satisfies the declared range. Warning-only (npm
/// semantics): peers don't block, they advise. Exotic ranges are skipped.
pub fn check_peers(resolution: &Resolution) -> Vec<String> {
    use node_semver::{Range, Version};
    let mut present: BTreeMap<&str, Vec<Version>> = BTreeMap::new();
    for pkg in resolution.packages.values() {
        if let Ok(v) = Version::parse(&pkg.version) {
            present.entry(pkg.name.as_str()).or_default().push(v);
        }
    }

    let mut warnings = Vec::new();
    for pkg in resolution.packages.values() {
        for (peer, range) in &pkg.meta.peer_dependencies {
            let Ok(req) = Range::parse(range) else {
                continue;
            };
            match present.get(peer.as_str()) {
                Some(versions) if versions.iter().any(|v| req.satisfies(v)) => {}
                Some(_) => warnings.push(format!(
                    "unmet peer dependency: {}@{} wants {peer}@{range}, but a different version is installed",
                    pkg.name, pkg.version
                )),
                None => warnings.push(format!(
                    "unmet peer dependency: {}@{} wants {peer}@{range} (not installed)",
                    pkg.name, pkg.version
                )),
            }
        }
    }
    warnings.sort();
    warnings.dedup();
    warnings
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
    fn parses_npm_aliases() {
        assert_eq!(
            parse_dep_spec("wrap-ansi-cjs", "npm:wrap-ansi@^7.0.0"),
            ("wrap-ansi".to_string(), "^7.0.0".to_string())
        );
        assert_eq!(
            parse_dep_spec("x", "npm:@scope/pkg@^1.2.3"),
            ("@scope/pkg".to_string(), "^1.2.3".to_string())
        );
        // Non-alias specs pass through unchanged.
        assert_eq!(
            parse_dep_spec("lodash", "^4.17.21"),
            ("lodash".to_string(), "^4.17.21".to_string())
        );
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
                    peer_dependencies: Default::default(),
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
