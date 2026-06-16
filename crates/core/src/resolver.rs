//! Dependency resolution.
//!
//! ## MVP strategy (phase 1)
//!
//! This is a pragmatic, *flat-first* resolver: each package name is resolved to
//! a single concrete version that satisfies the highest-priority requirement
//! seen so far. When a later requirement cannot be satisfied by the already
//! chosen version we pick the higher version and emit a warning.
//!
//! This deliberately does **not** yet handle conflicting transitive version
//! ranges with a nested `node_modules` layout. The full PubGrub-based solver
//! and pnpm-style isolated layout are tracked for phase 2 in `ROADMAP.md`.

use crate::error::{Result, VaultError};
use crate::registry::{Registry, VersionMeta};
use node_semver::{Range, Version};
use std::collections::{BTreeMap, VecDeque};

/// A fully resolved package pinned to one concrete version.
#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub meta: VersionMeta,
}

impl ResolvedPackage {
    /// `name@version` identifier used as a store + lockfile key.
    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// Warnings surfaced during resolution (e.g. version conflicts that were
/// resolved by upgrading).
#[derive(Debug, Clone)]
pub struct ResolutionWarning {
    pub name: String,
    pub message: String,
}

/// The outcome of resolving a dependency graph.
#[derive(Debug, Default)]
pub struct Resolution {
    /// Resolved packages keyed by name (flat layout).
    pub packages: BTreeMap<String, ResolvedPackage>,
    pub warnings: Vec<ResolutionWarning>,
}

/// Resolve a set of top-level requirements into a flat package set.
pub async fn resolve(registry: &Registry, roots: &BTreeMap<String, String>) -> Result<Resolution> {
    let mut resolution = Resolution::default();
    // Queue of (name, range) pairs still to process.
    let mut queue: VecDeque<(String, String)> =
        roots.iter().map(|(n, r)| (n.clone(), r.clone())).collect();

    while let Some((name, range_str)) = queue.pop_front() {
        // If we already have a version and it satisfies this range, reuse it.
        if let Some(existing) = resolution.packages.get(&name) {
            if range_satisfied(&range_str, &existing.version) {
                continue;
            }
        }

        let packument = registry.packument(&name).await?;
        let chosen = pick_version(&name, &range_str, &packument)?;
        let meta = packument
            .versions
            .get(&chosen)
            .ok_or_else(|| VaultError::Resolution {
                name: name.clone(),
                reason: format!("version {chosen} missing from packument"),
            })?
            .clone();

        // Conflict bookkeeping: warn if we are replacing a different version.
        if let Some(existing) = resolution.packages.get(&name) {
            if existing.version != chosen {
                let winner = higher_version(&existing.version, &chosen);
                resolution.warnings.push(ResolutionWarning {
                    name: name.clone(),
                    message: format!(
                        "version conflict ({} vs {}); keeping {winner} (flat resolver, phase 1)",
                        existing.version, chosen
                    ),
                });
                if winner == existing.version {
                    continue;
                }
            }
        }

        // Enqueue this version's runtime dependencies.
        for (dep_name, dep_range) in &meta.dependencies {
            queue.push_back((dep_name.clone(), dep_range.clone()));
        }

        resolution.packages.insert(
            name.clone(),
            ResolvedPackage {
                name: name.clone(),
                version: chosen,
                meta,
            },
        );
    }

    Ok(resolution)
}

/// Choose the highest version satisfying `range_str`. Dist-tags such as
/// `latest` are honoured, as is an exact-version request.
fn pick_version(
    name: &str,
    range_str: &str,
    packument: &crate::registry::Packument,
) -> Result<String> {
    // dist-tag (e.g. "latest", "next").
    if let Some(tagged) = packument.dist_tags.get(range_str) {
        return Ok(tagged.clone());
    }

    // `*` / empty / "latest" → newest stable.
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
        // Skip pre-releases unless explicitly requested by an exact range.
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

fn range_satisfied(range_str: &str, version: &str) -> bool {
    match (Range::parse(range_str), Version::parse(version)) {
        (Ok(r), Ok(v)) => r.satisfies(&v),
        _ => false,
    }
}

fn higher_version(a: &str, b: &str) -> String {
    match (Version::parse(a), Version::parse(b)) {
        (Ok(va), Ok(vb)) => {
            if va >= vb {
                a.to_string()
            } else {
                b.to_string()
            }
        }
        _ => a.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_version_picks_newer() {
        assert_eq!(higher_version("1.2.3", "1.4.0"), "1.4.0");
        assert_eq!(higher_version("2.0.0", "1.9.9"), "2.0.0");
    }

    #[test]
    fn caret_range_is_satisfied() {
        assert!(range_satisfied("^1.2.0", "1.5.1"));
        assert!(!range_satisfied("^1.2.0", "2.0.0"));
    }
}
