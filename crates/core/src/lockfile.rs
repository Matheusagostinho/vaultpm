//! `vault.lock` — a JSON lockfile recording resolved versions and the security
//! verdict for each package, so re-installs are reproducible and auditable.
//!
//! The lockfile stores enough to **reconstruct the full dependency graph without
//! touching the network** (versions, tarball URLs, integrity, the resolved
//! graph edges, and the lifecycle scripts needed for the static scan). That is
//! what powers lockfile-driven installs and `--frozen-lockfile`.

use crate::audit::AuditReport;
use crate::error::Result;
use crate::registry::{Dist, VersionMeta};
use crate::resolver::{Resolution, ResolvedPackage};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

const LOCKFILE_NAME: &str = "vault.lock";
const LOCKFILE_VERSION: u32 = 1;
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall"];

#[derive(Debug, Serialize, Deserialize)]
pub struct Lockfile {
    #[serde(rename = "lockfileVersion")]
    pub lockfile_version: u32,
    /// Direct dependencies: `aliasName -> resolved package id` (`name@version`).
    #[serde(default)]
    pub roots: BTreeMap<String, String>,
    pub packages: BTreeMap<String, LockedPackage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedPackage {
    pub resolved: String,
    pub integrity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shasum: Option<String>,
    /// Resolved dependency graph edges: `aliasName -> resolved package id`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    /// Lifecycle scripts (preinstall/install/postinstall) — kept so the static
    /// scan can run from the lockfile without re-fetching metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scripts: BTreeMap<String, String>,
    #[serde(rename = "auditedAt")]
    pub audited_at: String,
    #[serde(rename = "auditSources")]
    pub audit_sources: Vec<String>,
    #[serde(rename = "cveStatus")]
    pub cve_status: String,
    pub sandboxed: bool,
}

impl Lockfile {
    /// Build a lockfile from a resolution and the per-package audit reports.
    pub fn from_resolution(
        resolution: &Resolution,
        reports: &BTreeMap<String, AuditReport>,
        audit_sources: &[String],
    ) -> Self {
        let now = now_iso8601();
        let mut packages = BTreeMap::new();
        for pkg in resolution.packages.values() {
            let report = reports.get(&pkg.id());
            let cve_status = match report {
                Some(r) if r.has_critical_cve() => "critical",
                Some(r) if !r.advisories.is_empty() => "advisories",
                Some(_) => "clean",
                None => "unknown",
            };
            let scripts = pkg
                .meta
                .scripts
                .iter()
                .filter(|(k, _)| LIFECYCLE_SCRIPTS.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            packages.insert(
                pkg.id(),
                LockedPackage {
                    resolved: pkg.meta.dist.tarball.clone(),
                    integrity: pkg.meta.dist.integrity.clone().unwrap_or_default(),
                    shasum: pkg.meta.dist.shasum.clone(),
                    dependencies: pkg.deps.clone(),
                    scripts,
                    audited_at: now.clone(),
                    audit_sources: audit_sources.to_vec(),
                    cve_status: cve_status.to_string(),
                    sandboxed: false,
                },
            );
        }
        Self {
            lockfile_version: LOCKFILE_VERSION,
            roots: resolution.roots.clone(),
            packages,
        }
    }

    /// Load `vault.lock` from the project directory, if present and parseable.
    pub fn load(project_dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(project_dir.join(LOCKFILE_NAME)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Whether this lockfile still satisfies the project's declared direct
    /// dependencies. Conservative: any range it can't parse (npm aliases,
    /// dist-tags, URLs) makes it return `false`, forcing a fresh resolution.
    pub fn matches_manifest(&self, manifest: &BTreeMap<String, String>) -> bool {
        use node_semver::{Range, Version};
        if self.roots.len() != manifest.len() {
            return false;
        }
        for (alias, range) in manifest {
            let Some(id) = self.roots.get(alias) else {
                return false;
            };
            let Some((_, version)) = id.rsplit_once('@') else {
                return false;
            };
            let (Ok(r), Ok(v)) = (Range::parse(range), Version::parse(version)) else {
                return false;
            };
            if !r.satisfies(&v) {
                return false;
            }
        }
        // Every referenced package and graph edge must be present.
        for id in self.roots.values() {
            if !self.packages.contains_key(id) {
                return false;
            }
        }
        for pkg in self.packages.values() {
            for dep_id in pkg.dependencies.values() {
                if !self.packages.contains_key(dep_id) {
                    return false;
                }
            }
        }
        true
    }

    /// Reconstruct the dependency graph from the lockfile — no network needed.
    pub fn to_resolution(&self) -> Resolution {
        let mut packages = BTreeMap::new();
        for (id, locked) in &self.packages {
            let Some((name, version)) = id.rsplit_once('@') else {
                continue;
            };
            let meta = VersionMeta {
                name: name.to_string(),
                version: version.to_string(),
                dependencies: HashMap::new(),
                optional_dependencies: HashMap::new(),
                scripts: locked.scripts.clone().into_iter().collect(),
                dist: Dist {
                    tarball: locked.resolved.clone(),
                    shasum: locked.shasum.clone(),
                    integrity: if locked.integrity.is_empty() {
                        None
                    } else {
                        Some(locked.integrity.clone())
                    },
                },
            };
            packages.insert(
                id.clone(),
                ResolvedPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    meta,
                    deps: locked.dependencies.clone(),
                },
            );
        }
        Resolution {
            packages,
            roots: self.roots.clone(),
            warnings: Vec::new(),
        }
    }

    /// Write `vault.lock` to the project directory.
    pub fn save(&self, project_dir: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(project_dir.join(LOCKFILE_NAME), format!("{text}\n"))?;
        Ok(())
    }
}

/// Minimal ISO-8601 UTC timestamp without pulling in a date crate.
fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Days since epoch → civil date (Howard Hinnant's algorithm).
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_well_formed() {
        let ts = now_iso8601();
        assert_eq!(ts.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
        assert!(ts.ends_with('Z'));
    }

    #[test]
    fn manifest_match_and_roundtrip() {
        let mut roots = BTreeMap::new();
        roots.insert("lodash".to_string(), "lodash@4.17.21".to_string());
        let mut packages = BTreeMap::new();
        packages.insert(
            "lodash@4.17.21".to_string(),
            LockedPackage {
                resolved: "https://example/lodash.tgz".into(),
                integrity: "sha512-abc".into(),
                shasum: None,
                dependencies: BTreeMap::new(),
                scripts: BTreeMap::new(),
                audited_at: now_iso8601(),
                audit_sources: vec!["osv".into()],
                cve_status: "clean".into(),
                sandboxed: false,
            },
        );
        let lock = Lockfile {
            lockfile_version: LOCKFILE_VERSION,
            roots,
            packages,
        };

        let mut manifest = BTreeMap::new();
        manifest.insert("lodash".to_string(), "^4.17.0".to_string());
        assert!(lock.matches_manifest(&manifest));

        // A bumped range the lock can't satisfy forces re-resolution.
        manifest.insert("lodash".to_string(), "^5.0.0".to_string());
        assert!(!lock.matches_manifest(&manifest));

        let res = lock.to_resolution();
        assert_eq!(res.packages.len(), 1);
        assert_eq!(res.roots.get("lodash").unwrap(), "lodash@4.17.21");
        assert_eq!(
            res.packages
                .get("lodash@4.17.21")
                .unwrap()
                .meta
                .dist
                .tarball,
            "https://example/lodash.tgz"
        );
    }
}
