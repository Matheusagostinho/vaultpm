//! `vault.lock` — a JSON lockfile recording resolved versions and the security
//! verdict for each package, so re-installs are reproducible and auditable.

use crate::audit::AuditReport;
use crate::error::Result;
use crate::resolver::Resolution;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const LOCKFILE_NAME: &str = "vault.lock";
const LOCKFILE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Lockfile {
    #[serde(rename = "lockfileVersion")]
    pub lockfile_version: u32,
    pub packages: BTreeMap<String, LockedPackage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedPackage {
    pub resolved: String,
    pub integrity: String,
    /// Resolved dependency graph edges: `depName -> version`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
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
            packages.insert(
                pkg.id(),
                LockedPackage {
                    resolved: pkg.meta.dist.tarball.clone(),
                    integrity: pkg.meta.dist.integrity.clone().unwrap_or_default(),
                    dependencies: pkg.deps.clone(),
                    audited_at: now.clone(),
                    audit_sources: audit_sources.to_vec(),
                    cve_status: cve_status.to_string(),
                    sandboxed: false,
                },
            );
        }
        Self {
            lockfile_version: LOCKFILE_VERSION,
            packages,
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
}
