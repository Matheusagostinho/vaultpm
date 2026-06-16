//! The security layer — Vault's differentiator.
//!
//! Each package passes through this gate *before* its files are linked into the
//! project. The pipeline is:
//!
//! 1. [`integrity`] — SHA-512 verification against the registry (fail-closed).
//! 2. [`osv`] — CVE lookup via OSV.dev.
//! 3. [`static_scan`] — pattern analysis of lifecycle scripts.
//!
//! Phase 3 adds maintainer-takeover detection, a Landlock sandbox, and Sigstore
//! provenance (see `ROADMAP.md`).

pub mod integrity;
pub mod osv;
pub mod static_scan;

use crate::config::Config;
use crate::error::{Result, VaultError};
use crate::registry::VersionMeta;

/// Aggregated audit outcome for one package.
#[derive(Debug, Default)]
pub struct AuditReport {
    pub advisories: Vec<osv::Advisory>,
    pub findings: Vec<static_scan::Finding>,
    /// Lifecycle hooks present on the package (skipped, not executed, in MVP).
    pub lifecycle_hooks: Vec<String>,
}

impl AuditReport {
    /// Whether the package is clean of advisories and blocking findings.
    pub fn is_clean(&self) -> bool {
        self.advisories.is_empty() && self.findings.is_empty()
    }

    pub fn has_critical_cve(&self) -> bool {
        self.advisories.iter().any(osv::Advisory::is_critical)
    }
}

/// Run the full audit pipeline for a single package version.
///
/// Returns the report, or a [`VaultError::SecurityBlock`] when policy demands a
/// hard stop (critical CVE with `abort_on_critical_cve`, or a blocking static
/// finding).
pub async fn audit_package(
    client: &reqwest::Client,
    cfg: &Config,
    meta: &VersionMeta,
) -> Result<AuditReport> {
    let mut report = AuditReport::default();

    // 1. CVE lookup (only if OSV is an enabled source).
    if cfg.audit.sources.iter().any(|s| s == "osv") {
        report.advisories = osv::query(client, &meta.name, &meta.version).await?;
    }

    // 2. Static analysis of lifecycle scripts.
    report.findings = static_scan::scan(&meta.scripts);
    for hook in ["preinstall", "install", "postinstall"] {
        if meta.scripts.contains_key(hook) {
            report.lifecycle_hooks.push(hook.to_string());
        }
    }

    // 3. Enforce policy.
    if cfg.security.abort_on_critical_cve && report.has_critical_cve() {
        let ids: Vec<_> = report
            .advisories
            .iter()
            .filter(|a| a.is_critical())
            .map(|a| a.id.clone())
            .collect();
        return Err(VaultError::SecurityBlock {
            name: meta.name.clone(),
            version: meta.version.clone(),
            reason: format!("critical/high CVE(s): {}", ids.join(", ")),
        });
    }

    if static_scan::has_block(&report.findings) {
        let reasons: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == static_scan::Severity::Block)
            .map(|f| format!("{} ({})", f.explanation, f.script))
            .collect();
        return Err(VaultError::SecurityBlock {
            name: meta.name.clone(),
            version: meta.version.clone(),
            reason: format!("malicious lifecycle script: {}", reasons.join("; ")),
        });
    }

    Ok(report)
}
