//! CVE lookup via the free, no-auth OSV.dev API.
//!
//! We POST `{package, version}` to `https://api.osv.dev/v1/query` and surface
//! any advisories. OSV aggregates the GitHub Advisory Database, npm advisories
//! and more, so it is a strong free signal.

use crate::error::Result;
use serde::{Deserialize, Serialize};

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// OSV caps batch queries at 1000; stay well under.
const BATCH_SIZE: usize = 500;

#[derive(Serialize)]
struct OsvQuery<'a> {
    version: &'a str,
    package: OsvPackage<'a>,
}

#[derive(Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Deserialize, Default)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize, Clone)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<DatabaseSpecific>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Deserialize, Clone, Default)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Deserialize, Clone, Default)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Deserialize, Clone, Default)]
struct OsvEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Deserialize, Clone)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize, Clone)]
struct DatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
}

/// A normalized advisory result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    /// One of: critical / high / moderate / low / unknown.
    pub severity: String,
    /// The lowest version that fixes this advisory for the installed version's
    /// release line, if OSV provides one (the recommended upgrade target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
}

impl Advisory {
    /// Whether this advisory should abort a strict install.
    pub fn is_critical(&self) -> bool {
        matches!(self.severity.as_str(), "critical" | "high")
    }
}

/// Query OSV for a single package version. Network failures degrade to an empty
/// result with a warning rather than blocking the install (fail-open on the
/// advisory lookup, fail-closed on integrity — those are different trust axes).
pub async fn query(client: &reqwest::Client, name: &str, version: &str) -> Result<Vec<Advisory>> {
    let body = OsvQuery {
        version,
        package: OsvPackage {
            name,
            ecosystem: "npm",
        },
    };
    let resp = match client.post(OSV_QUERY_URL).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("OSV query for {name}@{version} failed: {e}");
            return Ok(vec![]);
        }
    };
    if !resp.status().is_success() {
        tracing::warn!("OSV returned HTTP {} for {name}@{version}", resp.status());
        return Ok(vec![]);
    }
    let parsed: OsvResponse = resp.json().await.unwrap_or_default();
    Ok(parsed
        .vulns
        .into_iter()
        .map(|v| normalize(v, version))
        .collect())
}

#[derive(Serialize)]
struct OsvBatch<'a> {
    queries: Vec<OsvQuery<'a>>,
}

#[derive(Deserialize, Default)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvBatchResult>,
}

#[derive(Deserialize, Default)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvBatchVuln>,
}

#[derive(Deserialize)]
struct OsvBatchVuln {
    id: String,
}

/// Batch-query OSV for many packages in **one** request (chunked at
/// [`BATCH_SIZE`]). Returns, per input index, the advisory IDs (empty = clean).
///
/// The batch endpoint returns only IDs, so callers fetch full details via
/// [`query`] for the (rare) packages that actually have advisories. Fail-open:
/// any network/parse error yields empty results for that chunk.
pub async fn query_batch(
    client: &reqwest::Client,
    packages: &[(String, String)],
) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::with_capacity(packages.len());
    for chunk in packages.chunks(BATCH_SIZE) {
        out.extend(query_batch_chunk(client, chunk).await);
    }
    out
}

async fn query_batch_chunk(
    client: &reqwest::Client,
    chunk: &[(String, String)],
) -> Vec<Vec<String>> {
    let empty = || vec![Vec::new(); chunk.len()];
    let body = OsvBatch {
        queries: chunk
            .iter()
            .map(|(name, version)| OsvQuery {
                version,
                package: OsvPackage {
                    name,
                    ecosystem: "npm",
                },
            })
            .collect(),
    };
    let resp = match client.post(OSV_BATCH_URL).json(&body).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!("OSV batch returned HTTP {}", r.status());
            return empty();
        }
        Err(e) => {
            tracing::warn!("OSV batch query failed: {e}");
            return empty();
        }
    };
    let parsed: OsvBatchResponse = resp.json().await.unwrap_or_default();
    let mut results: Vec<Vec<String>> = parsed
        .results
        .into_iter()
        .map(|r| r.vulns.into_iter().map(|v| v.id).collect())
        .collect();
    results.resize(chunk.len(), Vec::new());
    results
}

fn normalize(v: OsvVuln, current_version: &str) -> Advisory {
    let severity = classify_severity(&v);
    let fixed = recommended_fix(&v, current_version);
    Advisory {
        id: v.id,
        summary: v.summary.unwrap_or_else(|| "(no summary provided)".into()),
        severity,
        fixed,
    }
}

/// The lowest "fixed" version on the release line that contains
/// `current_version` — i.e. the minimal upgrade that resolves the advisory.
fn recommended_fix(v: &OsvVuln, current_version: &str) -> Option<String> {
    use node_semver::Version;
    let current = Version::parse(current_version).ok()?;
    let mut best: Option<Version> = None;
    for affected in &v.affected {
        for range in &affected.ranges {
            // Track the most recent `introduced` as we walk the event list.
            let mut introduced = Version::parse("0.0.0").ok();
            for event in &range.events {
                if let Some(i) = &event.introduced {
                    introduced = if i == "0" {
                        Version::parse("0.0.0").ok()
                    } else {
                        Version::parse(i).ok()
                    };
                }
                if let Some(f) = &event.fixed {
                    let Ok(fix) = Version::parse(f) else { continue };
                    let in_line = introduced.as_ref().map(|iv| current >= *iv).unwrap_or(true);
                    if in_line && current < fix {
                        best = Some(match best {
                            Some(b) if b <= fix => b,
                            _ => fix,
                        });
                    }
                }
            }
        }
    }
    best.map(|v| v.to_string())
}

/// Best-effort severity classification from OSV's heterogeneous fields.
fn classify_severity(v: &OsvVuln) -> String {
    // GitHub advisories expose a textual severity in database_specific.
    if let Some(ds) = &v.database_specific {
        if let Some(sev) = &ds.severity {
            return sev.to_lowercase();
        }
    }
    // Otherwise derive from a CVSS vector score if present.
    for s in &v.severity {
        if s.kind.starts_with("CVSS") {
            if let Some(score) = cvss_base_score(&s.score) {
                return bucket(score).to_string();
            }
        }
    }
    "unknown".to_string()
}

/// Parse a base score from OSV's `severity.score`. OSV usually stores a CVSS
/// *vector* (`CVSS:3.1/AV:N/...`), which does not embed the numeric score, so we
/// only succeed when the field is a plain number. Computing a base score from a
/// vector is a follow-up (see NEXT-STEPS); in practice GHSA advisories carry a
/// textual severity which `classify_severity` reads first, and `--strict` blocks
/// any advisory regardless of computed severity.
fn cvss_base_score(score: &str) -> Option<f32> {
    score.parse::<f32>().ok()
}

fn bucket(score: f32) -> &'static str {
    match score {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "moderate",
        s if s > 0.0 => "low",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_buckets() {
        assert_eq!(bucket(9.8), "critical");
        assert_eq!(bucket(7.5), "high");
        assert_eq!(bucket(5.0), "moderate");
        assert_eq!(bucket(1.0), "low");
    }

    #[test]
    fn critical_and_high_abort() {
        let a = Advisory {
            id: "GHSA-x".into(),
            summary: "".into(),
            severity: "critical".into(),
            fixed: None,
        };
        assert!(a.is_critical());
    }
}
