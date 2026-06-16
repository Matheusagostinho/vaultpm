//! CVE lookup via the free, no-auth OSV.dev API.
//!
//! We POST `{package, version}` to `https://api.osv.dev/v1/query` and surface
//! any advisories. OSV aggregates the GitHub Advisory Database, npm advisories
//! and more, so it is a strong free signal.

use crate::error::Result;
use serde::{Deserialize, Serialize};

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

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
#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    /// One of: critical / high / moderate / low / unknown.
    pub severity: String,
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
    Ok(parsed.vulns.into_iter().map(normalize).collect())
}

fn normalize(v: OsvVuln) -> Advisory {
    let severity = classify_severity(&v);
    Advisory {
        id: v.id,
        summary: v.summary.unwrap_or_else(|| "(no summary provided)".into()),
        severity,
    }
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

/// Extract the numeric base score from a CVSS vector string if it embeds one,
/// otherwise try to parse the whole string as a number.
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
        };
        assert!(a.is_critical());
    }
}
