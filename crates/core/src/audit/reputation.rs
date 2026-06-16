//! Reputation signals (phase 2): "is this package suspiciously new, or
//! suspiciously unpopular?".
//!
//! These are **soft** signals — they produce warnings, never hard blocks —
//! because legitimate new or niche packages exist. They are the cheap
//! first-line heuristic behind maintainer-takeover detection: a brand-new
//! release of an otherwise-established package is the classic takeover pattern.

use crate::audit::typosquat;
use crate::config::Config;
use crate::registry::Packument;
use crate::store::Store;
use serde::{Deserialize, Serialize};

/// A single reputation warning for a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepWarning {
    pub message: String,
}

#[derive(Serialize, Deserialize, Default)]
struct MaintainerRecord {
    names: Vec<String>,
}

/// Assess recency + popularity for one resolved package.
///
/// `weekly_downloads` is fetched separately (network) and passed in so this
/// function stays pure and unit-testable. `now_days` is days-since-epoch.
pub fn assess(
    cfg: &Config,
    packument: &Packument,
    version: &str,
    weekly_downloads: Option<u64>,
    now_days: i64,
) -> Vec<RepWarning> {
    let mut out = Vec::new();

    // Recency: a version published within the configured window is higher risk.
    if let Some(age) = published_age_days(packument, version, now_days) {
        let window = cfg.security.warn_new_maintainer_days as i64;
        if age >= 0 && age < window {
            let maint = packument.maintainers.len();
            out.push(RepWarning {
                message: format!(
                    "{}@{version} was published {age} day(s) ago (< {window}d); {maint} maintainer(s) — verify this is expected (possible maintainer takeover)",
                    packument.name
                ),
            });
        }
    }

    // Popularity: very low download counts are typical of typosquats.
    if let Some(dl) = weekly_downloads {
        if dl < cfg.security.min_weekly_downloads {
            out.push(RepWarning {
                message: format!(
                    "{} has only {dl} weekly downloads (< {}) — double-check the package name",
                    packument.name, cfg.security.min_weekly_downloads
                ),
            });
        }
    }

    // Typosquatting: does this name look like a popular package?
    if let Some(popular) = typosquat::nearest_popular(&packument.name) {
        out.push(RepWarning {
            message: format!(
                "{} closely resembles the popular package `{popular}` — possible typosquat",
                packument.name
            ),
        });
    }

    out
}

/// Compare the package's current maintainer set against the one seen on the
/// last install and warn if new maintainers appeared. Always updates the stored
/// record. Returns `None` on first sight (nothing to compare yet).
pub fn check_maintainers(store: &Store, packument: &Packument) -> Option<RepWarning> {
    let mut current: Vec<String> = packument
        .maintainers
        .iter()
        .map(|m| m.name.clone())
        .filter(|n| !n.is_empty())
        .collect();
    current.sort();
    current.dedup();

    let prev: Option<MaintainerRecord> = store.read_meta("maintainers", &packument.name);
    let warning = prev.as_ref().and_then(|rec| {
        let added: Vec<String> = current
            .iter()
            .filter(|n| !rec.names.contains(n))
            .cloned()
            .collect();
        if !rec.names.is_empty() && !added.is_empty() {
            Some(RepWarning {
                message: format!(
                    "{}: maintainer set changed since last install (new: {}) — possible takeover",
                    packument.name,
                    added.join(", ")
                ),
            })
        } else {
            None
        }
    });

    let _ = store.write_meta(
        "maintainers",
        &packument.name,
        &MaintainerRecord { names: current },
    );
    warning
}

/// Days between a version's publish timestamp and `now_days`. `None` if the
/// timestamp is missing or unparseable.
fn published_age_days(packument: &Packument, version: &str, now_days: i64) -> Option<i64> {
    let ts = packument.time.get(version)?;
    let day = iso_date_to_epoch_days(ts)?;
    Some(now_days - day)
}

/// Current time as days since the Unix epoch (UTC).
pub fn now_epoch_days() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 86_400) as i64
}

/// Parse the date portion of an ISO-8601 timestamp (`YYYY-MM-DD...`) into days
/// since the Unix epoch. Ignores the time-of-day part.
fn iso_date_to_epoch_days(ts: &str) -> Option<i64> {
    let date = ts.split('T').next()?;
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Howard Hinnant's days-from-civil algorithm (inverse of the one in lockfile).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Fetch last-week download count from the npm downloads API. Returns `None` on
/// any error (fail-open — this is only a soft signal).
pub async fn weekly_downloads(client: &reqwest::Client, name: &str) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct Point {
        downloads: u64,
    }
    let url = format!("https://api.npmjs.org/downloads/point/last-week/{name}");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Point>().await.ok().map(|p| p.downloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Maintainer, Packument};
    use std::collections::HashMap;

    fn packument_with(version: &str, published: &str, maintainers: usize) -> Packument {
        let mut time = HashMap::new();
        time.insert(version.to_string(), published.to_string());
        Packument {
            name: "demo".into(),
            dist_tags: HashMap::new(),
            versions: HashMap::new(),
            time,
            maintainers: (0..maintainers)
                .map(|i| Maintainer {
                    name: format!("m{i}"),
                    email: None,
                })
                .collect(),
        }
    }

    #[test]
    fn epoch_days_roundtrip() {
        // 1970-01-01 is day 0; 1970-01-02 is day 1.
        assert_eq!(iso_date_to_epoch_days("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso_date_to_epoch_days("1970-01-02"), Some(1));
        assert_eq!(iso_date_to_epoch_days("2000-01-01"), Some(10957));
    }

    #[test]
    fn recent_publish_warns() {
        let cfg = Config::default(); // warn window = 30 days
        let now = iso_date_to_epoch_days("2026-01-31").unwrap();
        let pack = packument_with("1.0.0", "2026-01-20", 1); // 11 days old
        let w = assess(&cfg, &pack, "1.0.0", None, now);
        assert_eq!(w.len(), 1);
        assert!(w[0].message.contains("11 day"));
    }

    #[test]
    fn old_publish_is_quiet() {
        let cfg = Config::default();
        let now = iso_date_to_epoch_days("2026-01-31").unwrap();
        let pack = packument_with("1.0.0", "2020-01-01", 3); // years old
        assert!(assess(&cfg, &pack, "1.0.0", None, now).is_empty());
    }

    #[test]
    fn low_downloads_warns() {
        let cfg = Config::default(); // threshold = 100
        let now = now_epoch_days();
        let pack = packument_with("1.0.0", "2000-01-01", 2);
        let w = assess(&cfg, &pack, "1.0.0", Some(7), now);
        assert_eq!(w.len(), 1);
        assert!(w[0].message.contains("7 weekly downloads"));
    }

    #[test]
    fn popular_old_package_is_quiet() {
        let cfg = Config::default();
        let now = now_epoch_days();
        let pack = packument_with("1.0.0", "2015-01-01", 5);
        assert!(assess(&cfg, &pack, "1.0.0", Some(5_000_000), now).is_empty());
    }
}
