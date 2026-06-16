//! Persistent audit cache (phase 2).
//!
//! CVE lookups are cached per `name@version` in the global store
//! (`~/.vault/store/v1/audit/`). A cached verdict is reused while it is younger
//! than `audit.cache_ttl_hours`, so repeated installs across projects don't
//! re-hit OSV for packages already vetted.

use crate::audit::osv::Advisory;
use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const KIND: &str = "audit";

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    /// Unix epoch seconds at which the audit ran.
    audited_at: u64,
    advisories: Vec<Advisory>,
}

/// Return cached advisories for `name@version` if present and still fresh.
pub fn get(store: &Store, name: &str, version: &str, ttl_hours: u64) -> Option<Vec<Advisory>> {
    let key = format!("{name}@{version}");
    let entry: CacheEntry = store.read_meta(KIND, &key)?;
    let age_secs = now_secs().saturating_sub(entry.audited_at);
    if age_secs <= ttl_hours.saturating_mul(3600) {
        Some(entry.advisories)
    } else {
        None
    }
}

/// Store the advisory verdict for `name@version`.
pub fn put(store: &Store, name: &str, version: &str, advisories: &[Advisory]) {
    let key = format!("{name}@{version}");
    let entry = CacheEntry {
        audited_at: now_secs(),
        advisories: advisories.to_vec(),
    };
    if let Err(e) = store.write_meta(KIND, &key, &entry) {
        tracing::warn!("could not write audit cache for {key}: {e}");
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (Store, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "vault-cache-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        (Store::open(Some(dir.to_str().unwrap())).unwrap(), dir)
    }

    #[test]
    fn roundtrip_within_ttl() {
        let (store, dir) = temp_store();
        let adv = vec![Advisory {
            id: "GHSA-x".into(),
            summary: "s".into(),
            severity: "high".into(),
        }];
        put(&store, "left-pad", "1.0.0", &adv);
        let got = get(&store, "left-pad", "1.0.0", 24).expect("fresh hit");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "GHSA-x");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_entry_is_a_miss() {
        let (store, dir) = temp_store();
        // Hand-write an entry aged two hours.
        let entry = CacheEntry {
            audited_at: now_secs().saturating_sub(2 * 3600),
            advisories: vec![],
        };
        store.write_meta(KIND, "pkg@1.0.0", &entry).unwrap();
        assert!(get(&store, "pkg", "1.0.0", 1).is_none(), "2h old > 1h TTL");
        assert!(get(&store, "pkg", "1.0.0", 3).is_some(), "2h old < 3h TTL");
        // A clearly-missing package is always a miss.
        assert!(get(&store, "missing", "9.9.9", 24).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
