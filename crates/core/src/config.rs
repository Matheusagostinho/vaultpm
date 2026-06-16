//! Project configuration parsed from `vault.toml`.

use serde::Deserialize;
use std::path::Path;

/// Top-level Vault configuration. All sections are optional and fall back to
/// safe defaults so that a project without a `vault.toml` still works.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub security: SecurityConfig,
    pub audit: AuditConfig,
    pub sandbox: SandboxConfig,
    pub store: StoreConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Block lifecycle scripts that reach out to the network.
    pub block_postinstall_network: bool,
    /// Warn when a maintainer changed within this many days.
    pub warn_new_maintainer_days: u32,
    /// Warn for packages below this weekly-download threshold.
    pub min_weekly_downloads: u64,
    /// Abort the install if a critical CVE is found.
    pub abort_on_critical_cve: bool,
    /// Require Sigstore provenance (strict mode, phase 3).
    pub require_provenance: bool,
    /// Run reputation checks (recency/popularity) on transitive deps too, not
    /// just direct ones. Off by default to bound API calls.
    pub check_transitive: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// CVE sources to query (currently: "osv").
    pub sources: Vec<String>,
    /// How long an audit result stays valid in the store.
    pub cache_ttl_hours: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub allow_fs_read: Vec<String>,
    pub allow_fs_write: Vec<String>,
    pub allow_net: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct StoreConfig {
    /// Override the global store path. `None` means `~/.vault/store`.
    pub path: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            block_postinstall_network: true,
            warn_new_maintainer_days: 30,
            min_weekly_downloads: 100,
            abort_on_critical_cve: true,
            require_provenance: false,
            check_transitive: false,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sources: vec!["osv".to_string()],
            cache_ttl_hours: 24,
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_fs_read: vec!["./node_modules".to_string()],
            allow_fs_write: vec!["./node_modules".to_string()],
            allow_net: vec![],
        }
    }
}

impl Config {
    /// Load `vault.toml` from the project directory, falling back to defaults
    /// when the file is missing.
    pub fn load(project_dir: &Path) -> Self {
        let path = project_dir.join("vault.toml");
        match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::warn!("ignoring invalid vault.toml: {e}");
                    Config::default()
                }
            },
            Err(_) => Config::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_secure() {
        let cfg = Config::default();
        assert!(cfg.security.abort_on_critical_cve);
        assert!(cfg.security.block_postinstall_network);
        assert_eq!(cfg.audit.sources, vec!["osv".to_string()]);
    }

    #[test]
    fn partial_config_merges_with_defaults() {
        let toml = r#"
            [security]
            abort_on_critical_cve = false
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(!cfg.security.abort_on_critical_cve);
        // Untouched field keeps its default.
        assert!(cfg.security.block_postinstall_network);
    }
}
