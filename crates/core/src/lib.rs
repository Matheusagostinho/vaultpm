//! Vault core — secure, pnpm-style package management for Node.js.
//!
//! The crate is organised around a single install pipeline (see [`install`]):
//! resolve → audit (metadata) → fetch + verify → link → lock. The security
//! audit runs *before* any tarball is downloaded or extracted, so a malicious
//! package is rejected on metadata alone whenever possible.

#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub mod audit;
pub mod config;
pub mod error;
pub mod fetcher;
pub mod linker;
pub mod lockfile;
pub mod package_json;
pub mod registry;
pub mod resolver;
pub mod script;
pub mod store;

use audit::AuditReport;
use config::Config;
use console::style;
use error::{Result, VaultError};
use package_json::PackageJson;
use registry::Registry;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Maximum number of packages processed concurrently (network-bound).
const CONCURRENCY: usize = 24;

/// Options controlling an install run.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub project_dir: PathBuf,
    pub include_dev: bool,
    /// When true, security blocks are downgraded to warnings (`--force`).
    pub force: bool,
    /// When true, any advisory (not just critical) blocks the install.
    pub strict: bool,
    /// When true, require an up-to-date `vault.lock` and never modify it
    /// (`--frozen-lockfile`); error if it is missing or out of date.
    pub frozen: bool,
}

impl InstallOptions {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            include_dev: true,
            force: false,
            strict: false,
            frozen: false,
        }
    }
}

/// Summary returned after a successful install.
#[derive(Debug, Default)]
pub struct InstallSummary {
    pub resolved: usize,
    pub downloaded: usize,
    pub advisories: usize,
    pub warnings: Vec<String>,
    pub blocked: Vec<String>,
}

/// Run the full install pipeline for the project at `opts.project_dir`.
pub async fn install(opts: &InstallOptions) -> Result<InstallSummary> {
    let cfg = Config::load(&opts.project_dir);
    let pkg_json = PackageJson::load(&opts.project_dir)?;
    let store = store::Store::open(cfg.store.path.as_deref())?;
    let registry = Registry::new();
    let http = reqwest::Client::builder()
        .user_agent(concat!("vault/", env!("CARGO_PKG_VERSION")))
        .build()?;

    // 1. Resolve.
    let roots = pkg_json.all_dependencies(opts.include_dev);
    if roots.is_empty() {
        println!("{}  no dependencies to install", style("·").dim());
        return Ok(InstallSummary::default());
    }
    // Fast path: a consistent vault.lock lets us skip network resolution.
    let locked =
        lockfile::Lockfile::load(&opts.project_dir).filter(|lock| lock.matches_manifest(&roots));
    let (resolution, used_lockfile) = match locked {
        Some(lock) => {
            eprintln!("{} using vault.lock (lockfile-driven)", style("⟳").cyan());
            (lock.to_resolution(), true)
        }
        None if opts.frozen => {
            return Err(VaultError::Config(
                "--frozen-lockfile: vault.lock is missing or out of date".into(),
            ));
        }
        None => {
            eprintln!("{} resolving dependency graph…", style("⟳").cyan());
            (resolver::resolve(&registry, &roots).await?, false)
        }
    };
    let mut summary = InstallSummary {
        resolved: resolution.packages.len(),
        ..Default::default()
    };
    for w in &resolution.warnings {
        summary.warnings.push(format!("{}: {}", w.name, w.message));
    }

    // 2. Audit (metadata only) — concurrently, fail-closed before any download.
    eprintln!(
        "{} auditing {} packages (OSV + static scan)…",
        style("🛡").yellow(),
        resolution.packages.len()
    );
    // Warm the CVE cache with one batched OSV request (cold-cache fast path).
    let pkg_list: Vec<(String, String)> = resolution
        .packages
        .values()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    audit::prime_osv_cache(&http, &cfg, &store, &pkg_list).await;
    let reports = audit_all(&http, &cfg, &store, &resolution).await;

    let mut audit_reports: BTreeMap<String, AuditReport> = BTreeMap::new();
    for (id, result) in reports {
        match result {
            Ok(report) => {
                summary.advisories += report.advisories.len();
                for adv in &report.advisories {
                    let fix = adv
                        .fixed
                        .as_deref()
                        .map(|v| format!(" — fix: upgrade to >= {v}"))
                        .unwrap_or_default();
                    summary.warnings.push(format!(
                        "{id}: {} [{}] {}{fix}",
                        style(&adv.id).red(),
                        adv.severity,
                        adv.summary
                    ));
                }
                if !report.lifecycle_hooks.is_empty() {
                    summary.warnings.push(format!(
                        "{id}: has lifecycle scripts ({}) — run them sandboxed with `vault run`",
                        report.lifecycle_hooks.join(", ")
                    ));
                }
                audit_reports.insert(id, report);
            }
            Err(VaultError::SecurityBlock { reason, .. }) => {
                summary.blocked.push(format!("{id}: {reason}"));
            }
            Err(e) => return Err(e),
        }
    }

    // 2b. Reputation signals (recency, popularity, typosquat, maintainer-diff).
    for msg in reputation_all(&registry, &http, &cfg, &store, &resolution).await {
        summary.warnings.push(msg);
    }

    // 2c. In strict mode, any advisory (not just critical) is a block.
    if opts.strict && summary.advisories > 0 {
        summary.blocked.push(format!(
            "{} advisory/ies present and --strict is set",
            summary.advisories
        ));
    }

    // 3. Enforce blocks unless --force.
    if !summary.blocked.is_empty() && !opts.force {
        for b in &summary.blocked {
            eprintln!("{} {}", style("✗ BLOCKED").red().bold(), b);
        }
        return Err(VaultError::Blocked(format!(
            "{} package(s) blocked (use --force to override)",
            summary.blocked.len()
        )));
    }

    // 4. Fetch + verify + extract into the store, concurrently.
    eprintln!("{} fetching tarballs…", style("⬇").green());
    summary.downloaded = fetch_all(&registry, &store, &resolution).await?;

    // 5. Link into node_modules.
    eprintln!("{} linking node_modules…", style("🔗").blue());
    linker::link_all(&store, &resolution, &opts.project_dir)?;

    // 6. Write the lockfile (unless we just installed *from* an up-to-date one).
    if !used_lockfile {
        let lock =
            lockfile::Lockfile::from_resolution(&resolution, &audit_reports, &cfg.audit.sources);
        lock.save(&opts.project_dir)?;
    }

    Ok(summary)
}

/// Add one or more `name[@range]` specs to the project and install.
pub async fn add(opts: &InstallOptions, specs: &[String]) -> Result<InstallSummary> {
    let mut pkg_json = PackageJson::load(&opts.project_dir)?;
    let registry = Registry::new();
    for spec in specs {
        let (name, range) = parse_spec(spec);
        let range = match range {
            Some(r) => r,
            None => {
                // Default to a caret range on the current latest version.
                let packument = registry.packument(&name).await?;
                let latest = packument
                    .dist_tags
                    .get("latest")
                    .cloned()
                    .unwrap_or_else(|| "*".into());
                if latest == "*" {
                    "*".into()
                } else {
                    format!("^{latest}")
                }
            }
        };
        pkg_json.set_dependency(&name, &range);
    }
    pkg_json.save()?;
    install(opts).await
}

/// Remove dependencies from `package.json`, re-link the remaining graph.
pub async fn remove(opts: &InstallOptions, names: &[String]) -> Result<InstallSummary> {
    let mut pkg_json = PackageJson::load(&opts.project_dir)?;
    for name in names {
        if !pkg_json.remove_dependency(name) {
            eprintln!("{} {name} not found in package.json", style("·").dim());
        }
    }
    pkg_json.save()?;
    install(opts).await
}

/// Audit the current project's dependency graph without installing.
pub async fn audit_project(project_dir: &Path) -> Result<InstallSummary> {
    let cfg = Config::load(project_dir);
    let pkg_json = PackageJson::load(project_dir)?;
    let store = store::Store::open(cfg.store.path.as_deref())?;
    let registry = Registry::new();
    let http = reqwest::Client::new();

    let roots = pkg_json.all_dependencies(true);
    let resolution = resolver::resolve(&registry, &roots).await?;
    let mut summary = InstallSummary {
        resolved: resolution.packages.len(),
        ..Default::default()
    };

    let pkg_list: Vec<(String, String)> = resolution
        .packages
        .values()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    audit::prime_osv_cache(&http, &cfg, &store, &pkg_list).await;
    for (id, result) in audit_all(&http, &cfg, &store, &resolution).await {
        match result {
            Ok(report) => {
                summary.advisories += report.advisories.len();
                for adv in &report.advisories {
                    let fix = adv
                        .fixed
                        .as_deref()
                        .map(|v| format!(" — fix: upgrade to >= {v}"))
                        .unwrap_or_default();
                    summary.warnings.push(format!(
                        "{id}: {} [{}] {}{fix}",
                        adv.id, adv.severity, adv.summary
                    ));
                }
            }
            Err(VaultError::SecurityBlock { reason, .. }) => {
                summary.blocked.push(format!("{id}: {reason}"))
            }
            Err(e) => return Err(e),
        }
    }
    for msg in reputation_all(&registry, &http, &cfg, &store, &resolution).await {
        summary.warnings.push(msg);
    }
    Ok(summary)
}

async fn audit_all(
    http: &reqwest::Client,
    cfg: &Config,
    store: &store::Store,
    resolution: &resolver::Resolution,
) -> Vec<(String, Result<AuditReport>)> {
    use futures::stream::StreamExt;
    futures::stream::iter(resolution.packages.values().cloned())
        .map(|pkg| {
            let http = http.clone();
            let cfg = cfg.clone();
            let store = store.clone();
            async move {
                let id = pkg.id();
                let res = audit::audit_package(&http, &cfg, &pkg.meta, Some(&store)).await;
                (id, res)
            }
        })
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await
}

/// Run reputation checks (recency + popularity + typosquat + maintainer-diff).
/// Scoped to **direct** dependencies by default; set `security.check_transitive`
/// to cover the whole graph. Returns warning strings.
async fn reputation_all(
    registry: &Registry,
    http: &reqwest::Client,
    cfg: &Config,
    store: &store::Store,
    resolution: &resolver::Resolution,
) -> Vec<String> {
    use futures::stream::StreamExt;
    let now = audit::reputation::now_epoch_days();

    let targets: Vec<resolver::ResolvedPackage> = if cfg.security.check_transitive {
        resolution.packages.values().cloned().collect()
    } else {
        resolution
            .roots
            .values()
            .filter_map(|real_id| resolution.packages.get(real_id).cloned())
            .collect()
    };

    futures::stream::iter(targets)
        .map(|pkg| {
            let registry = registry.clone();
            let http = http.clone();
            let cfg = cfg.clone();
            let store = store.clone();
            async move {
                let Ok(packument) = registry.packument(&pkg.name).await else {
                    return Vec::new();
                };
                let downloads = audit::reputation::weekly_downloads(&http, &pkg.name).await;
                let mut msgs: Vec<String> =
                    audit::reputation::assess(&cfg, &packument, &pkg.version, downloads, now)
                        .into_iter()
                        .map(|w| w.message)
                        .collect();
                if let Some(w) = audit::reputation::check_maintainers(&store, &packument) {
                    msgs.push(w.message);
                }
                msgs
            }
        })
        .buffer_unordered(CONCURRENCY)
        .collect::<Vec<Vec<String>>>()
        .await
        .into_iter()
        .flatten()
        .collect()
}

async fn fetch_all(
    registry: &Registry,
    store: &store::Store,
    resolution: &resolver::Resolution,
) -> Result<usize> {
    use futures::stream::StreamExt;
    let results: Vec<Result<bool>> = futures::stream::iter(resolution.packages.values().cloned())
        .map(|pkg| {
            let registry = registry.clone();
            let store = store.clone();
            async move { fetcher::ensure_in_store(&registry, &store, &pkg).await }
        })
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;

    let mut downloaded = 0;
    for r in results {
        if r? {
            downloaded += 1;
        }
    }
    Ok(downloaded)
}

/// Split a `name@range` (or scoped `@scope/name@range`) spec.
fn parse_spec(spec: &str) -> (String, Option<String>) {
    if let Some(rest) = spec.strip_prefix('@') {
        // Scoped: the version `@` is the one after the name's `/`.
        if let Some(at) = rest.find('@') {
            let (name, range) = rest.split_at(at);
            return (format!("@{name}"), Some(range[1..].to_string()));
        }
        return (spec.to_string(), None);
    }
    match spec.split_once('@') {
        Some((name, range)) => (name.to_string(), Some(range.to_string())),
        None => (spec.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_spec() {
        assert_eq!(parse_spec("lodash"), ("lodash".into(), None));
        assert_eq!(
            parse_spec("lodash@4.17.21"),
            ("lodash".into(), Some("4.17.21".into()))
        );
    }

    #[test]
    fn parse_scoped_spec() {
        assert_eq!(parse_spec("@types/node"), ("@types/node".into(), None));
        assert_eq!(
            parse_spec("@types/node@20.0.0"),
            ("@types/node".into(), Some("20.0.0".into()))
        );
    }
}
