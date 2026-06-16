//! Sandboxed execution of `package.json` scripts (phase 3).
//!
//! Scripts run through the [`vault_sandbox`] Landlock sandbox: they may touch
//! the project, the store, and the system runtime, but **not** `~/.ssh`,
//! `~/.aws`, `~/.npmrc`, or the rest of `$HOME`. This is how Vault can run a
//! `postinstall` without handing it your credentials.

use crate::error::{Result, VaultError};
use crate::package_json::PackageJson;
use crate::store::Store;
use std::path::{Path, PathBuf};
use vault_sandbox::{Policy, Status};

/// Run a named script from the project's `package.json` inside the sandbox.
///
/// Returns the process exit code. Errors if the script is not defined.
pub fn run_named(project_dir: &Path, script: &str) -> Result<i32> {
    let pkg = PackageJson::load(project_dir)?;
    let body = pkg
        .script(script)
        .ok_or_else(|| VaultError::Config(format!("no script named `{script}` in package.json")))?;
    run_command(project_dir, &body)
}

/// Run an arbitrary shell command line in the project sandbox.
pub fn run_command(project_dir: &Path, command_line: &str) -> Result<i32> {
    let project_dir =
        std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let policy = build_policy(&project_dir);

    // node's own runtime must be readable/executable.
    let env = build_env(&project_dir);

    let (status, sb) = vault_sandbox::run(
        "/bin/sh",
        &["-c".to_string(), command_line.to_string()],
        &project_dir,
        &env,
        &policy,
    )
    .map_err(|e| VaultError::Config(format!("failed to run script: {e}")))?;

    if sb == Status::Unavailable {
        tracing::warn!(
            "Landlock sandbox unavailable on this system — script ran without isolation"
        );
    }
    Ok(status.code().unwrap_or(1))
}

/// Whether the sandbox will actually be enforced here.
pub fn sandbox_enforced() -> bool {
    vault_sandbox::is_available()
}

/// Assemble the filesystem policy for a project script run.
fn build_policy(project_dir: &Path) -> Policy {
    let mut policy = Policy::default();

    // System runtime: read-only.
    for dir in [
        "/usr", "/bin", "/lib", "/lib64", "/etc", "/proc", "/dev", "/opt", "/sbin",
    ] {
        if Path::new(dir).exists() {
            policy.allow_read(dir);
        }
    }

    // The Node.js install (e.g. nvm) — grant its root so node can load itself.
    if let Some(node_root) = node_install_root() {
        policy.allow_read(node_root);
    }

    // The global store: read-only (packages live here).
    if let Ok(store) = Store::open(None) {
        policy.allow_read(store.root());
    }

    // The project: read + write (node_modules, build output, etc.).
    policy.allow_write(project_dir);

    // Scratch space.
    policy.allow_write("/tmp");

    policy
}

/// Environment for the script: inherit the parent's but ensure the project's
/// `node_modules/.bin` is first on `PATH` (npm-compatible behaviour).
fn build_env(project_dir: &Path) -> Vec<(String, String)> {
    let bin = project_dir.join("node_modules").join(".bin");
    let prev = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{}", bin.display(), prev);
    let mut env = vec![("PATH".to_string(), path)];
    // Pass through a few variables node/scripts commonly need.
    for key in ["HOME", "LANG", "TERM", "USER"] {
        if let Ok(v) = std::env::var(key) {
            env.push((key.to_string(), v));
        }
    }
    env
}

/// Best-effort discovery of the Node.js install root by locating `node` on PATH
/// and walking up from its `bin/` directory.
fn node_install_root() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("node");
        if candidate.exists() {
            // dir is `<root>/bin`; grant `<root>` so lib/ and friends are covered.
            return dir.parent().map(Path::to_path_buf).or(Some(dir));
        }
    }
    None
}
