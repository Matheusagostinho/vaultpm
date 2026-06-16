//! Vault CLI. The same logic backs both the `vault` and the short `vt` binary
//! (see `src/bin/`).

use clap::{Parser, Subcommand};
use console::style;
use std::path::PathBuf;
use std::process::ExitCode;
use vault_core::{InstallOptions, InstallSummary};

#[derive(Parser)]
#[command(
    name = "vault",
    bin_name = "vault",
    version,
    about = "Secure, pnpm-style Node.js package manager that blocks supply-chain attacks before install.",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Run in this directory instead of the current one.
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Install all dependencies from package.json (or add packages).
    #[command(visible_alias = "i")]
    Install {
        /// Optional packages to add, e.g. `lodash` or `lodash@4.17.21`.
        packages: Vec<String>,
        /// Skip devDependencies.
        #[arg(long)]
        production: bool,
        /// Install even if security policy would block a package.
        #[arg(long)]
        force: bool,
        /// Treat any advisory (not just critical) as a block.
        #[arg(long)]
        strict: bool,
    },
    /// Add one or more packages to dependencies and install.
    Add {
        packages: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// Remove one or more packages.
    #[command(visible_alias = "rm")]
    Remove { packages: Vec<String> },
    /// Audit the dependency graph for CVEs and malicious scripts.
    Audit,
    /// Run a script defined in package.json (placeholder — phase 4).
    Run { script: String },
}

/// Synchronous entry point used by both the `vault` and `vt` binaries. Builds
/// the Tokio runtime and dispatches the parsed command.
pub fn run() -> ExitCode {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime");
    runtime.block_on(run_async())
}

async fn run_async() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    let project_dir = cli
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));

    let result = match cli.command {
        Command::Install {
            packages,
            production,
            force,
            strict,
        } => {
            let mut opts = InstallOptions::new(&project_dir);
            opts.include_dev = !production;
            opts.force = force;
            opts.strict = strict;
            if packages.is_empty() {
                finish(vault_core::install(&opts).await)
            } else {
                finish(vault_core::add(&opts, &packages).await)
            }
        }
        Command::Add { packages, force } => {
            let mut opts = InstallOptions::new(&project_dir);
            opts.force = force;
            finish(vault_core::add(&opts, &packages).await)
        }
        Command::Remove { packages } => {
            let opts = InstallOptions::new(&project_dir);
            finish(vault_core::remove(&opts, &packages).await)
        }
        Command::Audit => match vault_core::audit_project(&project_dir).await {
            Ok(summary) => {
                print_summary(&summary, "Audit complete");
                if summary.blocked.is_empty() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(e) => fail(e),
        },
        Command::Run { script } => {
            let sb = if vault_core::script::sandbox_enforced() {
                style("🔒 sandboxed (Landlock)").green()
            } else {
                style("⚠ no sandbox (Landlock unavailable)").yellow()
            };
            eprintln!("{} running `{script}` — {sb}", style("▶").cyan());
            match vault_core::script::run_named(&project_dir, &script) {
                Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
                Err(e) => fail(e),
            }
        }
    };

    result
}

fn finish(result: vault_core::error::Result<InstallSummary>) -> ExitCode {
    match result {
        Ok(summary) => {
            print_summary(&summary, "Done");
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

fn fail(e: vault_core::error::VaultError) -> ExitCode {
    eprintln!("{} {e}", style("error:").red().bold());
    ExitCode::FAILURE
}

fn print_summary(summary: &InstallSummary, headline: &str) {
    println!();
    for w in &summary.warnings {
        println!("{} {w}", style("⚠").yellow());
    }
    for b in &summary.blocked {
        println!("{} {b}", style("✗ BLOCKED").red().bold());
    }
    println!(
        "{} {headline}: {} resolved, {} downloaded, {} advisor{}, {} blocked",
        style("✓").green().bold(),
        summary.resolved,
        summary.downloaded,
        summary.advisories,
        if summary.advisories == 1 { "y" } else { "ies" },
        summary.blocked.len(),
    );
}
