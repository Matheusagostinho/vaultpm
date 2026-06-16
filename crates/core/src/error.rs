//! Error types for the Vault core.

use thiserror::Error;

/// Errors that can occur during any Vault operation.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON (de)serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("could not parse package.json: {0}")]
    PackageJson(String),

    #[error("could not resolve `{name}`: {reason}")]
    Resolution { name: String, reason: String },

    #[error("integrity check failed for {name}@{version}: expected {expected}, got {actual}")]
    Integrity {
        name: String,
        version: String,
        expected: String,
        actual: String,
    },

    #[error("security policy blocked {name}@{version}: {reason}")]
    SecurityBlock {
        name: String,
        version: String,
        reason: String,
    },

    #[error("config error: {0}")]
    Config(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, VaultError>;
