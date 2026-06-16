//! The `vt` binary — short alias for `vault`, identical behaviour.

use std::process::ExitCode;

fn main() -> ExitCode {
    vault_cli::run()
}
