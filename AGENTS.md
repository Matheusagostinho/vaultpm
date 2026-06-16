# AGENTS.md — conventions for humans and AI agents working in this repo

## What this project is

Vault is a secure, pnpm-style Node.js package manager written in Rust. The
differentiator is an **active security gate that runs before any package is
extracted**. Read `README.md` for the product vision and `ROADMAP.md` for the
phased plan; never implement a later phase before the one it depends on.

## Golden rules

1. **Test-first.** Write the test, then the implementation. Every module ends
   with a `#[cfg(test)]` block. Run `cargo test --all` before committing.
2. **Security is fail-closed where it matters.** Integrity verification and the
   policy gate must *reject* on doubt. Advisory lookups (OSV) may fail-*open*
   (network error ⇒ warn, don't block) — these are different trust axes; keep
   them distinct.
3. **The audit runs on metadata, before download/extract.** Don't reorder the
   pipeline so that bytes hit disk before the gate.
4. **No `unsafe`.** `core` is `#![forbid(unsafe_code)]`. Sandbox code (Phase 3)
   that needs syscalls must isolate `unsafe` behind a reviewed module.
5. **Ask before assuming** on architectural decisions not covered by the docs.

## Code standards

- Errors: `thiserror` in `core`, `anyhow`/`ExitCode` at the CLI edge.
- Async: Tokio everywhere; bound concurrency (see `CONCURRENCY`).
- Logging: `tracing` (never `println!` for diagnostics; `println!` is reserved
  for user-facing CLI output).
- Lints: `cargo clippy --all-targets -- -D warnings` must pass.
- Format: `cargo fmt --all`.
- Public items get `///` docs.
- Commits: Conventional Commits (`feat:`, `fix:`, `security:`, `test:`, `docs:`).

## Repo map

- `crates/cli` — `clap` CLI, produces the `vault` and `vt` binaries.
- `crates/core` — the engine (resolver, registry, fetcher, store, linker,
  lockfile, audit). Start in `crates/core/src/lib.rs` (`install` is the spine).
- `npm/` — npm distribution (optionalDependencies; no install scripts).
- `install.sh` — `curl | sh` installer.
- `.github/workflows/` — CI and release pipelines.

## Local commands

```bash
cargo build                                   # debug build → target/debug/{vault,vt}
cargo test --all                              # all tests
cargo clippy --all-targets -- -D warnings     # lint gate
cargo fmt --all                               # format

# manual smoke test against the live registry:
mkdir /tmp/t && echo '{"name":"t","version":"1.0.0","dependencies":{"is-odd":"^3.0.1"}}' > /tmp/t/package.json
cargo run --bin vault -- install --dir /tmp/t
```

> Per-directory `CLAUDE.md` files hold local context for AI agents and are
> gitignored — do not rely on them being present for other contributors.
