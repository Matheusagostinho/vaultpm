# Vault Roadmap

The full plan from today's alpha to a **genuinely functional and distributable**
1.0 package manager. Checked boxes are implemented and tested **today**.

**Legend:** `[x]` done · `[~]` partial · `[ ]` todo

---

## Phase 0 — Foundations ✅ (done)

- [x] Cargo workspace (`crates/cli`, `crates/core`)
- [x] `#![forbid(unsafe_code)]`, clippy-clean, `cargo fmt`
- [x] Error model (`thiserror` in core, typed `VaultError`)
- [x] Async runtime (Tokio) + `reqwest` (rustls, no OpenSSL system dep)
- [x] Unit test suite (18 tests) running in CI
- [x] MIT license, `.gitignore`, `rust-toolchain.toml`

## Phase 1 — MVP install pipeline ✅ (done)

- [x] CLI with `clap`: `install`/`i`, `add`, `remove`/`rm`, `audit`, `run` (stub)
- [x] `vt` alias as a first-class second binary
- [x] Global flags: `--dir`, `--production`, `--force`
- [x] npm registry client with in-memory packument cache
- [x] Dependency resolution (pragmatic **flat** resolver — see Phase 4 for PubGrub)
- [x] Parallel tarball download (bounded concurrency)
- [x] **SHA-512 integrity verification (fail-closed)**
- [x] Content-addressable store at `~/.vault/store` (per-file dedup)
- [x] `node_modules` materialization via **hard links** (copy fallback)
- [x] `vault.lock` generation with per-package security verdict
- [x] `vault.toml` config parsing with secure defaults
- [x] Real end-to-end install verified against the live npm registry

## Phase 2 — Security layer (depth)

- [x] **OSV.dev CVE lookup** + policy gate (`abort_on_critical_cve`)
- [x] Static scan of `preinstall`/`install`/`postinstall` (pattern-based)
- [x] Audit runs on **metadata, before any download/extract**
- [x] Colored terminal security report
- [x] **Maintainer-takeover signal**: recency check (resolved version published
      within `warn_new_maintainer_days`) + maintainer count, on direct deps
- [x] **Low-popularity warning** via npm downloads API (`min_weekly_downloads`)
- [x] Offline integration tests covering the fixture scenarios
      (`clean`, `postinstall-network`, `postinstall-ssh`, `postinstall-env`)
- [x] **Obfuscation-resistant script scan**: whitespace-stripped matching +
      `eval`/`atob`/`Function`/`fromCharCode`/`process.binding` rules +
      `~/.npmrc` theft + hex/unicode-escape density heuristic
- [x] **Full maintainer-diff**: store the last-seen maintainer set and warn when
      new maintainers appear between installs
- [x] **Reputation on transitive deps** via `security.check_transitive`
- [x] **Persistent audit cache** (per `name@version` in the store, TTL from
      `audit.cache_ttl_hours`) — repeat installs reuse vetted verdicts
- [x] **Typosquatting heuristic** (Levenshtein vs a bundled popular-name list)
- [ ] `swc`-based **full AST** analysis (deeper hardening beyond the current
      token/normalization scan; resists data-flow obfuscation)
- [ ] npm Advisory API as a second CVE source *(note: OSV already aggregates the
      GitHub Advisory DB + npm advisories, so this is largely redundant today)*

## Phase 3 — Sandbox & provenance

- [ ] **Landlock sandbox** (Linux ≥ 5.13) for approved lifecycle scripts
- [ ] Permission policy from `vault.toml` (fs read/write/exec, net allowlist)
- [ ] Approved-script execution model with interactive allowlist prompt
- [ ] Graceful fallback (explicit warning) on kernels without Landlock
- [ ] **Sigstore provenance** verification of npm attestations
- [ ] `--strict` mode (require provenance; treat warnings as blocks)
- [ ] macOS sandbox via `sandbox-exec` profile (parity, best-effort)

## Phase 4 — Correctness & performance (to truly rival pnpm)

- [ ] **PubGrub SAT resolver** replacing the flat resolver (proper conflict handling)
- [ ] **pnpm-style isolated layout** (`node_modules/.vault` virtual store + symlinks)
- [ ] Peer-dependency resolution + warnings
- [ ] Optional / dev / bundled dependency semantics
- [ ] `.bin/` linking for package executables
- [ ] **Lockfile-driven installs** (respect existing `vault.lock`; `--frozen-lockfile`)
- [ ] Workspaces / monorepo support (`workspaces` field, filtering)
- [ ] Sandboxed execution of trusted lifecycle scripts (depends on Phase 3)
- [ ] Store garbage collection (`vault store prune`) + offline mode
- [ ] Download resume/retry, integrity-failure quarantine
- [ ] Benchmarks vs npm / pnpm / bun (cold + warm cache)

## Phase 5 — Distribution & platforms

- [x] npm package `vaultpm` via **optionalDependencies** (zero install scripts)
- [x] `curl | sh` installer (`install.sh`)
- [x] GitHub Actions **CI** (fmt + clippy + test on Linux/macOS/Windows)
- [x] GitHub Actions **Release** pipeline (build matrix → tarballs + npm publish)
- [x] `build-npm-packages.mjs` to assemble per-platform packages in CI
- [ ] Reserve npm org `@vaultpm` and publish the first `0.1.0` release
- [ ] Publish `vault-core` + `vault-cli` to **crates.io**
- [ ] **Windows support** 🪟
  - [ ] Verify build on `x86_64-pc-windows-msvc` in CI (matrix already present)
  - [ ] Windows path / reserved-filename handling in store + linker
  - [ ] No-Landlock fallback path (sandbox disabled with warning)
  - [ ] `.cmd` / `.ps1` bin shims; junctions instead of symlinks where needed
  - [ ] `aarch64-pc-windows-msvc` (ARM) target + `@vaultpm/win32-arm64`
  - [ ] `.zip` release asset wired into a `install.ps1` PowerShell installer
- [ ] Verify Linux `aarch64` cross-build end-to-end
- [ ] Homebrew tap (`brew install vault`)
- [ ] Shell completions (zsh/bash/fish) + man pages
- [ ] **Dogfood:** sign Vault's own releases with SLSA/Sigstore provenance

## Phase 6 — DX & community

- [ ] `vt why <pkg>` — explain why a package is in the tree
- [ ] `vt licenses` — license report
- [ ] `vt outdated` / `vt update`
- [ ] Progress bars (`indicatif`) for resolve/download/link
- [ ] `.npmrc` compatibility (registry mirrors, scoped registries, auth tokens)
- [ ] Private registry + authentication support
- [ ] Documentation site
- [ ] `CONTRIBUTING.md`, `SECURITY.md`, issue/PR templates
- [ ] Telemetry-free by design statement + threat model doc

---

## Definition of "really functional & distributable" (1.0 bar)

1. **Installs correctly:** PubGrub resolver + isolated layout + lockfile-driven,
   handles real-world graphs (Phase 4).
2. **Secure by default:** CVE gate, AST script analysis, maintainer-takeover
   detection, and a working Landlock sandbox (Phases 2–3).
3. **Cross-platform:** Linux (x64/arm64), macOS (x64/arm64), Windows (x64)
   binaries published and tested in CI (Phase 5).
4. **One-command install everywhere:** `npm i -g vaultpm`, `curl | sh`,
   `cargo install`, Homebrew (Phase 5).
5. **Trustworthy:** Vault's own releases carry provenance; threat model and
   security policy are public (Phases 5–6).

**Where we are now:** Phases 0–1 complete. **Phase 2 essentially complete** —
CVE gate, obfuscation-resistant static scan, maintainer-takeover signals
(recency + maintainer-diff), typosquat detection, low-popularity warnings and a
persistent audit cache are all live and tested (33 unit + 5 integration tests).
Distribution scaffolding (Phase 5) is in place and ready for the first publish.
Only deep `swc` AST analysis remains optional in Phase 2. **Next up: Phase 3
(Landlock sandbox) and the Phase 4 PubGrub resolver.**
