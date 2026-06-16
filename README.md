<div align="center">

# 🔒 Vault

**A secure, pnpm-style package manager for Node.js — written in Rust.**

Vault installs your dependencies as fast as pnpm (global content-addressable
store + hard links) but **actively blocks supply-chain attacks before a single
file is extracted.**

[![CI](https://github.com/matheus/vaultpm/actions/workflows/ci.yml/badge.svg)](https://github.com/matheus/vaultpm/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Made with Rust](https://img.shields.io/badge/made%20with-Rust-orange.svg)](https://www.rust-lang.org)

</div>

> [!WARNING]
> **Status: alpha (v0.1).** The core install pipeline and the OSV CVE gate are
> functional today. The sandbox, maintainer-takeover detection, and full
> PubGrub resolver are on the [roadmap](./ROADMAP.md). Don't use it as your only
> package manager in production yet — but please try it and file issues.

---

## Why Vault?

In 2025–2026 the npm ecosystem was hit by self-replicating worms
(**Shai-Hulud**, **Glassworm**), credential-stealing typosquats, and maintainer
takeovers. The painful truth: **no mainstream package manager inspects a package
*before* it runs on your machine.** `npm audit` only checks known CVEs *after*
install, and lifecycle scripts execute with full access to your home directory,
SSH keys, and cloud credentials.

Vault flips the model: **audit first, install second.**

```
            npm / yarn          pnpm 10 / bun        Vault
            ──────────          ─────────────        ─────
pre-install      ✗                   ✗                 ✅  CVE + static + maintainer
scan
lifecycle    runs by default   disabled by default   sandboxed (Landlock)
scripts
disk model     copies          hard links            hard links (CAS)
where it       reactive         passive               active, before extract
runs           (audit after)    (just disable)
```

## How it compares to other security tools

| | Vault | Socket.dev / Aikido | snpm / rnpm | pnpm 10 / bun |
|---|---|---|---|---|
| Is itself a package manager | ✅ | ❌ (wraps npm) | ✅ | ✅ |
| Pre-install CVE scan | ✅ | ✅ | partial | ❌ |
| Static analysis of install scripts | ✅ | ✅ | ❌ | ❌ |
| Kernel sandbox for scripts | ✅ *(roadmap)* | ❌ | ❌ | ❌ |
| Open source & self-contained | ✅ | ❌ (SaaS) | ✅ | ✅ |
| Native single binary | ✅ | ❌ | ✅ | bun ✅ |

Socket and friends pioneered pre-install behavioral analysis — but they're
commercial SaaS that *wrap* npm. snpm/rnpm are fast Rust package managers but
ship only passive defenses.

> **Vault é o primeiro package manager open-source nativo onde a análise de
> segurança (CVE + scan estático + sandbox Landlock) está embutida no
> instalador, offline-capable, num único binário.**
>
> *(Vault is the first open-source native package manager where the security
> analysis — CVE + static scan + Landlock sandbox — is built into the installer
> itself, offline-capable, in a single binary.)*

---

## Install

### npm (any OS)

```bash
npm install -g vaultpm
```

Installs the `vault` and `vt` commands. The native binary ships as a
per-platform optional dependency, so **installing Vault runs zero postinstall
scripts** — exactly what you'd want from a supply-chain security tool.

### curl (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/matheus/vaultpm/main/install.sh | sh
```

### Cargo

```bash
cargo install vault-cli
```

### Build from source

```bash
git clone https://github.com/matheus/vaultpm
cd vaultpm
cargo build --release
# binaries at target/release/vault and target/release/vt
```

---

## Usage

```bash
vault install            # install everything in package.json
vault install lodash     # add and install a package
vault add react react-dom
vault remove lodash
vault audit              # scan the dependency graph, install nothing

# `vt` is a shorter alias for everything:
vt i
vt add zod
vt audit
```

Every install produces a `vault.lock` recording the resolved version,
integrity hash, and the security verdict for each package.

### Example: Vault stops a vulnerable package

```console
$ vt audit
✗ BLOCKED lodash@4.17.4: critical/high CVE(s): GHSA-35jh-r3h4-6jhm,
  GHSA-4xc9-xhrj-v574, GHSA-jf85-cpcp-j695, GHSA-p6mc-m468-83gw, GHSA-r5fr-rjxr-66jc
✓ Audit complete: 1 resolved, 0 downloaded, 0 advisories, 1 blocked
```

---

## How it works

```
package.json
     │
     ▼
 resolve graph ──▶ AUDIT (metadata only, before any download)
                     ├── OSV.dev CVE lookup
                     ├── static scan of preinstall/postinstall scripts
                     └── policy gate ── BLOCK ──▶ abort (no files touched)
                     │
                     ▼ (clean)
              download tarball
                     │
                     ▼
           verify SHA-512 (fail-closed)
                     │
                     ▼
       extract into ~/.vault/store  (content-addressable, deduped)
                     │
                     ▼
        hard-link into ./node_modules
                     │
                     ▼
              write vault.lock
```

The global store at `~/.vault/store` keeps each file exactly once by content
hash. Ten projects using `lodash@4.17.21` share **one** copy on disk.

Configuration lives in [`vault.toml`](./vault.toml) (all fields optional, secure
defaults).

---

## Architecture

```
crates/
├── cli/     # clap CLI → the `vault` and `vt` binaries
└── core/    # the engine:
    ├── resolver   dependency resolution
    ├── registry   npm registry client
    ├── fetcher    download + verify + extract
    ├── store      content-addressable store (~/.vault/store)
    ├── linker     node_modules materialization
    ├── lockfile   vault.lock
    └── audit/     the security layer
        ├── integrity    SHA-512 verification
        ├── osv          CVE lookup (OSV.dev)
        └── static_scan  lifecycle script analysis
```

See [ROADMAP.md](./ROADMAP.md) for the full plan to a 1.0 release.

---

## Contributing

Contributions are very welcome. Vault is built test-first:

```bash
cargo test --all          # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

Please read [AGENTS.md](./AGENTS.md) for the repo conventions (also used by AI
coding agents). Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `security:`, `test:`).

## License

[MIT](./LICENSE) © 2026 Matheus Agostinho and Vault contributors.
