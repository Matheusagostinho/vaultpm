# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
**[private security advisories](https://github.com/Matheusagostinho/vaultpm/security/advisories/new)**
(Security → Report a vulnerability). We aim to acknowledge within 72 hours.

When relevant, include: affected version, reproduction steps, and whether the
issue is in Vault itself or in its handling of a malicious package.

## Threat model

Vault is a **defensive** tool. Its job is to stop a developer from installing or
executing a malicious npm package. It defends against:

| Threat | Defense |
|---|---|
| Known CVEs in dependencies | OSV.dev gate before download (`abort_on_critical_cve`) |
| Malicious `postinstall` (exfiltration, eval, credential theft) | Obfuscation-resistant static scan; scripts not run unless explicitly allowed |
| Credential/secret theft by scripts | Landlock sandbox denies `~/.ssh`, `~/.aws`, `~/.npmrc`, the rest of `$HOME` |
| Maintainer account takeover | Recency + maintainer-set-change warnings |
| Typosquatting | Edit-distance check vs popular names |
| Tampered tarballs | Fail-closed SHA-512 integrity verification |

### What Vault does **not** (yet) protect against

- Malicious code in a package's **runtime** path (only install-time scripts are
  sandboxed today). Sandboxing app execution is out of scope.
- Compromise of the npm registry's TLS/CDN itself (we trust the integrity hashes
  the registry serves; Sigstore provenance is on the roadmap to close this).
- Sophisticated payloads that defeat heuristic static analysis (full AST/data-flow
  analysis is roadmapped).
- Network exfiltration by scripts on kernels without Landlock ABI v4 (FS-only
  sandbox on older kernels).

## Trust & failure model

- **Integrity and policy gates fail *closed*** — on doubt, the install is
  rejected. A package with no integrity hash is refused.
- **Advisory lookups fail *open*** — if OSV.dev is unreachable, the install
  continues with a warning rather than blocking on a network outage. These are
  deliberately different trust axes.
- Vault's **own** distribution runs **no install scripts** (npm optional-deps
  pattern), minimising its own supply-chain surface.

## Hardening roadmap (making Vault more robust & more secure)

Concrete next steps, in rough priority order:

1. **Sigstore provenance verification** + `--strict` requiring it — closes the
   "registry/CDN compromise" gap.
2. **Full `swc` AST analysis** of scripts — resists obfuscation that beats the
   current normalized-pattern scan.
3. **Landlock network restriction** (ABI v4) for sandboxed scripts — deny
   outbound sockets, not just filesystem.
4. **Lockfile integrity** — sign/verify `vault.lock`; `--frozen-lockfile` to
   forbid drift in CI.
5. **Reproducible, provenance-signed releases** (SLSA) for Vault's own binaries.
6. **Second advisory source** (GitHub Advisory API direct) and offline advisory
   DB mirror for air-gapped use.
7. **Resource limits** on sandboxed scripts (CPU/memory/time) via cgroups.
8. **`cargo-audit` / `cargo-deny`** in CI for Vault's own Rust dependencies.
9. **Fuzzing** the tarball extractor and packument parser (untrusted input).

## Supported versions

Vault is pre-1.0; only the latest `0.x` release receives security fixes.
