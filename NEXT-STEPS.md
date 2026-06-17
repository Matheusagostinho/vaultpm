# Next Steps — Robustness, Effectiveness & Speed

A prioritized, honest engineering plan for taking Vault from a fast, secure
alpha to a production-grade package manager. Organized by the three goals; every
item is annotated with **impact**, **effort**, and a note confirming it keeps
the core guarantee intact (*audit & verify before anything is linked or run*).

Legend — Impact/Effort: 🔥 high · ◐ medium · · low. Status: ✅ done · 🔜 next · ⏳ later.

> See also: [ROADMAP.md](./ROADMAP.md) (phase tracker) and
> [SECURITY.md](./SECURITY.md) (threat model). This file is the "how we get
> better along three axes" view.

---

## ⚡ Speed

The engine is already concurrent + cached. Remaining wins target the cold path
and CI.

| Priority | Item | Impact | Effort | Notes |
|---|---|:--:|:--:|---|
| ✅ P0 | **`--frozen-lockfile` / lockfile-driven install** — a consistent `vault.lock` skips network resolution; `--frozen-lockfile` errors on drift and never rewrites the lock | 🔥 | ◐ | **Done.** Lockfile stores the graph + lifecycle scripts so audit still runs offline. |
| 🔜 P0 | **Abbreviated packuments** (`Accept: application/vnd.npm.install-v1+json`) for resolution; fetch the full document only for the few direct deps that need maintainer/recency data | 🔥 | ◐ | Much smaller metadata payloads → faster cold resolve + less bandwidth. |
| 🔜 P1 | **Metadata freshness window** — skip ETag revalidation when a cached packument is younger than N seconds (configurable; `--offline`/`--prefer-offline`) | ◐ | · | Cuts N revalidation round-trips on warm/repeat installs. Correctness preserved via the existing ETag path when stale. |
| ⏳ P1 | **Pipeline phases per package** — start fetching a package the moment *it* passes audit, instead of waiting for the whole tree to finish auditing | ◐ | ◐ | Overlaps audit and download. Keeps per-package "audit-before-fetch" ordering. |
| ⏳ P2 | **HTTP/2 connection reuse + tuned pool size**, and adaptive concurrency | · | · | Marginal; measure before/after. |
| ⏳ P2 | **Hard-link the whole package dir in one pass** / reflink (`copy_file_range`) where supported | · | ◐ | Faster linking on huge trees. |

## 🛡️ Robustness

Make Vault behave correctly under failure, concurrency and weird environments.

| Priority | Item | Impact | Effort | Notes |
|---|---|:--:|:--:|---|
| ✅ P0 | **Download retries with exponential backoff** for connection/timeout errors, `429` and `5xx` | 🔥 | ◐ | **Done** for packument + tarball requests. |
| 🔜 P0 | **Store lock file** — guard `~/.vault/store` against two concurrent `vault` processes corrupting it | 🔥 | ◐ | Advisory lock + atomic writes (CAS already uses unique-temp + rename). |
| 🔜 P1 | **`vault store verify` / self-heal** — detect and re-fetch CAS objects whose content no longer matches their hash | ◐ | ◐ | Recovers from disk corruption; deepens trust in the store. |
| 🔜 P1 | **Windows parity** — junctions instead of symlinks, `.cmd`/`.ps1` bin shims, reserved-name + long-path handling, `install.ps1` | 🔥 | 🔥 | Binaries already build on Windows; the linker/sandbox paths need work. |
| ⏳ P1 | **Fuzz the tarball extractor + packument parser** (`cargo-fuzz`) | ◐ | ◐ | They parse untrusted input — the highest-value fuzz targets. |
| ⏳ P1 | **`cargo-deny` + `cargo-audit` in CI** for Vault's *own* Rust dependencies | ◐ | · | Dogfood: a supply-chain tool must police its own supply chain. |
| ⏳ P2 | **Property tests for the resolver** (e.g. proptest) + a corpus of real lockfiles | ◐ | ◐ | Catches resolution regressions. |
| ⏳ P2 | **Graceful disk-full / permission errors** with actionable messages, and a `--offline` mode that never touches the network | · | · | DX + air-gapped support. |

## 🎯 Effectiveness (security & correctness)

Close the remaining gaps in *what* Vault catches and *how correctly* it installs.

| Priority | Item | Impact | Effort | Notes |
|---|---|:--:|:--:|---|
| 🔜 P0 | **Peer-dependency resolution + warnings** | 🔥 | ◐ | Real-world trees rely on peers; today they're ignored. |
| 🔜 P0 | **Sigstore provenance verification** + `require_provenance` / `--strict` | 🔥 | ◐ | Closes the "compromised registry/CDN" gap — verify the package was built from the claimed source, not just that bytes match a hash the registry served. |
| 🔜 P1 | **`swc` AST static analysis** of lifecycle scripts | 🔥 | 🔥 | Resists data-flow obfuscation that the current normalized-pattern scan can't see. Keep the `Finding`/`Severity` API stable. |
| 🔜 P1 | **Landlock network restriction (ABI v4, kernel ≥ 6.7)** for sandboxed scripts | ◐ | ◐ | Deny outbound sockets, not just filesystem — stops exfiltration even by an allowed script. |
| ⏳ P1 | **`--allow-scripts` to run audited lifecycle scripts inside the sandbox during install**, with an interactive allowlist | ◐ | ◐ | Some packages genuinely need build steps; run them *safely* instead of refusing. |
| ⏳ P1 | **Lockfile integrity** — sign `vault.lock` and verify it; `--frozen-lockfile` rejects drift | ◐ | ◐ | Prevents tampered lockfiles in CI. |
| ⏳ P2 | **Full PubGrub backtracking** to minimise duplicate versions when ranges overlap | ◐ | 🔥 | Optimisation; npm's multi-version model makes this lower-priority than for Cargo. |
| ⏳ P2 | **Second advisory source + offline advisory mirror** (GitHub Advisory DB direct) | · | ◐ | Redundancy + air-gapped CVE checks. |
| ⏳ P2 | **Smarter typosquat detection** — popularity-weighted, keyboard-distance, homoglyph-aware | · | ◐ | Fewer false positives, catches more real squats. |
| ⏳ P2 | **Resource limits on sandboxed scripts** (CPU/mem/time via cgroups) | · | ◐ | Stops a script from hanging or fork-bombing an install. |

---

## Suggested order of attack

1. **`--frozen-lockfile` + abbreviated packuments** — the two biggest, cleanest
   speed wins (especially for CI).
2. **Download retries + store lock** — the robustness floor; flaky networks and
   concurrent processes must not corrupt or fail installs.
3. **Peer deps + Sigstore provenance** — the two most-requested correctness/
   security features for real adoption.
4. **Windows parity** — unlocks a large slice of the community.
5. Then the deeper hardening (swc AST, Landlock network, fuzzing) and
   `crates.io` / Homebrew distribution.

Every item above is additive to the security model — none trade away the
guarantee that a package is audited and its bytes verified **before** anything is
linked into `node_modules` or executed.
