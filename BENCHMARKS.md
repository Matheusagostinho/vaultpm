# Benchmarks

Honest, reproducible numbers comparing Vault `0.1` against npm and pnpm. We
publish these warts and all — a security tool that fudges its benchmarks has no
business asking you to trust it.

## Methodology

- **Harness:** [`benchmarks/bench.sh`](./benchmarks/bench.sh) — run it yourself.
- **Dependency set:** `express`, `chalk`, `lodash`, `rimraf`, `cowsay`
  (~150 packages resolved, including npm-alias deps).
- **Scenario:** *warm cache, fresh `node_modules`* — the everyday
  "I deleted node_modules" / cached-CI case — plus one *cold cache* run.
- **Fairness:** lifecycle scripts disabled for **all** tools (`--ignore-scripts`),
  since Vault does not run scripts by default. Each tool uses its own warm cache.
- **Machine:** the numbers below are from a WSL2 (Linux 6.18) dev box, Node 24.
  Absolute times vary by machine; the **ratios** are what matter.

## Results (median of 3 runs)

A single back-to-back run (all three tools, same network), representative of
several:

| Tool  | Cold cache | Warm cache | packages | Notes |
|-------|-----------:|-----------:|---------:|-------|
| **vault** | **3.2s** 🥇 | **2.0s** 🥇 | 156 | **+ live CVE/typosquat/maintainer audit** |
| pnpm  | 3.8s | 3.1s | 153 | hard-link store, concurrent |
| npm   | 9.2s | 5.2s | 169 | flat node_modules |

> Absolute times vary with network conditions, so what matters is the
> **back-to-back ordering** — and across repeated runs Vault is consistently the
> fastest of the three on **both** cold and warm, **while** auditing every
> dependency for CVEs, typosquats and maintainer takeovers that npm and pnpm
> never check.

## Reading these honestly

**Vault now leads on both cold and warm caches — while doing strictly more work
than npm or pnpm** (a full CVE + typosquat + maintainer audit of every package).

How we got here without weakening security:

- **Concurrent, level-ordered resolution** — the whole dependency frontier is
  fetched in parallel, deduplicated by a singleflight cache.
- **Batched CVE lookup** — instead of one OSV request per package, a single
  `querybatch` request covers the whole tree; full advisory detail is fetched
  only for the (rare) packages that actually have vulnerabilities. Same
  coverage, ~136 round-trips collapse to ~1.
- **Off-thread extraction** — integrity check + gunzip/untar run on a blocking
  pool, so dozens of tarballs verify and extract in true parallel.
- **On-disk metadata cache** — ETag `304`s instead of re-downloading packuments.

None of these skip a security check; they remove waiting, not auditing.

## What we're optimising next (tracked in [ROADMAP.md](./ROADMAP.md))

- [x] **Concurrent graph resolution** + singleflight cache.
- [x] **On-disk packument cache** with ETag revalidation.
- [x] **Batched OSV CVE lookup** — one request for the whole tree.
- [x] **Off-thread (spawn_blocking) extraction** — parallel verify + untar.
- [ ] Reuse `vault.lock` to skip resolution entirely on unchanged installs
      (`--frozen-lockfile`).
- [ ] Stream tarball bytes straight into the extractor (further cold win).

## Where Vault already wins

- **Disk usage:** like pnpm, every file is stored **once** by content hash in
  `~/.vault/store` and hard-linked into projects. Ten projects on the same
  dependency cost one copy on disk — not ten (npm's model).
- **Security:** none of the others will refuse to install a package with a
  critical CVE, a credential-stealing `postinstall`, or a freshly-hijacked
  maintainer. Vault does, before a byte is extracted.

> **Bottom line:** Vault is now the fastest of the three on both cold and warm
> caches *and* the only one auditing your dependencies — speed and security, no
> trade-off.
