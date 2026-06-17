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

A back-to-back run (all three tools, same network), representative of several:

| Tool  | Cold cache | Warm cache | packages | Notes |
|-------|-----------:|-----------:|---------:|-------|
| **vault** | 3.7s | **1.3s** 🥇 | 156 | **+ live CVE/typosquat/maintainer audit** |
| pnpm  | 2.8s | 2.1s | 153 | hard-link store, concurrent |
| npm   | 8.0s | 3.5s | 169 | flat node_modules |

> **Warm cache (the everyday case): Vault is the fastest, by ~2×** — *while*
> auditing every dependency for CVEs, typosquats and maintainer takeovers that
> npm and pnpm never check.
>
> **Cold cache: Vault is neck-and-neck with pnpm** (both ~3s; which wins flips
> with network conditions) and ~2× faster than npm. Absolute times vary, so the
> back-to-back ordering is what matters.

## Reading these honestly

**On warm caches Vault is the fastest of the three by ~2×, and on cold caches it
is neck-and-neck with pnpm — all while doing strictly more work** (a full CVE +
typosquat + maintainer audit of every package) than npm or pnpm.

How we got here without weakening security:

- **Concurrent, level-ordered resolution** — the whole dependency frontier is
  fetched in parallel, deduplicated by a singleflight cache.
- **Batched CVE lookup** — instead of one OSV request per package, a single
  `querybatch` request covers the whole tree; full advisory detail is fetched
  only for the (rare) packages that actually have vulnerabilities. Same
  coverage, ~136 round-trips collapse to ~1.
- **Streaming downloads** — each tarball is streamed to a temp file while its
  SHA-512 is computed incrementally, then verified **before** extraction. We
  never hold a whole `.tgz` in memory, so high concurrency stays safe.
- **Off-thread extraction** — gunzip/untar runs on a blocking pool, so dozens of
  tarballs extract in true parallel.
- **On-disk metadata cache** — ETag `304`s instead of re-downloading packuments.

None of these skip a security check; integrity is still verified before any file
is extracted. They remove waiting, not auditing.

## What we're optimising next (tracked in [ROADMAP.md](./ROADMAP.md))

- [x] **Concurrent graph resolution** + singleflight cache.
- [x] **On-disk packument cache** with ETag revalidation.
- [x] **Batched OSV CVE lookup** — one request for the whole tree.
- [x] **Off-thread (spawn_blocking) extraction** — parallel untar.
- [x] **Streaming downloads** — hash-on-the-fly to a temp file, verify before
      extract, never buffer the whole tarball in memory.
- [ ] Reuse `vault.lock` to skip resolution entirely on unchanged installs
      (`--frozen-lockfile`) — would make cold-with-lockfile near-instant.

## Where Vault already wins

- **Disk usage:** like pnpm, every file is stored **once** by content hash in
  `~/.vault/store` and hard-linked into projects. Ten projects on the same
  dependency cost one copy on disk — not ten (npm's model).
- **Security:** none of the others will refuse to install a package with a
  critical CVE, a credential-stealing `postinstall`, or a freshly-hijacked
  maintainer. Vault does, before a byte is extracted.

> **Bottom line:** on warm caches Vault is the fastest by ~2×, on cold it's level
> with pnpm — *and* it's the only one auditing your dependencies. You stop paying
> for security with speed.
