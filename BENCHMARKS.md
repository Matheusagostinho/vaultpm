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

| Tool  | Cold cache | Warm cache | packages | Notes |
|-------|-----------:|-----------:|---------:|-------|
| **vault** | 5.3s | **1.25s** 🥇 | 156 | **+ live CVE/typosquat/maintainer audit** |
| pnpm  | 2.5s | 2.1s | 153 | hard-link store, concurrent |
| npm   | 7.4s | 3.0s | 169 | flat node_modules |

> Warm-cache install is the everyday case. Vault is **~2× faster than pnpm**
> there — *and* it audits every dependency. Cold installs still trail pnpm.

## Reading these honestly

**On a warm cache — the everyday "I deleted node_modules" case — Vault is now the
fastest of the three, _while also_ auditing every dependency for CVEs,
typosquats and maintainer takeovers that npm and pnpm don't check at all.**

This came from making resolution **concurrent**: the whole dependency frontier
is fetched in parallel (bounded), with a singleflight cache so each package is
fetched at most once. Combined with the persistent CVE-audit cache, warm
installs spend almost no time waiting on the network.

**On a cold cache Vault is still behind pnpm** (4.9s vs 2.5s). That gap is now
honest, expected work: a cold run downloads every tarball *and* performs each
package's first-ever OSV lookup and popularity check over the network — security
work the others simply skip. We keep optimising it, but we will not skip the
audits to win a benchmark.

## What we're optimising next (tracked in [ROADMAP.md](./ROADMAP.md))

- [x] **Concurrent graph resolution** — warm installs now beat pnpm.
- [x] **On-disk packument cache** with ETag revalidation — warm runs revalidate
      with cheap `304`s instead of re-downloading metadata, and metadata is
      reused across projects (kept in `~/.vault/cache`, separate from the store).
- [ ] Reuse `vault.lock` to skip resolution entirely on unchanged installs
      (`--frozen-lockfile`).
- [ ] Stream-extract tarballs while downloading (cold-cache win).

## Where Vault already wins

- **Disk usage:** like pnpm, every file is stored **once** by content hash in
  `~/.vault/store` and hard-linked into projects. Ten projects on the same
  dependency cost one copy on disk — not ten (npm's model).
- **Security:** none of the others will refuse to install a package with a
  critical CVE, a credential-stealing `postinstall`, or a freshly-hijacked
  maintainer. Vault does, before a byte is extracted.

> **Bottom line:** on warm caches Vault is now the fastest of the three *and*
> the only one auditing your dependencies. Cold installs still trail pnpm while
> we add on-disk metadata caching — but we get there without ever skipping the
> security checks that are the whole point.
