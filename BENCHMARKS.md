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

## Results (median of 3 warm runs)

| Tool  | Cold cache | Warm cache | packages | Notes |
|-------|-----------:|-----------:|---------:|-------|
| pnpm  | 2.5s | 2.1s | 153 | hard-link store, concurrent |
| npm   | 7.4s | 3.4s | 169 | flat node_modules |
| **vault** | **9.5s** | **6.8s** | 156 | **+ live CVE/typosquat/maintainer audit** |

## Reading these honestly

**Vault is currently the slowest — and that's expected for an alpha that is
doing strictly more work.** On every install Vault:

1. Queries **OSV.dev** for CVEs on each package (cached after first sight).
2. Hits the **npm downloads API** for popularity signals on direct deps.
3. Runs maintainer-takeover + typosquat + static-scan checks.

npm and pnpm do **none** of that. So part of the gap is the price of security —
and it is paid in network round-trips, not CPU.

The other part is a real, fixable engineering gap: **Vault resolves the
dependency graph sequentially today** (one registry request at a time), while
npm/pnpm fan out concurrently. This is the single biggest win available and is
the top item below.

## What we're optimising next (tracked in [ROADMAP.md](./ROADMAP.md))

- [ ] **Concurrent graph resolution** — fetch packuments in parallel (expected
      to close most of the gap on cold/warm alike).
- [ ] **On-disk metadata cache** — avoid re-fetching packuments every process.
- [ ] Reuse `vault.lock` to skip resolution entirely on unchanged installs
      (`--frozen-lockfile`).
- [ ] Stream-extract tarballs while downloading.

## Where Vault already wins

- **Disk usage:** like pnpm, every file is stored **once** by content hash in
  `~/.vault/store` and hard-linked into projects. Ten projects on the same
  dependency cost one copy on disk — not ten (npm's model).
- **Security:** none of the others will refuse to install a package with a
  critical CVE, a credential-stealing `postinstall`, or a freshly-hijacked
  maintainer. Vault does, before a byte is extracted.

> **Bottom line:** today you choose Vault for its security model, not its raw
> speed. Closing the performance gap is an engineering exercise (concurrency +
> caching), and it's the next thing we're building.
