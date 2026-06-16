#!/usr/bin/env node
// Assemble the per-platform npm packages from compiled binaries.
//
// Expected input layout (produced by the release workflow):
//   artifacts/<rust-target-triple>/vault[.exe]
//   artifacts/<rust-target-triple>/vt[.exe]
//
// Produces:
//   npm/platforms/<os>-<cpu>/package.json   (name: @vaultpm/<os>-<cpu>)
//   npm/platforms/<os>-<cpu>/vault[.exe]
//   npm/platforms/<os>-<cpu>/vt[.exe]
//
// Usage: node npm/scripts/build-npm-packages.mjs <artifacts-dir>
import { cpSync, mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const npmRoot = join(here, "..");
const artifactsDir = process.argv[2] || "artifacts";

const TARGETS = [
  { triple: "x86_64-unknown-linux-gnu", os: "linux", cpu: "x64", exe: "" },
  { triple: "aarch64-unknown-linux-gnu", os: "linux", cpu: "arm64", exe: "" },
  { triple: "x86_64-apple-darwin", os: "darwin", cpu: "x64", exe: "" },
  { triple: "aarch64-apple-darwin", os: "darwin", cpu: "arm64", exe: "" },
  { triple: "x86_64-pc-windows-msvc", os: "win32", cpu: "x64", exe: ".exe" },
];

const { version } = JSON.parse(readFileSync(join(npmRoot, "package.json"), "utf8"));

let built = 0;
for (const t of TARGETS) {
  const src = join(artifactsDir, t.triple);
  if (!existsSync(join(src, `vault${t.exe}`))) {
    console.warn(`skip ${t.os}-${t.cpu}: missing ${join(src, `vault${t.exe}`)}`);
    continue;
  }

  const pkgName = `${t.os}-${t.cpu}`;
  const outDir = join(npmRoot, "platforms", pkgName);
  mkdirSync(outDir, { recursive: true });

  for (const bin of ["vault", "vt"]) {
    const file = `${bin}${t.exe}`;
    const dest = join(outDir, file);
    cpSync(join(src, file), dest);
    if (t.exe === "") chmodSync(dest, 0o755);
  }

  const pkg = {
    name: `@vaultpm/${pkgName}`,
    version,
    description: `Vault binary for ${t.os} ${t.cpu}.`,
    license: "MIT",
    repository: { type: "git", url: "git+https://github.com/matheus/vaultpm.git" },
    os: [t.os],
    cpu: [t.cpu],
    bin: {
      vault: `vault${t.exe}`,
      vt: `vt${t.exe}`,
    },
    files: [`vault${t.exe}`, `vt${t.exe}`],
  };
  writeFileSync(join(outDir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
  console.log(`built @vaultpm/${pkgName}@${version}`);
  built++;
}

if (built === 0) {
  console.error("no platform packages built — check the artifacts directory");
  process.exit(1);
}
console.log(`\n${built} platform package(s) ready under npm/platforms/`);
