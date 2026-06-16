// Shared launcher for the `vault` / `vt` commands. The actual native executable
// is shipped as a per-platform optional dependency (@vaultpm/<platform>-<arch>)
// so that installing Vault runs no postinstall scripts at all.
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";

export function run(binName) {
  const require = createRequire(import.meta.url);
  const { platform, arch } = process;
  const ext = platform === "win32" ? ".exe" : "";
  const pkg = `@vaultpm/${platform}-${arch}`;

  let binary;
  try {
    binary = require.resolve(`${pkg}/${binName}${ext}`);
  } catch {
    console.error(
      `vaultpm: no prebuilt binary available for ${platform}-${arch}.\n` +
        `Supported: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64.\n` +
        `Build from source instead: https://github.com/matheus/vaultpm#build-from-source`,
    );
    process.exit(1);
  }

  const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
  if (result.error) {
    console.error(`vaultpm: failed to launch ${binName}: ${result.error.message}`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}
