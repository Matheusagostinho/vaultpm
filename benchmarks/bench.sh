#!/usr/bin/env bash
# Benchmark Vault against npm and pnpm on the same dependency set.
#
# Measures the common developer scenario: a **warm cache, fresh node_modules**
# install (the "I just deleted node_modules" / fresh CI-with-cache case), plus a
# single **cold cache** run. Lifecycle scripts are disabled for every tool so we
# compare the same work (Vault does not run scripts by default).
#
# Usage: benchmarks/bench.sh [runs]   (default 3 timed runs per tool)
set -uo pipefail

RUNS="${1:-3}"
VAULT_BIN="${VAULT_BIN:-$(pwd)/target/release/vault}"
WORK="$HOME/.cache/vault-bench"      # under $HOME so Vault's hard links stay on one fs
PROJECT='{
  "name": "bench",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.19.2",
    "chalk": "^4.1.2",
    "lodash": "^4.17.21",
    "rimraf": "^5.0.5",
    "cowsay": "^1.6.0"
  }
}'

command -v "$VAULT_BIN" >/dev/null || { echo "build first: cargo build --release"; exit 1; }
mkdir -p "$WORK"; cd "$WORK"
echo "$PROJECT" > package.json

median() { sort -n | awk '{a[NR]=$1} END{print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2}'; }
clean()  { rm -rf node_modules package-lock.json pnpm-lock.yaml vault.lock; }

time_cmd() { local s e; s=$(date +%s.%N); "$@" >/dev/null 2>&1 || true; e=$(date +%s.%N); awk "BEGIN{printf \"%.2f\", $e-$s}"; }

declare -A WARM COLD COUNT

bench_tool() {
  local name="$1"; shift
  local install_cmd=("$@")

  # Cold: clear the tool's cache, then install.
  case "$name" in
    npm)   npm cache clean --force >/dev/null 2>&1 || true ;;
    pnpm)  pnpm store prune >/dev/null 2>&1 || true ;;
    vault) rm -rf "$HOME/.vault/store" "$HOME/.vault/cache" ;;
  esac
  clean
  COLD[$name]=$(time_cmd "${install_cmd[@]}")

  # Warm: cache now populated; measure fresh-node_modules installs.
  local times=()
  for _ in $(seq "$RUNS"); do
    clean
    times+=("$(time_cmd "${install_cmd[@]}")")
  done
  WARM[$name]=$(printf '%s\n' "${times[@]}" | median)
  COUNT[$name]=$(find node_modules -name package.json 2>/dev/null | wc -l | tr -d ' ')
  echo "  [$name] cold=${COLD[$name]}s warm=${WARM[$name]}s pkgs=${COUNT[$name]}"
}

echo "Benchmarking (runs=$RUNS) in $WORK …"
bench_tool npm   npm   install --ignore-scripts --no-audit --no-fund
bench_tool pnpm  pnpm  install --ignore-scripts --config.confirmModulesPurge=false
bench_tool vault "$VAULT_BIN" install

printf '\n| Tool  | Cold cache | Warm cache (median of %s) | packages |\n' "$RUNS"
printf -- '|-------|-----------|---------------------------|----------|\n'
for t in npm pnpm vault; do
  printf '| %-5s | %6.2fs   | %6.2fs                   | %s |\n' \
    "$t" "${COLD[$t]}" "${WARM[$t]}" "${COUNT[$t]}"
done
