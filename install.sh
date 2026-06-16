#!/bin/sh
# Vault installer — downloads the prebuilt `vault` + `vt` binaries for your
# platform from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/matheus/vaultpm/main/install.sh | sh
#
# Environment overrides:
#   VAULT_VERSION   release tag to install (default: latest)
#   VAULT_BIN_DIR   install location (default: $HOME/.vault/bin)
set -eu

REPO="matheus/vaultpm"
BIN_DIR="${VAULT_BIN_DIR:-$HOME/.vault/bin}"
VERSION="${VAULT_VERSION:-latest}"

err() { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '\033[36m::\033[0m %s\n' "$1"; }

# --- detect platform -------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)  target_os="unknown-linux-gnu" ;;
  Darwin) target_os="apple-darwin" ;;
  *) err "unsupported OS '$os'. On Windows use: npm install -g vaultpm" ;;
esac

case "$arch" in
  x86_64|amd64) target_arch="x86_64" ;;
  arm64|aarch64) target_arch="aarch64" ;;
  *) err "unsupported architecture '$arch'" ;;
esac

target="${target_arch}-${target_os}"

# --- resolve version -------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  info "resolving latest release…"
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -n1 | cut -d'"' -f4)"
  [ -n "$VERSION" ] || err "could not determine latest release (set VAULT_VERSION)"
fi

asset="vault-${VERSION}-${target}.tar.gz"
url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"

# --- download + extract ----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "downloading ${asset}…"
curl -fSL --progress-bar "$url" -o "$tmp/vault.tar.gz" \
  || err "download failed: $url"

info "extracting…"
tar -xzf "$tmp/vault.tar.gz" -C "$tmp"

mkdir -p "$BIN_DIR"
install -m 0755 "$tmp/vault" "$BIN_DIR/vault"
# `vt` is the same binary; prefer a symlink, fall back to a copy.
ln -sf "$BIN_DIR/vault" "$BIN_DIR/vt" 2>/dev/null \
  || install -m 0755 "$tmp/vault" "$BIN_DIR/vt"

info "installed vault ${VERSION} to ${BIN_DIR}"

# --- PATH hint -------------------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    printf '\n\033[33mAdd Vault to your PATH:\033[0m\n'
    printf '  export PATH="%s:$PATH"\n\n' "$BIN_DIR"
    ;;
esac

"$BIN_DIR/vault" --version || true
info "done — run 'vault install' in any Node.js project."
