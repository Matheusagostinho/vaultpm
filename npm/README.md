# vaultpm

Installer for **Vault** — a secure, pnpm-style Node.js package manager written in
Rust that blocks supply-chain attacks *before* install.

```bash
npm install -g vaultpm
```

This installs two commands:

- `vault` — the package manager
- `vt` — short alias

The native binary is delivered through a per-platform optional dependency
(`@vaultpm/<platform>-<arch>`). **Vault's own installation runs no postinstall
scripts** — fitting for a tool whose job is to protect you from them.

See the full documentation at <https://github.com/matheus/vaultpm>.
