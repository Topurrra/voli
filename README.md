<p align="center">
  <img src="assets/logo.png" width="180" alt="voli — the bear that delivers">
</p>

<h1 align="center">voli</h1>

<p align="center">⚡ A fast, no-admin package manager for Windows. One binary, clean uninstalls, zero scripts.</p>

## Install

One line in PowerShell (no admin):

```powershell
iwr -useb volibear.dev/install | iex
```

The installer downloads the latest release, verifies its SHA-256, and runs
`voli setup` (user-level PATH, no admin). It does nothing else — read it first
if you like: [`install.ps1`](install.ps1).

> **Status: early development.** The core works — `voli install ripgrep`
> downloads from the signed registry, installs, and runs — but nothing is
> released yet and everything may change. Don't depend on it before v0.1.

## Guarantees (never violated)

1. **Never requires admin.** Never touches HKLM or Program Files.
2. **Clean uninstall.** `voli uninstall x` leaves zero trace — directory, shims,
   env vars, and PATH entries are all removed.
3. **No scripts, ever.** Install is download → verify hash → extract → shim →
   (consented) env vars. A package cannot run code on your machine.
4. **Everything is pinned.** Every artifact is sha256-verified; the index is
   Ed25519-signed.

## Commands

```
voli install ripgrep fd fzf     # from the registry (935 packages and growing)
voli install ripgrep@15.2.0     # pin a version
voli uninstall ripgrep          # zero trace
voli update                     # refresh the signed index (~250 KB)
voli upgrade --all              # respects pins; running apps keep working
voli search regex               # full-text, offline
voli info ripgrep
voli pin ripgrep / unpin
voli cleanup                    # old versions + stale cache
voli setup                      # self-install + PATH (user-level)
voli doctor                     # health checks
```

## How it works

Portable archives only — no MSI/EXE installers, no vendor install scripts.
Apps live in versioned directories under your user profile; tiny shims on a
single user-PATH entry point at the current version through a junction, so
upgrades are an atomic flip and never break a running program. Every mutation
(files, shims, env vars) is recorded in a local ledger, and uninstall replays
it backwards — that's the zero-trace guarantee, by construction rather than
by promise.

The package index is a signed sqlite snapshot fetched over HTTP — updating it
is one small download, not a git clone. Registry:
[Topurrra/voli-registry](https://github.com/Topurrra/voli-registry).
