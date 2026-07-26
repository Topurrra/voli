<p align="center">
  <img src="assets/logo-forest-git.png" width="420" alt="voli — the bear that delivers">
</p>

<h1 align="center">Voli · The Bear That Delivers</h1>

<p align="center">⚡ A fast, no-admin package manager for Windows. One binary, clean uninstalls, zero scripts.</p>

<p align="center">
  <img src="assets/Voli.gif" width="400" alt="Voli the bear in the forest">
</p>

## Install

One line in PowerShell (no admin):

```powershell
iwr -useb volibear.dev/install | iex
```

The installer downloads the latest release, verifies its SHA-256, and runs
`voli setup` (user-level PATH, no admin). It does nothing else - read it first
if you like: [`install.ps1`](install.ps1).

> **Status: v0.5.7, still pre-1.0.** The core workflow is released and working,
> but commands and the manifest schema may still change before v1.

## Guarantees (never violated)

1. **Never requires admin.** Never touches HKLM or Program Files.
2. **Clean uninstall.** `voli delete x` leaves zero trace - directory, shims,
   env vars, and PATH entries are all removed.
3. **No scripts, ever.** Install is download → verify hash → extract → shim →
   (consented) env vars. A package cannot run code on your machine.
4. **Everything is pinned.** Every artifact is sha256-verified; the index is
   Ed25519-signed.

## Commands

Global options:

- `--yes` accepts confirmations and never waits for input.
- `--json` emits machine-readable output where supported.
- `-h`, `--help` shows help. `-V`, `--version` shows the installed version.

| Command | Purpose |
|---|---|
| `voli install <pkg>[@version] ...` | Install one or more packages from the signed registry. |
| `voli delete <pkg> ...` | Delete packages by replaying their ledger. Persist data is kept by default. |
| `voli update` | Refresh the local signed package index. |
| `voli upgrade [pkg ...]` | Upgrade named packages. Use `--all` to upgrade everything except pinned packages. |
| `voli list` | List installed packages and versions. |
| `voli search <query>` | Search the local index by package name, description, or binary. |
| `voli info <pkg>` | Show package metadata and available binaries. |
| `voli pin <pkg>` | Exclude a package from `upgrade --all`. |
| `voli unpin <pkg>` | Remove a package pin. |
| `voli env <pkg>` | Show environment variables recorded for a package. |
| `voli cleanup` | Remove non-current versions and stale cached downloads. |
| `voli setup` | Install Voli into its user-level root and add its shims to PATH. |
| `voli config get <key>` | Read `root` or `index_url`. |
| `voli config set <key> <value>` | Set `root` or `index_url`. |
| `voli doctor` | Check PATH, environment drift, shims, state, and installation health. |
| `voli which <bin>` | Resolve a shim to its real executable. |
| `voli self-update` | Download and install the latest Voli release. |
| `voli self-delete` | Delete Voli, installed packages, cache, state, shims, and PATH entries. |
| `voli help [command]` | Show general help or help for one command. |

Common examples:

```powershell
voli update
voli search regex
voli install ripgrep fd fzf
voli install ripgrep@15.2.0
voli install .\local-package.toml --archive .\local-package.zip
voli install googlechrome --no-env

voli list
voli info ripgrep
voli env googlechrome
voli which chrome

voli pin ripgrep
voli unpin ripgrep
voli upgrade ripgrep
voli upgrade --all

voli delete ripgrep
voli delete ripgrep --purge

voli cleanup --dry-run
voli cleanup --cache-days 7
voli doctor

voli config get root
voli config set root D:\Apps\voli
voli config get index_url

voli setup
voli self-update
voli self-delete
```

`voli delete <pkg> --purge` also removes the package's persisted user data.
Without `--purge`, persist directories survive so a later reinstall can reuse
them. The older `uninstall` and `self-uninstall` spellings remain supported as
hidden compatibility aliases.

## How it works

Portable archives are extracted directly. Explicit `installer-archive` sources
may use a locally installed 7-Zip to extract an EXE/MSI as a container; the
installer is never executed. Vendor scripts and installers that must run remain
unsupported. Apps live in versioned directories under your user profile; tiny
shims on a single user-PATH entry point at the current version through a
junction, so upgrades are an atomic flip and never break a running program.
Every mutation (files, shims, env vars) is recorded in a local ledger, and
`delete` replays it backwards - that's the zero-trace guarantee, by
construction rather than by promise.

The package index is a signed sqlite snapshot fetched over HTTP - updating it
is one small download, not a git clone. Registry:
[Voli Registry](https://github.com/Topurrra/voli-registry).

## License

[MIT](/license/LICENSE-MIT) | [Apache-2.0](/license/LICENSE-APACHE)
