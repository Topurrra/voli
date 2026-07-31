# Changelog

Notable changes per release. Versions are pre-1.0: commands and the manifest
schema may still change.

## v0.10.1

### Added

- **`voli-index-tool fmt <dir>`** rewrites manifests into canonical form
  (`--write`), or lists what would change and exits non-zero without it - the
  shape a CI check wants. A manifest generator can now emit whatever valid TOML
  is convenient and pipe it through this, instead of reimplementing the
  canonical shape and drifting from it. That is what the registry's Python skill
  importer was doing, making it a fourth emitter that agreed with the others
  only by coincidence.

## v0.10.0

### Added

- **`voli web <bang> <query>`** - open a search shortcut in your browser. Voli
  builds the URL and fetches nothing, so there is no API key, no quota and
  nothing to bot-block. Shortcuts cover search engines, reference, code and
  packages, developer reference, and community. The query is percent-encoded to
  the unreserved characters and handed to `ShellExecuteW` as a single argument,
  never through a shell.
- **`voli fetch <url>`** - retrieve a page as readable text with the provenance
  to prove what was read: final URL after redirects, timestamp, sha256 of
  exactly the bytes received, and byte length. HTTPS by default; `file:`,
  `data:` and `javascript:` are refused. Size, redirect count and total time are
  all capped, and the size cap is enforced while reading rather than audited
  after.
- **`voli fetch --format md`** - keeps the structure that flattened prose throws
  away: headings, nested lists, fenced code blocks, blockquotes, inline code,
  bold, italic, strikethrough, task lists with their checked state, horizontal
  rules, hard line breaks, images, and link targets resolved against the page's
  final URL. Tables become real pipe tables when every row agrees on the column
  count, and one cell per line when they do not. `--format json`/`--json` and
  `--format text` (the default, unchanged) round out the shapes.
- **Per-project agent memory.** `voli memory init --project` creates a store
  scoped to one codebase, and every `voli memory` command run inside that tree
  finds it automatically - nearest `.voli\memory` wins, so nested repositories
  each keep their own. `--global` reaches past it.
- **`voli memory prompt`** now writes the setup prompt to a file so you can copy
  it out of an editor rather than the terminal. `--print` sends it to stdout
  instead, `--out <path>` chooses the file, and `--per-project` writes the
  project-scoped variant.
- **Package aliases.** A renamed package keeps answering to its old name, so a
  rename no longer strands the people who installed it. `voli install python`
  installs `python-embed` and says so; an existing install is reported by
  `voli upgrade` and `voli doctor` rather than silently skipped, and is never
  migrated automatically, because the new name is a different package with its
  own shims. Aliases resolve in exactly one hop, a live package always beats an
  alias on the same name, and the index build rejects an alias that shadows a
  real package or that two packages both claim.
- **`jq`** joins the registry.

### Changed

- **arm64 is real.** `[source.arm64]` was previously inert: every install path
  hardcoded `.x64`, so an arm64 machine silently installed x64 binaries. Host
  architecture is now detected at runtime through `IsWow64Process2`, resolved
  via `GetProcAddress` so the binary still runs on Windows versions that predate
  the API, and per-arch `extract_dir` is part of the manifest schema.
- **One canonical TOML emitter.** Manifest serialization had drifted across
  three hand-rolled emitters, so every import reshuffled files that nobody had
  edited and the registry collected merge conflicts weekly. There is now a
  single canonical form; 288 manifests were normalized to it in one pass, with
  no semantic change to any of them.
- **`python` is now `python-embed`.** The manifest installed the embeddable
  distribution, which is not a full Python: no `pip`, no `venv`, no standard
  install layout. The name now says what you get rather than implying what you
  don't. `python` remains a working alias, so nothing breaks on upgrade.

### Fixed

- Page titles are masked and fence-neutralised like the body. A title prints
  above the `VOLI_WEB_DATA` fence, inside what reads as voli's own output, so an
  unmasked one could smuggle a secret or a forged end-marker past the boundary.
- HTML entity decoding no longer panics on multibyte input: the named-entity
  scan compared a byte slice whose length could land inside a multibyte
  character.
- The index-tool `new` wizard emits canonical TOML instead of being a third
  hand-rolled emitter.

## v0.9.2

- `voli memory` help drops the internal engine name and documents project scope.

## v0.9.1

### Added

- **Per-project memory** - a store scoped to one codebase, found automatically
  from anywhere inside it.
- A `binary` source kind for single-executable packages.

### Fixed

- 7-Zip offset handling for archives with a leading stub.

## v0.9.0

### Changed

- **Security pass.** Every manifest path field is validated and extraction is
  hardened, so a hostile manifest cannot write outside its own directory.
- The index epoch is signed *inside* the snapshot. `index.json` is fetched over
  plain HTTP, so the epoch it advertises is attacker-controlled: replaying a
  genuine older snapshot under a forged epoch would otherwise downgrade a client
  and freeze it there forever.
- Memory summaries are cryptographically bound to the memories they cover.
- CI gates the release version, so a tag and the binary it ships can never
  disagree, and every action is pinned.

### Fixed

- Shim and shortcut names are derived without the host path parser, which was
  platform-dependent.

## v0.8.2

- The Tier-1 skill catalog is live: 267 skills installable from the signed
  registry.
- `voli memory` documents that the store is local to wherever the agent runs.

## v0.8.1

### Fixed

- A manifest's `gui` flag now selects the windowless shim stub, so launching a
  GUI package no longer flashes a console window.

## v0.8.0

### Added

- **`voli memory`** - encrypted, local, zero-network memory for AI agents. Every
  record is encrypted at rest (XChaCha20-Poly1305, key from the OS keychain or an
  Argon2id passphrase) and hash-chained, so tampering is caught by
  `voli memory verify`. Recall is firewalled: secrets are masked before an agent
  sees them.
- A full documentation page, with a shared header and footer across the site.

### Fixed

- Shims carry the target app's icon instead of Voli's own stub.

## v0.7.1

### Fixed

- The default `index_url` is pinned to the index release tag. Pointing it at
  `/releases/latest` meant that creating any other release silently 404'd every
  client's index fetch.

## v0.7.0

### Added

- **Skill targeting** - repeatable `--for`, `--for detected`, `--for all`, and
  explicit `--project` or `--global` scope. Targets that share one physical
  directory are installed once and reference-counted for safe deletion.
- A confirmation gate that shows the plan before anything is written.
- Skill search on the website.

## v0.6.0

### Added

- **Agent skills** - a new package kind, validated and installed atomically into
  a verified agent directory, with each target recorded separately in the ledger.

### Changed

- `uninstall` is now `delete`, with the old spelling kept as a hidden alias.

## v0.5.1 - v0.5.7

### Added

- Package search on the website, with catalog icons and automatic per-package
  favicons.
- An installer completion banner, and clearer setup and install progress.

### Fixed

- Hardened installs and self-uninstall.
- Scoop archive rename fragments are handled.

## v0.5.0

### Added

- **Installer-archive extraction** - an EXE or MSI can be opened as a container
  and unpacked with a locally installed 7-Zip. The installer is never executed.

## v0.4.0

### Added

- An auto-bump command for the registry, and `self-uninstall`.

## v0.3.0

### Added

- Apps & Features registration, so installed packages appear where Windows users
  expect them.
- A published catalog and package search on the website.

## v0.2.0

### Added

- **`voli self-update`**, plus 7-Zip extraction, Start Menu shortcuts, sha512
  hashes, multi-URL sources, and `write_file`.
- A manifest wizard that scaffolds a package from a release asset URL.

## v0.1.1

### Fixed

- Voli shims itself, so `voli` resolves on PATH after `setup` and a bare `voli`
  shows help.

## v0.1.0

First public release.

### Added

- **The install engine** - transactional install and uninstall, with every
  mutation recorded in a ledger that `delete` replays backwards. That is the
  zero-trace guarantee, by construction rather than by promise.
- **The signed index** - an Ed25519-signed sqlite snapshot with FTS5 search,
  resumable cached downloads, dependency resolution, and did-you-mean on a miss.
- `upgrade`, `pin`, `cleanup`, `doctor`, `config`, and a consent flow for
  environment variables.
- Self-install with user-level PATH setup - no admin, at any point.
- `voli-index-tool` for validating, building, and signing the registry index.
- The one-line installer and volibear.dev.
