# Changelog

Notable changes per release. Versions are pre-1.0: commands and the manifest
schema may still change.

## v0.12.0

### Changed

- **`voli memory init` makes a store for the codebase you are in**, like
  `git init`. Use `--global` for the machine-wide store - who you are and how
  you like to work, the things that follow you between projects. This is a
  behaviour change: plain `init` used to mean the machine-wide store, so the
  first run now names the other option rather than letting you discover it
  later. `--project` still parses, as a no-op.

### Added

- **`voli memory hook` writes the settings file for you.** Pick a target -
  `--project-local`, `--project-shared`, or `--global` - and it edits that file
  in place instead of printing a block to paste. It merges into whatever hooks
  are already there, so permissions and other hooks survive; running it twice is
  a no-op rather than a second copy; and `--remove` takes it back out, pruning
  the scaffolding it created. A settings file that does not parse is refused
  rather than rewritten, because a broken one silently disables every setting in
  it. With no target it explains the three and writes nothing.

### Fixed

- **One containment rule, not three.** The rule telling an agent that memories
  are records and never instructions lived in the setup prompt, the MCP tool
  descriptions, and the companion skill - and the three had drifted apart in
  substance, not just wording. The MCP copy, the one an agent sees most often
  because a tool list is re-sent on every request, had lost the exfiltration
  vector entirely. There is now a single `stela::CONTAINMENT`, with a test that
  fails if the skill's copy stops matching it.
- `voli memory init` honours `$VOLI_MEMORY_DIR` again. It is documented as
  overriding everything, project detection included; once a project store became
  the default, a scripted `VOLI_MEMORY_DIR=... voli memory init` would silently
  have created `.voli\` in whatever directory it ran from.
- `voli memory init` says "created" on a first run. Passphrase custody writes
  into the directory before the store checked whether it existed, so a fresh
  init always reported "found".

## v0.11.0

### Added

- **`voli memory serve --mcp`** - serves the encrypted memory to an agent over
  MCP (stdio), so it reads and writes with native tools instead of shelling out.
  Six tools: `memory_read`, `memory_search`, `memory_note`, `memory_recall`,
  `memory_history`, `memory_verify`. A prompt telling an agent to check its
  memory decays -- it scrolls out of context and dies at compaction. A tool
  definition does not, because the harness re-sends the tool list on every
  request. The disclosure firewall is enforced inside the server rather than by
  trusting the agent, and the server refuses to start while
  `VOLI_MEMORY_SHOW_SECRETS` is set: a per-command escape hatch must not quietly
  become a session-long one aimed at a model.
- **`voli memory hook`** - prints the SessionStart hook that loads memory before
  the agent decides anything, which is the only layer that does not depend on a
  model remembering. It prints rather than edits, because that file belongs to
  the agent and voli has no ledger entry to reverse the change with. A missing
  store or a locked keychain contributes nothing and exits cleanly; a hook must
  never fail the session it is starting.
- **`voli memory read --hook`** emits the hook's context envelope.
- A companion skill at `skills/voli-memory/` covering the judgement layer: what
  earns a note, supersede versus retract, `--private`, project versus global.
  Authored, not yet published to the registry.

### Fixed

- **The contradiction warning leaked secrets.** `voli memory note` quoted the
  memory it clashed with verbatim, so an AWS key came back unmasked and a
  `--private` memory came back in full -- both of which `read` correctly hides.
  Pre-existing on the CLI path; harmless-looking when a human sees their own
  secret in their own terminal, and not harmless once an agent receives it and
  carries it onward. Fixed where contradictions are collected, so the CLI and
  MCP paths are fixed together.
- The agent setup prompt and the companion skill now know about the hook and the
  MCP tools. Both previously said "run `voli memory read` first", which
  re-reads memory a hook already loaded and shells out when a native tool exists.
- Progress-row marks are coloured against the stream they are written to.
  `success_mark`/`cache_mark` asked stdout, but indicatif draws its bars to
  stderr, so piping stdout alone stripped colour from rows still on a terminal.
- `installer_archive_extracts_and_uninstalls_cleanly` and its siblings no longer
  race. Tests share one scratch Apps & Features base and reuse package names, so
  a key one test asserted on was deleted by another; and because HKCU belongs to
  the user rather than the checkout, two concurrent test processes collided
  where no in-process lock could help. The base is now per-process.

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
