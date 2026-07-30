# Changelog

Notable changes per release. Versions are pre-1.0: commands and the manifest
schema may still change.

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
