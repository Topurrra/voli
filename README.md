<p align="center">
  <img src="assets/Voli.gif" width="800" alt="Voli the bear in the forest">
</p>

<h1 align="center">Voli · The Bear That Delivers</h1>

<p align="center">⚡ A fast, no-admin package manager for Windows. One binary, clean uninstalls, zero scripts.</p>

## Install

One line in PowerShell (no admin):

```powershell
iwr -useb volibear.dev/install | iex
```

The installer downloads the latest release, verifies its SHA-256, and runs
`voli setup` (user-level PATH, no admin). It does nothing else - read it first
if you like: [`install.ps1`](install.ps1).

> **Status: v0.12.2, still pre-1.0.** The core workflow is released and working,
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
| `voli install skill/<name> --for <agent>` | Install a published skill for one or more supported agents. |
| `voli delete <pkg> ...` | Delete packages by replaying their ledger. Persist data is kept by default. |
| `voli delete skill/<name> --for <agent>` | Delete one or more target-scoped skill mappings. |
| `voli memory <cmd>` | Encrypted, local memory for AI agents - see [Agent memory](#agent-memory). |
| `voli memory serve --mcp` | Serve memory to an agent over MCP (stdio), so it reads and writes with native tools. |
| `voli memory hook --global\|--project-shared\|--project-local` | Wire the SessionStart hook that loads memory before the agent decides anything. `--remove` takes it out. |
| `voli web <bang> <query>` | Open a search shortcut in your browser. Voli builds the URL and fetches nothing. |
| `voli fetch <url>` | Fetch a page as text, Markdown, or JSON, with provenance - see [Web search and fetch](#web-search-and-fetch). |
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
voli install skill/tdd --for codex
voli install skill/tdd --for codex --for cursor
voli install skill/tdd --for detected --global
voli install skill/tdd --for all --project
voli install skill/voli-memory --for claude-code

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
voli delete skill/tdd --for codex
voli delete skill/tdd --for codex --for cursor --global

voli web g "rust async traits"
voli web --url gh tantivy
voli fetch https://doc.rust-lang.org/std/pin/index.html
voli fetch example.com --format md
voli fetch example.com --json

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

## Renamed packages

A package that gets renamed keeps answering to its old name. `voli install
python` installs `python-embed` and says so first - the old name resolves, it
just never pretends nothing changed.

An existing install is left alone, because the new name is a different package
with its own shims and switching is your call, not the package manager's:

```powershell
voli upgrade --all
# python (3.14.6) was renamed to python-embed and is no longer updated
#   switch with: voli install python-embed && voli delete python
```

`voli doctor` reports the same thing as a warning, so a package that has quietly
stopped receiving updates is visible rather than silent. Aliases are one hop and
never chain, a live package always beats an alias on the same name, and the
index build refuses to publish an alias that shadows a real package or that two
packages both claim.

`voli delete <pkg> --purge` also removes the package's persisted user data.
Without `--purge`, persist directories survive so a later reinstall can reuse
them. The older `uninstall` and `self-uninstall` spellings remain supported as
hidden compatibility aliases.

## Agent skills

Voli validates Agent Skills archives, installs them atomically into a verified
agent directory, and records each target separately in its ledger. The public
Tier-1 skill catalog is live: 267 skills you can install straight from the
signed registry, for example `voli install skill/tdd --for codex`.

You can also install a local archive:

```powershell
voli install .\skill.toml --archive .\skill.zip --for codex
voli list
voli delete skill/example-skill --for codex
```

Voli ships one of its own: `skill/voli-memory` teaches an agent the judgement
half of `voli memory` - what earns a note, when a fact has been *superseded*
rather than *retracted*, and what should never be written down at all.

```powershell
voli install skill/voli-memory --for claude-code
```

Skill installation uses direct copies and supports repeatable `--for` targets,
`--for detected`, `--for all`, and explicit `--project` or `--global` scope.
Without `--for`, an interactive terminal offers a filtered multi-select and
remembers the last successful selection. Non-interactive commands must provide
an explicit target. Targets that share one physical directory are installed
once and reference-counted for safe deletion. Link mode remains deferred.

## Agent memory

`voli memory` is a persistent, encrypted, on-disk memory for AI agents - one
store that outlives restarts, context resets, and model changes. Zero network,
like the rest of Voli: every record is encrypted at rest (XChaCha20-Poly1305,
key from the OS keychain or an Argon2id passphrase) and hash-chained, so
tampering is caught by `voli memory verify`.

```powershell
voli memory read --task "<what you're doing>"   # load context - run first
voli memory note "<one line>"                    # record a fact or decision
voli memory search "<question>"                  # best-match retrieval
voli memory verify                               # prove nothing was altered

voli memory hook --project-local                 # deterministic load at session start
voli memory serve --mcp                          # native tools instead of shelling out
```

Recall is firewalled - secrets (keys, cards, SSNs) are masked before an agent
sees them and `--private` notes are withheld. `voli memory prompt` writes the
setup prompt that wires an agent to the whole workflow into
`voli-memory-prompt.md`, so you can copy it out of an editor rather than the
terminal; add `--print` to send it to stdout instead, or `--out <path>` to choose
the file. Bitemporal validity, supersession, contradiction warnings, and
passphrase recovery are built in.

### Wiring an agent

Three layers, doing different jobs. An instruction can be forgotten and a tool
can go uncalled, but a hook fires whether the model cooperates or not.

**The hook** is the deterministic one. A prompt telling an agent to check its
memory lives in the conversation, so it scrolls away and dies at compaction. A
SessionStart hook runs before the model chooses anything:

```powershell
voli memory hook --project-local     # this project, just you
voli memory hook --project-shared    # this project, committed for the team
voli memory hook --global            # every project on this machine
```

Each edits that settings file in place, merging into whatever hooks are already
there - your permissions and other hooks are untouched. Running it twice is a
no-op rather than a second copy, and `--remove` takes it back out, pruning the
scaffolding it created. A settings file that does not parse is refused rather
than rewritten, because a broken one silently disables every setting in it.

`voli memory hook` with no target explains the three and writes nothing.

If the store is missing or locked the hook contributes nothing and exits
cleanly - it must never fail the session it is starting.

**The MCP server** keeps the tools present. A tool definition does not decay,
because the harness re-sends the tool list on every request:

```powershell
voli memory serve --mcp
```

Six tools - `memory_read`, `memory_search`, `memory_note`, `memory_recall`,
`memory_history`, `memory_verify` - each mapping onto the command of the same
name. Point an agent at it with:

```json
{ "mcpServers": { "voli-memory": {
  "command": "voli", "args": ["memory", "serve", "--mcp"] } } }
```

The disclosure firewall runs *inside* the server rather than trusting the agent:
secrets are masked and `--private` memories withheld before anything crosses the
wire. The server refuses to start while `VOLI_MEMORY_SHOW_SECRETS` is set,
because a per-command escape hatch must not quietly become a session-long one
aimed at a model.

**The prompt or the skill** supplies the judgement - what is worth saving, when
to supersede versus retract. That is the part that genuinely needs a model.
`voli memory prompt` writes it as a file to paste;
`voli install skill/voli-memory --for <agent>` installs it as a skill the agent
loads on its own.

### Per-project memory

A project can keep its own store for knowledge about that codebase, separate
from what you know about the user:

```powershell
voli memory init                 # creates .voli\memory here, git-ignores .voli\
voli memory prompt --per-project # writes voli-memory-prompt.project.md
```

`init` works like `git init`: it makes a store for the codebase you are standing
in. Use `voli memory init --global` for the machine-wide store instead - who you
are and how you like to work, the things that follow you between projects.

Every `voli memory` command run anywhere inside the project then finds it
automatically - the nearest `.voli\memory` in the current directory or an
ancestor wins, so nested repositories each keep their own. Detection requires
the store to exist, so a directory that never ran `init` keeps using the
machine-wide store. Add `--global` to any command to reach that store from
inside a project, and `$VOLI_MEMORY_DIR` still overrides everything.

## Web search and fetch

`voli web` turns a shortcut into a URL and hands it to your browser. Voli makes
no request of its own: there is no API key, no quota, no cost, and nothing to
bot-block, because the search is performed by the browser you are already
signed in to.

```powershell
voli web                              # list the shortcuts
voli web g "rust async traits"         # Google
voli web cr tantivy                    # crates.io
voli web --url so "lifetime error"     # print the URL instead of opening it
```

Shortcuts cover the search engines (`g`, `ddg`, `bing`, `brave`, `kagi`, `sp`),
reference (`w`, `tr`, `maps`, `img`), code and packages (`gh`, `ghc`, `cr`,
`rs`, `std`, `npm`, `pypi`, `go`), developer reference (`so`, `mdn`, `ciu`,
`aw`, `man`, `cve`), and community (`hn`, `r`, `yt`). The query is
percent-encoded down to the unreserved characters and the URL is passed to
`ShellExecuteW` as a single argument - never through a shell - so a query full
of `&`, `|`, `` ` `` or `%` has nothing to escape into.

`voli fetch` retrieves a page and turns it into clean text an agent can read,
with the provenance to prove what was read:

```powershell
voli fetch https://doc.rust-lang.org/std/pin/index.html
voli fetch example.com --format md
voli fetch example.com --json --max-bytes 262144
```

It prints the final URL after redirects (so a redirect to a login page is
visible, not silent), the fetch timestamp, the sha256 of exactly the bytes
received, and the byte length. HTTPS is the default and only http/https is
accepted - `file:`, `data:` and `javascript:` URLs are refused. Response size,
redirect count, and total time are all capped, and the size cap is enforced
while reading rather than audited afterwards.

`--format` picks the shape: `text` (the default, flattened prose), `md`, or
`json`. `--json` is an alias for `--format json`, so asking for both at once -
`--json --format md` - is refused rather than silently resolved.

`--format md` keeps the structure instead of flattening it: headings, ordered
and unordered lists (nested ones included), fenced code blocks, blockquotes,
inline code, bold and italic, strikethrough, task lists with their checked
state, horizontal rules, hard line breaks, images, and link targets resolved
against the page's final URL. A table becomes a real pipe
table when every row agrees on the column count, and one cell per line when it
does not - a table that lies about its shape is worse than plain lines. An
image becomes `![alt](src)` with its source resolved like any other link, so a
figure an agent can go and look at survives instead of vanishing. Struck-out
text keeps its `~~` and a checklist keeps its `[x]`/`[ ]`, because text that
has been retracted reads as current fact without them, and a checklist whose
state is gone makes every item look equally undone.
Structure survives a token budget far better than flattened prose, and a link
an agent can follow is worth more than the word that was linked.

Page content is hostile, so the Markdown is defensive: a code block's fence is
always longer than any run of backticks inside it, link labels have their
brackets escaped and link targets have their parens percent-encoded, a `<` that
could start raw HTML is escaped, and a `javascript:` or `data:` href keeps its
text and loses its target. Images get the same treatment, because their alt
text and their source are attacker-controlled in exactly the same way.

Text is extracted locally - no reader service is contacted - by stripping
scripts, styles, and page chrome; a content type that is not text is reported
rather than turned into invented prose. Every format goes through the same two
gates: the result is wrapped in a `VOLI_WEB_DATA` fence that tells the agent
everything inside is data and never instructions, and it passes through the
same secret masking `voli memory` uses on recall. Fetched pages are the number
one prompt-injection vector, and this is the seam that says so out loud.

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
