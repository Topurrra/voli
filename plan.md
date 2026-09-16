# Voli improvement plan

Prioritized, evidence-backed. Every item cites the code it comes from.
Status: proposed — none of this is started.

Legend: **P0** correctness/security · **P1** reliability/UX · **P2** memory
quality · **P3** graph depth · **P4** fetch/web/shim polish.

---

## P0 — correctness & security (do first)

### Install engine
- [ ] **Cross-process install lock.** Check-then-act with no lock: two
      concurrent installs both pass `is_installed`, the loser's rollback can
      delete the winner's live dir (`install.rs:471-474,694,1028-1030`,
      `state.rs:169-194`). Add a lock file held for the whole
      install/upgrade/uninstall + `busy_timeout` on sqlite (`state.rs:104-123`).
- [ ] **Atomic `current` swap on upgrade.** `current` is unlinked before the
      new payload exists (`install.rs:1304-1305` → `:778`); a crash leaves all
      shims broken plus an orphan dir. Swap via temp-name rename; reconcile
      orphans at startup.
- [ ] **`check_gone` follows symlinks.** `path.exists()` reports a dangling
      unix symlink as gone (`install.rs:1233-1237`); ledger row drops, link
      strands. Use `symlink_metadata`.
- [ ] **Reject reserved versions.** `"current"`/`"persist"` pass
      `check_component` but collide with layout dirs (`paths.rs:216-224`,
      `manifest.rs:886`).
- [ ] **Failed upgrade strands locked shims.** Vanished-bin deletion is
      best-effort outside the action list; Windows-locked `.exe` survives and
      no future uninstall knows it (`install.rs:1328-1344,1374,1347-1389`).
      Verify deletion, fail or record leftovers.

### Trust root & environment
- [ ] **Versioned keyset + rotation runbook.** Single embedded `DEV_PUBKEY`
      (`index/sign.rs:13,44-50`); rotation bricks old clients, no key-id in
      `index.sig`. Ship `[{id, pubkey, valid_from}]`, dual-sign overlap.
- [ ] **Gate test-hook env vars in release.** `VOLI_ENV_SUBKEY`,
      `VOLI_ENV_DIR`, `VOLI_INDEX_URL` are honored unconditionally
      (`env.rs:37-39,251`, `cmd_index.rs:18-23`) — same attack class `sign.rs`
      already fixed for the pubkey override. `cfg!(debug_assertions)`-gate the
      first two; validate the URL like the config file.
- [ ] **`keygen` writes the registry secret world-readable.**
      `voli-index-tool/src/main.rs:160-179` — `fs::write` with no mode;
      umask 022 → 0644 secret. `chmod 600` after write (+ Windows ACL note).

---

## P1 — reliability & UX

### Network & versions
- [ ] **Retry with backoff everywhere.** Single-attempt fetches in
      `fetch.rs:130-146`, `remote.rs:485-502,585-602`, `index/net.rs:108-111`
      (plus unbounded index-tool fetches, `index-tool/lib.rs:995-1005`).
      Retry transient failures ~3×, resume via `.part`, stream-decompress +
      incremental hash (index snapshot holds 2× RAM today, `net.rs:149-159`).
- [ ] **Index staleness signal.** `fetched_at` is recorded and never read
      (`net.rs:38-44`); `search`/`info`/`install` present months-old data as
      current. Warn past N days; conditional-fetch headers to keep `update`
      cheap. Collapse of all `ureq` errors into "offline"
      (`net.rs:118-127`) must go with it: 4xx/5xx/TLS are hard errors, not
      "using local copy, exit 0".
- [ ] **Real version constraints.** Single-constraint solver, no unions, wrong
      pre-release order (`index/mod.rs:177-204,145-164`). Split on `,` and AND;
      adopt `semver` as the comments already suggest. Related: diamond deps
      resolve by visit order (`remote.rs:623,636,680-692`) — collect all
      constraints, error on conflict; upgrades never install *new* deps
      (`remote.rs:539-612` vs `:448`); `install foo@2.0` over 1.0 reports a
      misleading `Skipped` (`remote.rs:458-471`); wrong-version errors drop the
      version (`remote.rs:628-658` → `NotFound { name }` with no version).
- [ ] **Search hardening.** Unescaped `%`/`_` in `LIKE`
      (`index/query.rs:324-351`); empty query dumps the catalog with N+1
      lookups (`:44-52,296-298`). Escape + early-return + one `GROUP BY`.

### CLI surface
- [ ] **Uniform `--json` / `--yes`.** `which`, `pin`, `config set`, `setup`,
      `self-update` ignore `--json` (`main.rs:264-289,680,1926,927,1304`);
      `self-delete` still prompts under `--json` while `delete` doesn't
      (`:261` vs `:281`); `upgrade` ignores `--yes`. One rule: `--json`
      implies non-interactive, prompts to stderr default-abort.
- [ ] **Doctor: missing categories + `--strict`.** No index/cache/orphan-shim/
      skill/outdated-self/disk checks; renamed-check silently skips with no
      index (`main.rs:2157-2158`); WARN exits 0 so CI misses drift. Add the
      checks + orphan scan (see also install finding on orphans), add
      `--strict`. Also: doctor parses only line 1 of `.shim` instead of
      reusing `voli_shim::parse_shim` (`:2254-2258` vs `shim/lib.rs:84-110`).
- [ ] **Completions + man pages.** No `clap_complete`/`clap_mangen`
      (`voli/Cargo.toml:13-23`). Hidden `voli completion <shell>` + `voli man`.
- [ ] **Atomic writes on the trust path.** Predictable `.tmp` names, no fsync,
      `.old` deleted before the new binary verifies
      (`net.rs:185,204,213`, `selfinstall.rs:134-137,190-206`).
      Unique tmp names, write→fsync→rename→fsync-dir, shared helper.
- [ ] **Self-install ledger honesty.** `PathAdded` recorded when nothing was
      added (TOCTOU on `prior`, `selfinstall.rs:120-126,145-163`); missing shim
      stub fails silent (`:132-142`).

---

## P2 — memory quality (stela + skills)

- [ ] **Retrieval ranking.** Lexical-only BM25, no tag boost, `recall`
      ignores tags, ties surface oldest first
      (`record.rs:299-350`, `store.rs:922-944`). Tag boost, acronym expansion,
      recency tiebreak, tag-aware recall.
- [ ] **Contradiction precision.** Changed-value rule fires on any refinement;
      numbers/dates never compared; candidates gated by BM25 top-8
      (`contradiction.rs:42-61,107-140`, `store.rs:45-48,461-497`). Compare
      salient values; require entity/value mismatch; log candidate scores.
- [ ] **Firewall coverage.** PEM header-only match leaves bodies recallable;
      4+4 previews leak secret substrings; no generic `password=`/`api_key=`
      shapes (`firewall.rs:108-144,126-128,255-289,171-174`). Span PEM/PGP
      bodies, last-4-only previews, generic assignment patterns.
- [ ] **Silent truncation warnings.** Tags capped at 32 B, conf clamped, 585 B
      note limit — all invisible (`record.rs:98-111,174`,
      `store.rs:418-424,1522-1530`, `lib.rs:122`). Return warnings on
      `NoteOutcome`, print in `note_lines`, document the limit in `--help`.
- [ ] **Expired memories vanish.** No expired count in `stats`/`read`
      (`store.rs:298-304,801-919,1078-1108`). One line in `read`, `(past)`
      markers in `search`.
- [ ] **Compaction audit.** One-line summaries, no leaf linkage, no re-screen,
      `doctor` covers only rendered blocks (`store.rs:606-629,745-785,870-897`,
      `:1150-1173`). Persist leaf digests, screen `tree_put`, `doctor --deep`.
- [ ] **MCP lifecycle gap.** No compact/retract/expand/forget/stats/export
      tools (`mcp.rs:259-320`) — MCP-driven stores rot. Add retract/compact/
      expand minimum.
- [ ] **Hook beyond Claude Code.** Non-claude `for_agent` is a hard error
      (`cmd_memory.rs:1278-1282`) while skills target many agents. Next 2–3
      hook writers or a `--print` generic spec.
- [ ] **Keychain blast radius.** One entry backs every store
      (`key.rs:381-402`); `recover` re-seeds silently
      (`cmd_memory.rs:913-934`). Per-vault entries or explicit `init`/`recover`
      output. Related: recovery blob stores no Argon2 params/AAD
      (`key.rs:298-332`) — embed version + params, cross-profile test.
- [ ] **Passphrase + hook silence.** Hook returns 0 with nothing when the key
      is missing (`cmd_memory.rs:1113-1123,498-509`) — exactly the portable-
      custody users. One-line hook warning or documented unsupported pairing.
- [ ] **Skill lifecycle.** Refcount path skips integrity check
      (`skill.rs:403-464`); same-version reinstall hard-errors instead of
      no-op (`:242-255`); no scope migration (`state.rs:293-332`). Verify on
      refcount path, idempotent reinstall, `skill move --scope`.

---

## P3 — graph depth (built; harden)

- [ ] **Verify the map.** `memory verify` should cover `graph.json`'s hash —
      agents are told to rely on a file nothing checks.
- [ ] **Freshness loop.** `doctor` warns on stale graph vs HEAD; `read`
      header already names the commit — add the rebuild nudge.
- [ ] **Release numbers.** All timings so far are debug builds. Timing + binary-
      size audit; split grammars behind a Cargo feature if bloat hurts.
- [ ] **Unpin the pins.** 27 exact `=0.x` grammar pins rot. CI job trying
      newer releases against the 0.24 ABI and bumping what fits.
- [ ] **Prove it.** Same questions via `graph query` vs grep vs graphify:
      tokens spent, hops to answer. Publish the table in `docs-site/docs.html`.
- [ ] **MCP root scoping.** Graph tools discover upward from CWD; an MCP
      server's CWD isn't always the project. Explicit root (env/init arg).

---

## P4 — fetch / web / shim polish

- [ ] **Fetch exit codes.** Non-text outcomes return 0 with a stdout note
      (`cmd_fetch.rs:1564-1572`); agents can't distinguish success. Distinct
      exit code / stderr note; normalize echoed URLs (`:1496-1527`).
- [ ] **Validate `--max-bytes`.** `0` breaks every body, `u64::MAX` relies on
      saturating math, no timeout flag (`main.rs:176-184`,
      `cmd_fetch.rs:1509,40-42,254-265`). Clap range + documented budgets.
- [ ] **Redirect chain in provenance.** Only `final_url` surfaces; http
      downgrades invisible (`cmd_fetch.rs:39,171-200`, `Page:91-103`). Emit
      the chain in JSON, `via N redirects` in text, warn on downgrade.
- [ ] **Content sniffing.** Missing `Content-Type` on HTML bodies extracts
      nothing; lossy UTF-8 is silent; `title: null` for non-HTML
      (`:187-215,230`). Sniff prefixes, `encoding_lossy` flag.
- [ ] **Web bangs.** CVE shortcut points at a retired host; table is
      release-gated (`cmd_web.rs:32-65`). Update CVE, verify Translate,
      `did-you-mean` + stable JSON error for unknown bangs; later: config-
      level custom bangs.
- [ ] **Shim hardening.** `resolve()` accepts directories; GUI variant fails
      silent (`shim/lib.rs:200-215`, `voli-shim-gui.rs:12-18`). Require
      `is_file`, implement the noted MessageBox path. Install-time ambiguity
      warning for line-2 `KEY=VALUE` args, explicit unset sentinel, document
      the whitespace-splitter limit (`shim/lib.rs:96-99,135-178,140-172`).

---

## Deferred (deliberate)

Semantic (LLM/vision) backends for PDFs/images/video; Neo4j/FalkorDB push;
Google Workspace; PR triage; remaining outlier grammars (Swift, Kotlin, Lua,
Haskell, Elixir, Dart, HCL, DM, Robot beyond regex). Server-side or model-
side features that contradict local-first — graphify's list, not ours.
