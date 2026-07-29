//! `voli memory <subcommand>`: the STELA agent-memory engine (crate `stela`).
//!
//! The engine is embeddable and keychain-free; this layer resolves the master
//! key (passphrase custody, or the Windows keychain) and formats output.
//!
//! The memory directory is `$VOLI_MEMORY_DIR` / `$STELA_DIR`, else the nearest
//! `.voli\memory` in the current directory or an ancestor (unless `--global`),
//! else `%LOCALAPPDATA%\voli\memory` (or `~/.stela/memory`). A passphrase memory
//! reads `$VOLI_MEMORY_PASSPHRASE` / `$STELA_PASSPHRASE`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Subcommand;
use stela::{CustodyMode, Store, custody_mode, parse_block_id};

#[derive(Subcommand)]
pub enum MemoryCmd {
    /// Create this memory and print the agent setup prompt.
    Init {
        /// Create a project-local store in the current directory and git-ignore it.
        #[arg(long)]
        project: bool,
    },
    /// Load memory: core + task-relevant + a decaying timeline. Run first.
    Read {
        /// What you are about to do (ranks the task-relevant section).
        #[arg(long)]
        task: Option<String>,
        /// Reading budget, in lines.
        #[arg(long, default_value_t = stela::READ_LINES)]
        budget: u64,
        /// Hits for the task-relevant section.
        #[arg(short = 'k', long, default_value_t = stela::SEARCH_K)]
        k: usize,
    },
    /// Record one memory (one line).
    Note {
        /// The memory text (one line).
        text: String,
        /// Identity-critical: never compressed, always loaded (kind = core).
        #[arg(long)]
        pin: bool,
        /// Withhold this memory's text at recall (`••• (private, withheld)`).
        #[arg(long)]
        private: bool,
        /// Kind: core|fact|evnt|dcsn|pref|rtrc.
        #[arg(long, default_value = "fact")]
        kind: String,
        /// Confidence 0-100.
        #[arg(long, default_value_t = 80)]
        conf: u32,
        /// Comma-separated tags.
        #[arg(long)]
        tags: Option<String>,
        /// The memory this one supersedes (ID); the old line stays for audit.
        #[arg(long)]
        supersedes: Option<String>,
        /// This fact is true FROM this date (YYYY, YYYY-MM-DD, or unix millis).
        #[arg(long)]
        valid_from: Option<String>,
        /// This fact is true UNTIL this date (exclusive). Omit = still valid.
        #[arg(long)]
        valid_until: Option<String>,
        /// Provenance: where it came from (e.g. user, agent, import).
        #[arg(long, default_value = "user")]
        src: String,
        /// Provenance: how it was captured (e.g. note, manual).
        #[arg(long, default_value = "note")]
        method: String,
    },
    /// Ranked semantic search (BM25) -- try this first.
    Search {
        query: String,
        #[arg(short = 'k', long, default_value_t = stela::SEARCH_K)]
        k: usize,
    },
    /// Exact word search (regex); include superseded with --all.
    Recall {
        pattern: String,
        #[arg(long)]
        all: bool,
    },
    /// How a fact changed over time (the audit trail).
    History { id: Option<String> },
    /// Open a compressed block into its two halves.
    Expand { block: String },
    /// Answer a due compression (no args: show the next prompt).
    Compact {
        block: Option<String>,
        line: Option<String>,
    },
    /// Mark a memory wrong (never deletes).
    Retract { id: String, why: Option<String> },
    /// Drop a bad summary; compact rebuilds it.
    Forget { block: String },
    /// Prove the log has not been altered.
    Verify,
    /// Restore access from the recovery blob after a keychain wipe (`--save` to
    /// create the blob while access still works).
    Recover {
        /// Recovery passphrase (else $VOLI_MEMORY_PASSPHRASE / $STELA_PASSPHRASE).
        #[arg(long)]
        passphrase: Option<String>,
        /// Save a recovery blob for the CURRENT master key instead of restoring.
        #[arg(long)]
        save: bool,
    },
    /// Show memory statistics.
    Stats,
    /// Diagnose caches that are out of step.
    Doctor,
    /// Print every memory in time order.
    Export {
        #[arg(long)]
        json: bool,
    },
    /// Print the agent setup prompt.
    Prompt {
        /// Describe the project-local store instead of the machine-wide one.
        #[arg(long = "per-project")]
        per_project: bool,
    },
}

const TOOL: &str = "voli memory";

pub fn run(action: &MemoryCmd, force_global: bool) -> i32 {
    // `--global` pins every verb to the machine-wide store, so an agent working
    // inside a project can still record a fact that is not about this codebase.
    GLOBAL_ONLY.store(force_global, Ordering::Relaxed);
    match action {
        MemoryCmd::Init { project } => cmd_init(*project),
        MemoryCmd::Prompt { per_project } => {
            let (dir, scope) = if *per_project {
                (project_dir_for_prompt(), stela::Scope::Project)
            } else {
                (stela::default_memory_dir(), stela::Scope::Global)
            };
            println!("{}", stela::prompt_for(&dir, scope));
            0
        }
        MemoryCmd::Read { task, budget, k } => {
            with_store(|s| out(s.render_read(*budget, task.as_deref(), *k)))
        }
        MemoryCmd::Note {
            text,
            pin,
            private,
            kind,
            conf,
            tags,
            supersedes,
            valid_from,
            valid_until,
            src,
            method,
        } => with_store(|s| {
            cmd_note(
                &s,
                text,
                *pin,
                *private,
                kind,
                *conf,
                tags.as_deref(),
                supersedes.as_deref(),
                valid_from.as_deref(),
                valid_until.as_deref(),
                src,
                method,
            )
        }),
        MemoryCmd::Search { query, k } => with_store(|s| out(s.search(query, *k))),
        MemoryCmd::Recall { pattern, all } => with_store(|s| out(s.recall(pattern, *all))),
        MemoryCmd::History { id } => with_store(|s| out(s.history(id.as_deref()))),
        MemoryCmd::Expand { block } => with_store(|s| match parse_block_id(block) {
            Ok((lo, hi)) => out(s.expand(lo, hi)),
            Err(e) => fail(&e.to_string()),
        }),
        MemoryCmd::Compact { block, line } => {
            with_store(|s| cmd_compact(&s, block.as_deref(), line.as_deref()))
        }
        MemoryCmd::Retract { id, why } => with_store(|s| match s.retract(id, why.as_deref()) {
            Ok((rid, new)) => {
                println!(
                    "Retracted {rid} (by {new}). The original stays in the log and in `{TOOL} history`."
                );
                0
            }
            Err(e) => fail(&e.to_string()),
        }),
        MemoryCmd::Forget { block } => with_store(|s| cmd_forget(&s, block)),
        MemoryCmd::Verify => with_store(cmd_verify),
        MemoryCmd::Recover { passphrase, save } => cmd_recover(passphrase.as_deref(), *save),
        MemoryCmd::Stats => with_store(cmd_stats),
        MemoryCmd::Doctor => with_store(cmd_doctor),
        MemoryCmd::Export { json } => with_store(|s| cmd_export(&s, *json)),
    }
}

// ---------------------------------------------------------------- key custody

/// Set by `--global`, read by [`memory_dir`]. A flag rather than a parameter
/// because every verb resolves the store the same way and threading it through
/// each one would be noise.
static GLOBAL_ONLY: AtomicBool = AtomicBool::new(false);

/// Which store this invocation acts on.
///
/// 1. `$VOLI_MEMORY_DIR` / `$STELA_DIR` — an explicit path always wins.
/// 2. `--global` — skip project detection.
/// 3. A `.voli/memory` in the current directory or an ancestor.
/// 4. The machine-wide default.
///
/// Detection requires the directory to already exist, so a project only gets
/// its own store after `init --project`; nothing is ever silently redirected.
fn memory_dir() -> PathBuf {
    for var in ["VOLI_MEMORY_DIR", "STELA_DIR"] {
        if let Some(v) = std::env::var_os(var)
            && !v.is_empty()
        {
            return PathBuf::from(v);
        }
    }
    if !GLOBAL_ONLY.load(Ordering::Relaxed)
        && let Ok(cwd) = std::env::current_dir()
        && let Some(dir) = stela::project_memory_dir(&cwd)
    {
        return dir;
    }
    stela::default_memory_dir()
}

/// The path `prompt --per-project` should describe: the project store governing
/// the current directory if there is one, else where `init --project` would put
/// it. The prompt is generated before the store exists, so this must not
/// require one.
fn project_dir_for_prompt() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    stela::project_memory_dir(&cwd).unwrap_or_else(|| cwd.join(".voli").join("memory"))
}

/// Add `.voli/` to the project's `.gitignore`, creating the file if needed.
/// Returns what happened, for the caller to report.
fn ignore_project_store(project_root: &Path) -> std::io::Result<&'static str> {
    let path = project_root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    // Match the entry, not a substring: `.volirc` must not count as a hit.
    if existing
        .lines()
        .any(|l| matches!(l.trim().trim_end_matches('/'), ".voli"))
    {
        return Ok("already ignored");
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("\n# voli project memory (local knowledge, not for the repo)\n.voli/\n");
    std::fs::write(&path, out)?;
    Ok("added .voli/ to .gitignore")
}

fn passphrase() -> Option<String> {
    for var in ["VOLI_MEMORY_PASSPHRASE", "STELA_PASSPHRASE"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            return Some(v);
        }
    }
    None
}

/// Resolve the master key to OPEN an existing memory.
fn open_key(dir: &std::path::Path) -> Result<[u8; 32], String> {
    match custody_mode(dir) {
        CustodyMode::Passphrase => {
            let pass = passphrase()
                .ok_or("this memory is passphrase-protected; set VOLI_MEMORY_PASSPHRASE")?;
            stela::derive_master_for_open(dir, &pass)
                .map(|k| *k)
                .map_err(|e| e.to_string())
        }
        CustodyMode::Keyring => keyring_open(),
    }
}

/// Resolve the master key to CREATE (or re-open) a memory.
fn init_key(dir: &std::path::Path) -> Result<([u8; 32], &'static str), String> {
    if let Some(pass) = passphrase() {
        let key = if custody_mode(dir) == CustodyMode::Passphrase {
            stela::derive_master_for_open(dir, &pass).map_err(|e| e.to_string())?
        } else {
            stela::create_passphrase_custody(dir, &pass).map_err(|e| e.to_string())?
        };
        Ok((*key, "passphrase"))
    } else {
        keyring_init().map(|k| (k, "keychain"))
    }
}

#[cfg(windows)]
fn keyring_open() -> Result<[u8; 32], String> {
    match stela::key::load_master_key().map_err(|e| e.to_string())? {
        Some(k) => Ok(k),
        None => Err(format!(
            "no key found; run `{TOOL} init` or set VOLI_MEMORY_PASSPHRASE"
        )),
    }
}

#[cfg(not(windows))]
fn keyring_open() -> Result<[u8; 32], String> {
    Err("this platform has no keychain; set VOLI_MEMORY_PASSPHRASE for a passphrase memory".into())
}

#[cfg(windows)]
fn keyring_init() -> Result<[u8; 32], String> {
    stela::key::load_or_create_master_key().map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn keyring_init() -> Result<[u8; 32], String> {
    Err(
        "this platform has no keychain; set VOLI_MEMORY_PASSPHRASE to create a passphrase memory"
            .into(),
    )
}

fn with_store(f: impl FnOnce(Store) -> i32) -> i32 {
    let dir = memory_dir();
    if !dir.is_dir() {
        eprintln!("error: no memory at {}. Run: {TOOL} init", dir.display());
        return 1;
    }
    let key = match open_key(&dir) {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    match Store::open_with_key(dir, key) {
        Ok(s) => f(s),
        Err(e) => fail(&e.to_string()),
    }
}

// ---------------------------------------------------------------- commands

fn cmd_init(project: bool) -> i32 {
    let mut gitignore_note = None;
    let dir = if project {
        let root = match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => return fail(&e.to_string()),
        };
        match ignore_project_store(&root) {
            Ok(note) => gitignore_note = Some(note),
            // Not fatal: the store is still usable, the user just has to ignore
            // it themselves. Saying so beats failing the init.
            Err(e) => {
                gitignore_note = Some(Box::leak(
                    format!("could not update .gitignore ({e}) - add .voli/ yourself")
                        .into_boxed_str(),
                ))
            }
        }
        root.join(".voli").join("memory")
    } else {
        memory_dir()
    };
    let (key, mode) = match init_key(&dir) {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let (store, fresh) = match Store::init_with_key(&dir, key) {
        Ok(sf) => sf,
        Err(e) => return fail(&e.to_string()),
    };
    let dev = store.device().unwrap_or_default();
    println!(
        "{} memory {} at {} (device {dev}, custody: {mode}).",
        if project { "Project" } else { "Global" },
        if fresh { "created" } else { "found" },
        dir.display()
    );
    if let Some(note) = gitignore_note {
        println!("{note}");
    }
    println!();
    let scope = if project {
        stela::Scope::Project
    } else {
        stela::Scope::Global
    };
    println!("{}", stela::prompt_for(&dir, scope));
    0
}

#[allow(clippy::too_many_arguments)]
fn cmd_note(
    store: &Store,
    text: &str,
    pin: bool,
    private: bool,
    kind: &str,
    conf: u32,
    tags: Option<&str>,
    supersedes: Option<&str>,
    valid_from: Option<&str>,
    valid_until: Option<&str>,
    src: &str,
    method: &str,
) -> i32 {
    let kind = if pin { "core" } else { kind };
    let mut tags: Vec<String> = tags
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    // The `--private` marker rides as a reserved tag, prepended so the tag-width
    // cap can never drop it. Detection at write; withheld at recall.
    if private {
        tags.retain(|t| t != stela::PRIVATE_TAG);
        tags.insert(0, stela::PRIVATE_TAG.to_string());
    }
    let vfrom = match valid_from.map(parse_when).transpose() {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let vuntil = match valid_until.map(parse_when).transpose() {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    match store.note_valid(
        text, kind, conf, &tags, supersedes, src, method, vfrom, vuntil,
    ) {
        Ok(o) => {
            println!(
                "Saved {}{}.",
                o.id,
                if o.is_core {
                    " (core - never compressed)"
                } else {
                    ""
                }
            );
            if let Some(sup) = o.superseded {
                println!("Superseded {sup}. It stays in the log; `{TOOL} history` shows it.");
            }
            for (id, text) in &o.contradicts {
                println!(
                    "warning: this may contradict {id}: \"{text}\". If the truth changed, \
                     re-run with `--supersedes {id}`."
                );
            }
            if o.pending > 0 {
                println!(
                    "{} block(s) now due for compression - run `{TOOL} compact` when between tasks.",
                    o.pending
                );
            }
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

/// Parse a `--valid-from` / `--valid-until` value: `YYYY`, `YYYY-MM-DD` (or with
/// `/` `.` separators), or a raw unix-millis integer (≥ 5 digits).
fn parse_when(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let bad = || format!("bad date '{s}' (use YYYY, YYYY-MM-DD, or unix millis)");
    if s.len() >= 5 && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<i64>().map_err(|_| bad());
    }
    let mut parts = s.split(['-', '/', '.', 'T']);
    let y: i64 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
    let m: u32 = parts
        .next()
        .map_or(Ok(1), |p| p.parse())
        .map_err(|_| bad())?;
    let d: u32 = parts
        .next()
        .map_or(Ok(1), |p| p.parse())
        .map_err(|_| bad())?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    Ok(stela::millis_from_civil(y, m, d))
}

fn cmd_compact(store: &Store, block: Option<&str>, line: Option<&str>) -> i32 {
    match (block, line) {
        (Some(b), Some(l)) => {
            let (lo, hi) = match parse_block_id(b) {
                Ok(x) => x,
                Err(e) => return fail(&e.to_string()),
            };
            match store.tree_put(lo, hi, l) {
                Ok(true) => println!("{}-{} saved.", lo, hi - 1),
                Ok(false) => println!(
                    "{}-{} is already settled or is not the next block.",
                    lo,
                    hi - 1
                ),
                Err(e) => return fail(&e.to_string()),
            }
        }
        (None, None) => {}
        _ => {
            eprintln!("usage: {TOOL} compact <lo>-<hi> \"<one line>\"");
            return 1;
        }
    }
    match store.next_compact() {
        Ok(Some(p)) => {
            println!("{p}");
            0
        }
        Ok(None) => {
            println!("Nothing to compress.");
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_forget(store: &Store, block: &str) -> i32 {
    let (lo, hi) = match parse_block_id(block) {
        Ok(x) => x,
        Err(e) => return fail(&e.to_string()),
    };
    match store.tree_drop(lo, hi) {
        Ok(gone) if gone.is_empty() => {
            println!("No summary at {block}.");
            0
        }
        Ok(gone) => {
            println!(
                "Dropped {} summary/summaries. The next `{TOOL} compact` rebuilds them.",
                gone.len()
            );
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_recover(pass_flag: Option<&str>, save: bool) -> i32 {
    let dir = memory_dir();
    let Some(pass) = pass_flag.map(str::to_string).or_else(passphrase) else {
        return fail("a recovery passphrase is required (--passphrase or VOLI_MEMORY_PASSPHRASE)");
    };
    if save {
        if !dir.is_dir() {
            return fail(&format!("no memory at {}. Run: {TOOL} init", dir.display()));
        }
        let key = match open_key(&dir) {
            Ok(k) => k,
            Err(e) => return fail(&e),
        };
        match stela::write_recovery_blob(&dir, &key, &pass) {
            Ok(()) => {
                println!(
                    "Recovery key saved to {}. Keep the passphrase safe: it is the only way\n\
                     to restore access if the OS keychain is wiped.",
                    stela::recovery_blob_path(&dir).display()
                );
                0
            }
            Err(e) => fail(&e.to_string()),
        }
    } else {
        let key = match stela::recover_master(&dir, &pass) {
            Ok(k) => k,
            Err(e) => return fail(&e.to_string()),
        };
        reestablish_custody(&dir, &key)
    }
}

/// Put the recovered master key back into the OS keychain so `read` works again.
#[cfg(windows)]
fn reestablish_custody(dir: &std::path::Path, key: &[u8; 32]) -> i32 {
    if custody_mode(dir) == CustodyMode::Passphrase {
        return fail(
            "this memory uses passphrase custody, not the keychain; just set VOLI_MEMORY_PASSPHRASE \
             and run read (no recovery blob needed)",
        );
    }
    if let Err(e) = stela::key::store_master_key(key) {
        return fail(&e.to_string());
    }
    // Sanity: the store now opens with the restored key.
    match Store::open_with_key(dir.to_path_buf(), *key) {
        Ok(_) => {
            println!(
                "Access restored: the master key is back in the Windows keychain. \
                 Run `{TOOL} read` to confirm."
            );
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

/// Off Windows there is no OS keychain to re-seed; passphrase custody needs no
/// recovery blob. The passphrase was still validated (the unwrap succeeded).
#[cfg(not(windows))]
fn reestablish_custody(_dir: &std::path::Path, _key: &[u8; 32]) -> i32 {
    eprintln!(
        "error: keychain restore is Windows-only. The recovery passphrase is correct, but on \
         this platform use passphrase custody (VOLI_MEMORY_PASSPHRASE) instead of a recovery blob."
    );
    1
}

fn cmd_verify(store: Store) -> i32 {
    match store.verify() {
        Ok(report) if report.ok() => {
            println!("OK - {} records, every hash chain intact.", report.total);
            0
        }
        Ok(report) => {
            eprintln!("INTEGRITY FAILURE - {} record(s) checked", report.total);
            for b in &report.bad {
                eprintln!("  {b}");
            }
            2
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_stats(store: Store) -> i32 {
    match store.stats() {
        Ok(s) => {
            println!("memories      {} live / {} total", s.live, s.total);
            println!("superseded    {}", s.superseded);
            for (k, c) in &s.by_kind {
                println!("  {k:<10}  {c}   ({})", stela::kind_help(k));
            }
            println!("shards        {}", s.shards.join(", "));
            println!("on disk       {:.1} MB", s.bytes as f64 / 1e6);
            println!("pending merge {}", s.pending);
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_doctor(store: Store) -> i32 {
    match store.doctor() {
        Ok(issues) if issues.is_empty() => {
            println!("No issues.");
            0
        }
        Ok(issues) => {
            for i in &issues {
                println!("{i}");
            }
            println!("{} issue(s).", issues.len());
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_export(store: &Store, json: bool) -> i32 {
    if json {
        match store.export_records() {
            Ok(recs) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&recs).unwrap_or_default()
                );
                0
            }
            Err(e) => fail(&e.to_string()),
        }
    } else {
        match store.export_lines() {
            Ok(lines) => {
                for l in &lines {
                    println!("{l}");
                }
                0
            }
            Err(e) => fail(&e.to_string()),
        }
    }
}

// ---------------------------------------------------------------- helpers

/// Print a fenced, firewalled result, or the error. The [`stela::Disclosed`]
/// egress type prints via `Display`; its raw form is never exposed here.
fn out(r: stela::Result<stela::Disclosed>) -> i32 {
    match r {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn fail(msg: &str) -> i32 {
    eprintln!("error: {msg}");
    1
}
