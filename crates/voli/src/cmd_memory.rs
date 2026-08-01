//! `voli memory <subcommand>`: the agent-memory engine (internal crate `stela`;
//! that name is never surfaced to users).
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
    /// Create a memory here, for THIS codebase, and print the agent setup prompt.
    ///
    /// Like `git init`: it creates `.voli\memory` in the current directory and
    /// git-ignores `.voli\`. Every memory command run anywhere inside the project
    /// then finds it automatically, with no path to pass.
    ///
    /// Use `--global` for the machine-wide store instead: who you are and how you
    /// like to work, the things that follow you between projects.
    Init {
        /// Accepted and ignored: a project store is what plain `init` now makes.
        #[arg(long, hide = true)]
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
        /// Emit the agent-hook envelope instead of plain text, so a SessionStart
        /// hook injects this straight into the model's context.
        #[arg(long)]
        hook: bool,
    },
    /// Print the agent hook that loads memory at the start of every session.
    ///
    /// An instruction telling an agent to read memory decays: it scrolls out of
    /// context and is lost to compaction. A hook does not -- it fires before the
    /// model chooses anything, so loading memory stops being the agent's job to
    /// remember.
    /// Wire the session-start hook that loads memory before the agent decides
    /// anything.
    ///
    /// With no target flag this explains the options and writes nothing. Pick a
    /// target and it edits that settings file for you, merging into whatever
    /// hooks are already there.
    Hook {
        /// Write to this project, for you only (.claude\settings.local.json).
        #[arg(long, conflicts_with = "project_shared")]
        project_local: bool,
        /// Write to this project, shared with the team (.claude\settings.json).
        #[arg(long)]
        project_shared: bool,
        /// Take the hook back out of the same file.
        #[arg(long)]
        remove: bool,
        /// Which agent's config format (currently: claude-code).
        #[arg(long, default_value = "claude-code")]
        for_agent: String,
    },
    /// Serve this memory to an agent over MCP, on stdin/stdout.
    ///
    /// The same decay argument as `hook`, one level up. A hook fires once per
    /// session; a TOOL LIST is re-sent by the harness on every single request,
    /// so a memory tool never scrolls away and never dies at compaction. This
    /// is memory moved from decaying context into non-decaying context.
    Serve {
        /// Speak the Model Context Protocol over stdin/stdout.
        #[arg(long)]
        mcp: bool,
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
    ///
    /// With --per-project, prints the prompt for a project-local store: what
    /// belongs in it, that it is git-ignored, and when to use --global instead.
    ///
    /// Writes it to a Markdown file so you can open it and copy from an editor
    /// rather than a terminal scrollback. `--print` sends it to stdout instead,
    /// which is what you want when piping it somewhere.
    Prompt {
        /// Describe the project-local store instead of the machine-wide one.
        #[arg(long = "per-project")]
        per_project: bool,
        /// Print to stdout instead of writing a file.
        #[arg(long)]
        print: bool,
        /// Where to write it (default: voli-memory-prompt.md here).
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
}

const TOOL: &str = "voli memory";

pub fn run(action: &MemoryCmd, force_global: bool) -> i32 {
    // `--global` pins every verb to the machine-wide store, so an agent working
    // inside a project can still record a fact that is not about this codebase.
    GLOBAL_ONLY.store(force_global, Ordering::Relaxed);
    match action {
        // `--project` is the default now, so the flag survives only so an older
        // command line keeps working rather than erroring on an unknown arg.
        MemoryCmd::Init { project: _ } => cmd_init(!force_global),
        MemoryCmd::Prompt {
            per_project,
            print,
            out,
        } => {
            let (dir, scope) = if *per_project {
                (project_dir_for_prompt(), stela::Scope::Project)
            } else {
                (stela::default_memory_dir(), stela::Scope::Global)
            };
            let text = stela::prompt_for(&dir, scope);
            if *print {
                println!("{text}");
                return 0;
            }
            write_prompt_file(&text, out.as_deref(), *per_project)
        }
        MemoryCmd::Read {
            task,
            budget,
            k,
            hook,
        } => {
            if *hook {
                // Never fail, never speak: a hook runs before the session the
                // user is trying to start, so a missing store or a locked
                // keychain must contribute nothing rather than surface an error
                // at the worst possible moment. `with_store` is bypassed for
                // exactly that reason -- it reports failures, which is right for
                // every other caller and wrong for this one.
                return read_for_hook(*budget, task.as_deref(), *k);
            }
            with_store(|s| {
                out(s.render_read(*budget, task.as_deref(), *k, &global_core_for_project()))
            })
        }
        MemoryCmd::Hook {
            project_local,
            project_shared,
            remove,
            for_agent,
        } => cmd_hook(
            for_agent,
            // `--global` is the existing machine-wide flag on `voli memory`, so
            // it keeps meaning the same thing here rather than gaining a second
            // spelling.
            HookTarget::pick(force_global, *project_shared, *project_local),
            *remove,
        ),
        MemoryCmd::Serve { mcp } => {
            if !*mcp {
                eprintln!("error: `{TOOL} serve` speaks only MCP; pass --mcp");
                return 1;
            }
            crate::mcp::serve()
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

/// The store dir pinned by env, if any. One place for the override contract so
/// [`memory_dir`] and the global-core borrow cannot disagree about what counts
/// as "the user pinned this store explicitly".
fn env_dir() -> Option<PathBuf> {
    ["VOLI_MEMORY_DIR", "STELA_DIR"]
        .into_iter()
        .find_map(|var| {
            std::env::var_os(var)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
}

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
    if let Some(dir) = env_dir() {
        return dir;
    }
    if !GLOBAL_ONLY.load(Ordering::Relaxed)
        && let Ok(cwd) = std::env::current_dir()
        && let Some(dir) = stela::project_memory_dir(&cwd)
    {
        return dir;
    }
    stela::default_memory_dir()
}

/// Write the agent prompt to a Markdown file and say where it went.
///
/// A file rather than stdout by default because the prompt's whole purpose is to
/// be pasted into an agent's system prompt or a `CLAUDE.md` / `AGENTS.md`, and
/// copying ~90 lines out of a terminal scrollback is miserable. `--print` keeps
/// the old behaviour for pipes.
fn write_prompt_file(text: &str, out: Option<&Path>, per_project: bool) -> i32 {
    let default_name = if per_project {
        "voli-memory-prompt.project.md"
    } else {
        "voli-memory-prompt.md"
    };
    let path = match out {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(d) => d.join(default_name),
            Err(e) => return fail(&e.to_string()),
        },
    };
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return fail(&format!("could not create {}: {e}", parent.display()));
    }
    // Existing file is overwritten: this is a generated artefact and the point of
    // re-running is to regenerate it. Say which happened so an edited file being
    // replaced is never a surprise.
    let existed = path.exists();
    // The prompt is fenced Markdown; a trailing newline keeps editors and `cat`
    // happy and makes the file diff-friendly.
    let body = if text.ends_with('\n') {
        text.to_string()
    } else {
        format!("{text}\n")
    };
    if let Err(e) = std::fs::write(&path, body) {
        return fail(&format!("could not write {}: {e}", path.display()));
    }
    println!(
        "{} {} {}",
        crate::success_mark(),
        if existed { "updated" } else { "wrote" },
        path.display()
    );
    println!("  paste it into your agent's system prompt, CLAUDE.md, or AGENTS.md");
    println!("  regenerated by this command - no need to commit it");
    println!("  `{TOOL} prompt --print` sends it to stdout instead");
    ignore_generated_prompt(&path);
    0
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
    add_gitignore_entry(
        project_root,
        ".voli",
        ".voli/",
        "# voli project memory (local knowledge, not for the repo)",
    )
    .map(|added| {
        if added {
            "added .voli/ to .gitignore"
        } else {
            "already ignored"
        }
    })
}

/// Add one entry to the project's `.gitignore`, if it is not already there.
///
/// `entry` is the line written; `key` is what an existing line has to equal
/// (trailing slash stripped) to count as already present -- matching the entry
/// rather than a substring, so `.volirc` never counts as `.voli`.
///
/// Returns whether anything was written.
fn add_gitignore_entry(
    project_root: &Path,
    key: &str,
    entry: &str,
    comment: &str,
) -> std::io::Result<bool> {
    let path = project_root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing
        .lines()
        .any(|l| l.trim().trim_end_matches('/') == key)
    {
        return Ok(false);
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("\n{comment}\n{entry}\n"));
    std::fs::write(&path, out)?;
    Ok(true)
}

/// Keep a generated prompt file out of the repository it was written into.
///
/// The prompt is generated from `stela`, so a committed copy is a duplicate that
/// goes stale the next time the wording changes -- the same trap the containment
/// rule fell into. Best effort: not being in a git repo, or not being able to
/// write, is not a reason to fail writing the prompt itself.
fn ignore_generated_prompt(path: &Path) {
    let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return;
    };
    if !dir.join(".git").exists() {
        return; // not a repository root: nothing to ignore it in
    }
    let _ = add_gitignore_entry(
        dir,
        "voli-memory-prompt*.md",
        "voli-memory-prompt*.md",
        "# generated by `voli memory prompt`; regenerate rather than commit it",
    );
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

/// Open the machine-wide store explicitly, whatever directory we are in.
///
/// The MCP `memory_note` uses this to honour `global: true` without the server
/// having to be started in global scope. Like the CLI, it does not create the
/// store -- a note needs one that exists, so a missing global store is a clear
/// error, not a silent new store in a surprising place.
pub(crate) fn open_global_store() -> Result<Store, String> {
    let dir = stela::default_memory_dir();
    if !dir.is_dir() {
        return Err(format!(
            "no global memory yet. Run `{TOOL} init --global` once to create it."
        ));
    }
    let key = open_key(&dir)?;
    Store::open_with_key(dir, key).map_err(|e| e.to_string())
}

/// Resolve the store this invocation acts on, or say why it cannot be opened.
///
/// Split out of [`with_store`] because a caller that does not own the process
/// exit code -- the MCP server, which must answer the request rather than die --
/// still has to resolve the directory and the custody key exactly the same way.
pub(crate) fn open_store() -> Result<Store, String> {
    let dir = memory_dir();
    if !dir.is_dir() {
        return Err(format!("no memory at {}. Run: {TOOL} init", dir.display()));
    }
    let key = open_key(&dir)?;
    Store::open_with_key(dir, key).map_err(|e| e.to_string())
}

fn with_store(f: impl FnOnce(Store) -> i32) -> i32 {
    match open_store() {
        Ok(s) => f(s),
        Err(e) => fail(&e),
    }
}

// ---------------------------------------------------------------- commands

/// Whether `init` should make a store for the current directory.
///
/// Split out because getting it wrong is silent: the store lands in whatever
/// directory the command happened to run from, and nothing says so. An explicit
/// `$VOLI_MEMORY_DIR` always wins -- it is documented as overriding everything,
/// project detection included.
fn wants_project_store(project_requested: bool, explicit: Option<&Path>) -> bool {
    project_requested && explicit.is_none()
}

fn cmd_init(project: bool) -> i32 {
    let mut gitignore_note = None;
    // `$VOLI_MEMORY_DIR` is documented as overriding everything, project
    // detection included. That used to be true of `init` for free, because it
    // went through memory_dir(); now that a project store is the default, the
    // override has to be honoured explicitly or a scripted init silently makes
    // `.voli\` in whatever directory it was run from.
    let explicit = ["VOLI_MEMORY_DIR", "STELA_DIR"]
        .iter()
        .find_map(|var| std::env::var_os(var).filter(|v| !v.is_empty()))
        .map(PathBuf::from);
    let project = wants_project_store(project, explicit.as_deref());
    let dir = if let Some(dir) = explicit {
        dir
    } else if project {
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
    // Ask BEFORE init_key: passphrase custody writes its file into this
    // directory, so by the time the store computes its own answer the directory
    // exists and a first run reports "found".
    let fresh = !dir.is_dir();
    let (key, mode) = match init_key(&dir) {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let (store, _) = match Store::init_with_key(&dir, key) {
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
    // Plain `init` used to mean the machine-wide store. Anyone carrying that
    // habit now gets a store in whatever directory they happened to be in, so
    // name the other one rather than let them find out later.
    if project && fresh {
        println!("  (for the machine-wide store instead: {TOOL} init --global)");
    }
    println!();
    // Deliberately NOT the whole prompt. It is ~70 lines, and dumping it here
    // buries the one thing the user came for -- the store exists -- under a wall
    // of text they cannot act on from a terminal. Name the three ways to wire an
    // agent instead, so the next step is a command rather than a scroll.
    // The hook has to land in the same scope as the store it loads: a global
    // store wired per-project would go unloaded everywhere else.
    let (hook_flag, prompt_flag) = if project {
        ("--project-local", " --per-project")
    } else {
        ("--global", "")
    };
    println!("Wire an agent to it, best first:");
    println!();
    for (command, what) in [
        (
            format!("{TOOL} hook {hook_flag}"),
            "load it at session start, unasked",
        ),
        (
            format!("{TOOL} serve --mcp"),
            "serve it as native agent tools",
        ),
        (
            "voli install skill/voli-memory --for <agent>".to_string(),
            "teach it what is worth keeping",
        ),
        (
            format!("{TOOL} prompt{prompt_flag}"),
            "write the setup prompt to a file",
        ),
    ] {
        println!("  {command:<44}  {what}");
    }
    0
}

/// Record one memory and return the lines to report, or why it was refused.
///
/// The MCP tool records through this same function rather than calling
/// [`stela::Store::note_valid`] itself: tag parsing, the `--private` marker and
/// the contradiction warning are behaviour, not formatting, and a second copy of
/// them would drift the moment either side changed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn note_lines(
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
) -> Result<Vec<String>, String> {
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
    let vfrom = valid_from.map(parse_when).transpose()?;
    let vuntil = valid_until.map(parse_when).transpose()?;
    let o = store
        .note_valid(
            text, kind, conf, &tags, supersedes, src, method, vfrom, vuntil,
        )
        .map_err(|e| e.to_string())?;
    let mut lines = vec![format!(
        "Saved {}{}.",
        o.id,
        if o.is_core {
            " (core - never compressed)"
        } else {
            ""
        }
    )];
    if let Some(sup) = o.superseded {
        lines.push(format!(
            "Superseded {sup}. It stays in the log; `{TOOL} history` shows it."
        ));
    }
    for (id, text) in &o.contradicts {
        lines.push(format!(
            "warning: this may contradict {id}: \"{text}\". If the truth changed, \
             record it again superseding {id}."
        ));
    }
    if o.pending > 0 {
        lines.push(format!(
            "{} block(s) now due for compression - run `{TOOL} compact` when between tasks.",
            o.pending
        ));
    }
    Ok(lines)
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
    match note_lines(
        store,
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
    ) {
        Ok(lines) => {
            for l in &lines {
                println!("{l}");
            }
            0
        }
        Err(e) => fail(&e),
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

/// What a verify run says. Shared with the MCP tool so "intact" reads the same
/// whichever caller asked, and a named failure keeps its exact record id.
pub(crate) fn verify_lines(report: &stela::VerifyReport) -> Vec<String> {
    if report.ok() {
        return vec![format!(
            "OK - {} records, every hash chain intact.",
            report.total
        )];
    }
    let mut lines = vec![format!(
        "INTEGRITY FAILURE - {} record(s) checked",
        report.total
    )];
    lines.extend(report.bad.iter().map(|b| format!("  {b}")));
    lines
}

fn cmd_verify(store: Store) -> i32 {
    match store.verify() {
        Ok(report) if report.ok() => {
            println!("{}", verify_lines(&report).join("\n"));
            0
        }
        Ok(report) => {
            eprintln!("{}", verify_lines(&report).join("\n"));
            2
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_stats(store: Store) -> i32 {
    match store.stats() {
        Ok(s) => {
            let p = Paint::for_stdout();
            println!(
                "{}      {} live / {} total",
                p.label("memories"),
                p.count(&s.live.to_string()),
                s.total
            );
            println!("{}    {}", p.label("superseded"), s.superseded);
            for (k, c) in &s.by_kind {
                println!(
                    "  {:<10}  {}   {}",
                    p.kind_name(k),
                    p.count(&c.to_string()),
                    p.dim(&format!("({})", stela::kind_help(k)))
                );
            }
            println!("{}        {}", p.label("shards"), s.shards.join(", "));
            println!(
                "{}       {:.1} MB",
                p.label("on disk"),
                s.bytes as f64 / 1e6
            );
            println!("{} {}", p.label("pending merge"), s.pending);
            // The one number that means something is wrong. Every other command
            // skips these records without a word, so this is where the silence
            // ends.
            if s.unreadable > 0 {
                println!();
                println!(
                    "{} {} record(s) on disk cannot be decrypted or parsed.",
                    p.warn("!"),
                    s.unreadable
                );
                println!("  They are missing from read, search and stats. `{TOOL} verify`");
                println!("  shows which; a store written under a different key is the");
                println!("  usual cause.");
            }
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

/// Two paths naming the same directory. Windows is case-insensitive and accepts
/// either slash, so a raw `==` would treat one directory as two; canonicalise
/// both and fall back to raw equality only when a path will not resolve.
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The user's global core, to show inside a *project* read.
///
/// Returns the machine-wide store's live core memories when the current read
/// resolves to a project store; an empty vec otherwise (a global read already
/// shows its own core, and `--global` asked for global only). Everything here is
/// best-effort and silent: if the global store is missing, locked under a key
/// this session does not hold, or unreadable, a project read simply proceeds
/// without it -- borrowing the global core must never fail or delay a read.
pub(crate) fn global_core_for_project() -> Vec<stela::Record> {
    // A global read, or an explicit `--global`, is already looking at the global
    // store -- nothing to borrow.
    if GLOBAL_ONLY.load(Ordering::Relaxed) {
        return Vec::new();
    }
    // `$VOLI_MEMORY_DIR` / `$STELA_DIR` pin the store exactly. The borrow is a
    // convenience for automatic project detection, not for a hand-picked dir, so
    // an explicit override suppresses it -- which is also what lets a test point
    // the read at a temp store without dragging in the real machine-wide core.
    if env_dir().is_some() {
        return Vec::new();
    }
    let here = memory_dir();
    let global = stela::default_memory_dir();
    // With no override, project detection resolves to the global dir only when
    // there is no project store above the cwd -- then the read already *is* the
    // global store and there is nothing to borrow. Compared canonicalised, since
    // on Windows the same directory differs by letter case or slash direction and
    // a raw `==` would inject the core twice.
    if !global.is_dir() || same_dir(&here, &global) {
        return Vec::new();
    }
    // ponytail: opens the global store fresh every read. Under keyring custody
    // that is cheap; under passphrase custody it re-runs Argon2id each time, and
    // a missing passphrase makes open_key fail here and the read proceeds without
    // the borrowed core. Cache the opened store in the MCP server if a
    // passphrase-custody global ever becomes a hot read path.
    let Ok(key) = open_key(&global) else {
        return Vec::new();
    };
    let Ok(store) = Store::open_with_key(&global, key) else {
        return Vec::new();
    };
    store.live_core().unwrap_or_default()
}

/// Load memory for the hook path, silently, whatever goes wrong.
fn read_for_hook(budget: u64, task: Option<&str>, k: usize) -> i32 {
    let dir = memory_dir();
    if !dir.is_dir() {
        return 0;
    }
    let Ok(key) = open_key(&dir) else {
        return 0;
    };
    let Ok(store) = Store::open_with_key(dir, key) else {
        return 0;
    };
    // Nothing to inject only when BOTH are empty: a freshly-`init`ed project with
    // no notes of its own must still carry the user's global core, or the hook --
    // the primary surface -- would drop the standing rules the CLI read shows.
    // The check has to include borrowed core, not just this store's.
    let extra = global_core_for_project();
    let local_empty = store.stats().map(|s| s.live == 0).unwrap_or(true);
    if local_empty && extra.is_empty() {
        return 0;
    }
    out_hook(store.render_read(budget, task, k, &extra))
}

/// The SessionStart hook payload.
///
/// `hookSpecificOutput.additionalContext` is the documented channel for putting
/// text into the model's context, and it is the whole point of this mode: the
/// model never decides whether to load memory, because the hook has already run
/// by the time it sees anything.
///
/// A failure here prints nothing and exits 0 on purpose. A hook that dies noisily
/// at session start is worse than one that quietly contributes nothing -- a
/// missing store or a locked keychain must not stop the agent from starting.
fn out_hook(r: stela::Result<stela::Disclosed>) -> i32 {
    let Ok(disclosed) = r else {
        return 0;
    };
    match hook_envelope(&disclosed.to_string()) {
        Some(payload) => println!("{payload}"),
        None => return 0,
    }
    0
}

/// Wrap loaded memory in the SessionStart envelope, or `None` when there is
/// nothing worth injecting. Split out so the shape can be asserted directly.
///
/// The memory arrives as a bare fenced block. The hook is the one path that
/// injects it straight into an agent's context with no skill or prompt
/// necessarily present, so the block cannot speak for itself -- it needs a
/// preamble that says what it is, that it is data and not orders, and how to add
/// to it. The preamble sits ABOVE the fence because it is voli talking to the
/// agent, not a memory; the containment rule is the shared `stela::CONTAINMENT`
/// so there is no fourth copy to drift from.
fn hook_envelope(body: &str) -> Option<serde_json::Value> {
    if body.trim().is_empty() {
        return None;
    }
    let context = format!(
        "This is your voli memory for this session, loaded automatically. \
         {containment}\n\n{scoping}\n\nWhen you learn a durable fact, decision or \
         preference, save it with `{TOOL} note \"<one line>\"` (add \
         `--supersedes <id>` when a stored fact has changed, `--private` for a \
         secret, `--global` when it belongs to the user rather than this \
         codebase). To reload this yourself later: `{TOOL} read`.\n\n{body}",
        containment = stela::CONTAINMENT,
        scoping = stela::SCOPING,
    );
    Some(serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }))
}

/// Which settings file the hook goes in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookTarget {
    /// Explain the choices; touch nothing.
    Explain,
    /// `~/.claude/settings.json` -- every project on this machine.
    Global,
    /// `.claude/settings.json` -- this project, committed, shared with the team.
    ProjectShared,
    /// `.claude/settings.local.json` -- this project, yours, git-ignored.
    ProjectLocal,
}

impl HookTarget {
    fn pick(global: bool, shared: bool, local: bool) -> HookTarget {
        match (global, shared, local) {
            (true, _, _) => HookTarget::Global,
            (_, true, _) => HookTarget::ProjectShared,
            (_, _, true) => HookTarget::ProjectLocal,
            _ => HookTarget::Explain,
        }
    }

    fn path(self) -> Option<PathBuf> {
        let rel = match self {
            HookTarget::Explain => return None,
            HookTarget::Global => {
                return crate::user_home().map(|h| h.join(".claude").join("settings.json"));
            }
            HookTarget::ProjectShared => "settings.json",
            HookTarget::ProjectLocal => "settings.local.json",
        };
        std::env::current_dir()
            .ok()
            .map(|d| d.join(".claude").join(rel))
    }

    fn label(self) -> &'static str {
        match self {
            HookTarget::Explain => "",
            HookTarget::Global => "every project on this machine",
            HookTarget::ProjectShared => "this project, shared with the team",
            HookTarget::ProjectLocal => "this project, just you",
        }
    }
}

/// The hook entry voli owns.
///
/// Exec form: `args` makes the harness spawn the executable directly rather than
/// hand a line to a shell, which is the rule the rest of the product follows --
/// nothing voli emits should need a shell to interpret it.
fn hook_entry() -> serde_json::Value {
    serde_json::json!({
        "type": "command",
        "command": "voli",
        "args": ["memory", "read", "--hook"],
        "timeout": 10,
        "statusMessage": "Loading voli memory"
    })
}

/// True when an entry is voli's hook, so a second run is a no-op rather than a
/// duplicate that loads memory twice.
fn is_voli_hook(entry: &serde_json::Value) -> bool {
    entry.get("command").and_then(|c| c.as_str()) == Some("voli")
        && entry
            .get("args")
            .and_then(|a| a.as_array())
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("--hook")))
}

enum Outcome {
    Added,
    Removed,
    AlreadyPresent,
    NotPresent,
}

fn cmd_hook(for_agent: &str, target: HookTarget, remove: bool) -> i32 {
    if for_agent != "claude-code" {
        eprintln!("error: no hook format known for '{for_agent}' (try: claude-code)");
        return 1;
    }
    let Some(path) = target.path() else {
        return explain_hook();
    };
    match edit_hook(&path, remove) {
        Ok(Outcome::Added) => {
            println!("added the voli memory hook to {}", path.display());
            println!("  scope: {}", target.label());
            println!("  memory now loads at the start of every session, unasked.");
            0
        }
        Ok(Outcome::Removed) => {
            println!("removed the voli memory hook from {}", path.display());
            0
        }
        Ok(Outcome::AlreadyPresent) => {
            println!("{} already has the hook - nothing to do", path.display());
            0
        }
        Ok(Outcome::NotPresent) => {
            println!("{} has no voli hook - nothing to remove", path.display());
            0
        }
        Err(e) => fail(&e),
    }
}

/// Merge the hook into (or out of) an agent settings file.
///
/// Refuses outright on malformed JSON rather than replacing it: the file is the
/// user's, it may hold hooks and permissions that took real effort, and a
/// settings file that fails to parse silently disables every setting in it.
fn edit_hook(path: &Path, remove: bool) -> Result<Outcome, String> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut root: serde_json::Value = match existing.as_deref().map(str::trim) {
        None | Some("") => serde_json::json!({}),
        Some(text) => serde_json::from_str(text).map_err(|e| {
            format!(
                "{} is not valid JSON ({e}). Refusing to touch it -- fix or move it first.",
                path.display()
            )
        })?,
    };
    let Some(obj) = root.as_object_mut() else {
        return Err(format!("{} is not a JSON object", path.display()));
    };

    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| format!("{}: hooks is not an object", path.display()))?;
    let groups = hooks
        .entry("SessionStart")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or_else(|| format!("{}: SessionStart is not an array", path.display()))?;

    let mut present = false;
    for group in groups.iter_mut() {
        if let Some(entries) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) {
            if remove {
                let before = entries.len();
                entries.retain(|e| !is_voli_hook(e));
                present |= entries.len() != before;
            } else if entries.iter().any(is_voli_hook) {
                present = true;
            }
        }
    }

    if remove {
        if !present {
            return Ok(Outcome::NotPresent);
        }
        // Drop groups this emptied, so removal leaves as little behind as a
        // shared file allows.
        groups.retain(|g| {
            g.get("hooks")
                .and_then(|h| h.as_array())
                .is_none_or(|entries| !entries.is_empty())
        });
        prune_empty(&mut root);
    } else {
        if present {
            return Ok(Outcome::AlreadyPresent);
        }
        groups.push(serde_json::json!({ "hooks": [hook_entry()] }));
    }

    write_settings(path, &root)?;
    Ok(if remove {
        Outcome::Removed
    } else {
        Outcome::Added
    })
}

/// Drop `hooks.SessionStart` and `hooks` once they hold nothing, so an uninstall
/// does not leave scaffolding behind in someone else's file.
fn prune_empty(root: &mut serde_json::Value) {
    let Some(obj) = root.as_object_mut() else {
        return;
    };
    let empty_sessionstart = obj
        .get("hooks")
        .and_then(|h| h.get("SessionStart"))
        .and_then(|s| s.as_array())
        .is_some_and(|a| a.is_empty());
    if empty_sessionstart && let Some(hooks) = obj.get_mut("hooks").and_then(|h| h.as_object_mut())
    {
        hooks.remove("SessionStart");
    }
    let empty_hooks = obj
        .get("hooks")
        .and_then(|h| h.as_object())
        .is_some_and(|h| h.is_empty());
    if empty_hooks {
        obj.remove("hooks");
    }
}

/// Parent created, temp file then rename, so a crash mid-write cannot leave a
/// half-written settings file behind.
fn write_settings(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let mut text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    text.push('\n');
    let tmp = path.with_extension("voli-tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", path.display())
    })
}

/// No target given: say what the choices are and change nothing.
fn explain_hook() -> i32 {
    println!("The session-start hook loads your memory before the agent decides");
    println!("anything, so you stop having to ask it. Pick where it should live:");
    println!();
    println!("  {TOOL} hook --project-local     this project, just you");
    println!("  {TOOL} hook --project-shared    this project, shared with the team");
    println!("  {TOOL} hook --global            every project on this machine");
    println!();
    println!("Each edits that settings file in place, keeping any hooks already");
    println!("there. Add --remove to the same command to take it back out.");
    0
}

/// Colour for a terminal, and nothing at all for anything else.
///
/// Rendered memory reaches three audiences: a person at a terminal, an agent
/// through `--hook` or MCP, and a pipe. Only the first can use escape codes --
/// inside the fence they are context an agent pays for and a parser can trip
/// over -- so painting happens here, at the edge, never in `stela`.
#[derive(Clone, Copy)]
pub(crate) struct Paint {
    on: bool,
}

impl Paint {
    /// Painted only when stdout is a terminal and colour is not switched off.
    pub(crate) fn for_stdout() -> Paint {
        Paint {
            on: crate::colors_enabled(crate::MarkStream::Stdout),
        }
    }

    fn wrap(self, code: &str, text: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn dim(self, text: &str) -> String {
        self.wrap("2", text)
    }

    fn label(self, text: &str) -> String {
        self.wrap("1", text)
    }

    fn count(self, text: &str) -> String {
        self.wrap("1;36", text)
    }

    fn warn(self, text: &str) -> String {
        self.wrap("1;33", text)
    }

    fn kind_name(self, text: &str) -> String {
        self.wrap("36", text)
    }

    /// Paint the *structure* of rendered memory: the fence, the headings, the
    /// ids you retype into other commands, dates, tags and scores.
    ///
    /// The memory text itself is left alone. It is the user's content, and
    /// colouring it would compete with the one thing colour already means here
    /// -- that a secret was masked or a private note withheld.
    pub(crate) fn memory(self, text: &str) -> String {
        if !self.on {
            return text.to_string();
        }
        text.lines()
            .map(|line| self.memory_line(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn memory_line(self, line: &str) -> String {
        if line.starts_with("<<<") {
            return self.dim(line);
        }
        if let Some(heading) = line.strip_prefix("## ") {
            return format!("{} {}", self.dim("##"), self.wrap("1", heading));
        }
        // `<mark> #<dev>:<seq> <date> <text...>` is the one shape worth taking
        // apart; anything else is prose and stays as written.
        let Some((mark, rest)) = split_mark(line) else {
            return line.to_string();
        };
        let Some((id, after_id)) = take_word(rest) else {
            return line.to_string();
        };
        if !id.starts_with('#') {
            return line.to_string();
        }
        let (date, body) = match take_word(after_id) {
            Some((d, b)) if looks_like_date(d) => (Some(d), b),
            _ => (None, after_id),
        };
        let mut out = String::new();
        out.push_str(&self.mark(mark));
        out.push(' ');
        out.push_str(&self.wrap("33", id));
        if let Some(date) = date {
            out.push(' ');
            out.push_str(&self.dim(date));
        }
        out.push(' ');
        out.push_str(&self.body(body));
        out
    }

    /// The leading glyph carries the record's standing, so it is the one thing
    /// worth telling apart at a glance.
    fn mark(self, mark: char) -> String {
        match mark {
            '*' => self.wrap("1;31", "*"), // core: never compacted
            '!' => self.wrap("33", "!"),   // pinned/notable
            '~' => self.dim("~"),          // superseded or weak match
            other => self.dim(&other.to_string()),
        }
    }

    /// Trailing `[tags]` and `(score n)` are metadata, not what was remembered.
    fn body(self, body: &str) -> String {
        let mut text = body;
        let mut suffix = String::new();
        if let Some(open) = text.rfind(" (score ")
            && text.ends_with(')')
        {
            suffix = format!("{}{}", self.dim(&text[open..]), suffix);
            text = &text[..open];
        }
        if let Some(open) = text.rfind(" [")
            && text.ends_with(']')
        {
            suffix = format!("{}{}", self.dim(&text[open..]), suffix);
            text = &text[..open];
        }
        format!("{text}{suffix}")
    }
}

/// `"* rest"` → `('*', "rest")`, for the single-glyph record markers only.
fn split_mark(line: &str) -> Option<(char, &str)> {
    let mut chars = line.chars();
    let mark = chars.next()?;
    if !matches!(mark, '*' | '!' | '~' | '-') {
        return None;
    }
    let rest = chars.as_str();
    rest.strip_prefix(' ').map(|r| (mark, r))
}

fn take_word(s: &str) -> Option<(&str, &str)> {
    let end = s.find(' ')?;
    Some((&s[..end], &s[end + 1..]))
}

/// `YYYY-MM-DD`, checked by shape so a memory that merely starts with a number
/// is not mistaken for a timestamp.
fn looks_like_date(s: &str) -> bool {
    s.len() == 10
        && s.as_bytes()[4] == b'-'
        && s.as_bytes()[7] == b'-'
        && s.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
}

/// Print a fenced, firewalled result, or the error. The [`stela::Disclosed`]
/// egress type prints via `Display`; its raw form is never exposed here.
fn out(r: stela::Result<stela::Disclosed>) -> i32 {
    match r {
        Ok(s) => {
            println!("{}", Paint::for_stdout().memory(&s.to_string()));
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn fail(msg: &str) -> i32 {
    eprintln!("error: {msg}");
    1
}

#[cfg(test)]
mod hook_tests {
    use super::hook_envelope;

    /// The harness only injects text it finds under this exact path, so the
    /// shape is the contract -- a rename here silently stops memory loading.
    #[test]
    fn the_envelope_puts_memory_where_the_harness_looks_for_it() {
        let payload = hook_envelope(
            "<<<VOLI_MEMORY_DATA>>>
knows rust
",
        )
        .expect("has body");
        let out = &payload["hookSpecificOutput"];
        assert_eq!(out["hookEventName"], "SessionStart");
        let ctx = out["additionalContext"].as_str().unwrap();
        // The memory itself is carried verbatim, inside its fence...
        assert!(ctx.contains(
            "<<<VOLI_MEMORY_DATA>>>
knows rust
"
        ));
        // ...under a preamble that says it is data, not orders, and how to add.
        assert!(ctx.contains(stela::CONTAINMENT), "containment rule missing");
        assert!(ctx.contains(stela::SCOPING), "scoping/routing rule missing");
        assert!(ctx.contains("voli memory note"), "how-to-add missing");
        // The preamble is ABOVE the fence, so a memory can never impersonate it.
        assert!(
            ctx.find(stela::CONTAINMENT).unwrap() < ctx.find("<<<VOLI_MEMORY_DATA>>>").unwrap(),
            "preamble must precede the fenced data"
        );
    }

    /// An empty store must inject nothing at all rather than an empty block,
    /// which would spend context saying there is no context.
    #[test]
    fn an_empty_read_injects_nothing() {
        assert!(hook_envelope("").is_none());
        assert!(
            hook_envelope(
                "   
	 "
            )
            .is_none()
        );
    }
}

#[cfg(test)]
mod hook_edit_tests {
    use super::{HookTarget, Outcome, edit_hook};

    fn read(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn voli_hooks(v: &serde_json::Value) -> usize {
        v["hooks"]["SessionStart"]
            .as_array()
            .map(|groups| {
                groups
                    .iter()
                    .filter_map(|g| g["hooks"].as_array())
                    .flatten()
                    .filter(|h| h["command"] == "voli")
                    .count()
            })
            .unwrap_or(0)
    }

    /// The file belongs to the user and may hold hooks and permissions that took
    /// real effort. Adding ours must not cost them any of it.
    #[test]
    fn adding_the_hook_keeps_every_setting_already_in_the_file() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"permissions":{"allow":["Bash(git *)"]},
                "hooks":{"PostToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"prettier"}]}],
                         "SessionStart":[{"hooks":[{"type":"command","command":"echo hi"}]}]}}"#,
        )
        .unwrap();

        assert!(matches!(edit_hook(&path, false), Ok(Outcome::Added)));
        let after = read(&path);
        assert_eq!(after["permissions"]["allow"][0], "Bash(git *)");
        assert_eq!(after["hooks"]["PostToolUse"][0]["matcher"], "Write");
        assert_eq!(
            after["hooks"]["SessionStart"][0]["hooks"][0]["command"],
            "echo hi"
        );
        assert_eq!(voli_hooks(&after), 1);
    }

    /// Running it twice must not load memory twice.
    #[test]
    fn adding_the_hook_twice_leaves_exactly_one() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("settings.json");
        assert!(matches!(edit_hook(&path, false), Ok(Outcome::Added)));
        assert!(matches!(
            edit_hook(&path, false),
            Ok(Outcome::AlreadyPresent)
        ));
        assert_eq!(voli_hooks(&read(&path)), 1);
    }

    /// Removal takes ours out and nothing else, and leaves no empty scaffolding
    /// where the whole file was ours.
    #[test]
    fn removing_the_hook_takes_only_ours() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo hi"}]}]}}"#,
        )
        .unwrap();
        edit_hook(&path, false).unwrap();
        assert!(matches!(edit_hook(&path, true), Ok(Outcome::Removed)));
        let after = read(&path);
        assert_eq!(voli_hooks(&after), 0);
        assert_eq!(
            after["hooks"]["SessionStart"][0]["hooks"][0]["command"],
            "echo hi"
        );
        // Nothing of ours left to remove a second time.
        assert!(matches!(edit_hook(&path, true), Ok(Outcome::NotPresent)));
    }

    /// A file that was empty before we touched it goes back to empty, rather than
    /// keeping `hooks: { SessionStart: [] }` forever.
    #[test]
    fn removing_the_only_hook_prunes_the_scaffolding_it_created() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("settings.json");
        edit_hook(&path, false).unwrap();
        edit_hook(&path, true).unwrap();
        let after = read(&path);
        assert!(after.get("hooks").is_none(), "left scaffolding: {after}");
    }

    /// A settings file that fails to parse silently disables every setting in it,
    /// so a half-understood file must be refused, not rewritten.
    #[test]
    fn malformed_json_is_refused_and_the_file_is_left_byte_for_byte() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("settings.json");
        let original = r#"{ "permissions": { "allow": ["Bash(git *)"] ,, }"#;
        std::fs::write(&path, original).unwrap();
        assert!(edit_hook(&path, false).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    /// `--global` already means the machine-wide store everywhere else in
    /// `voli memory`, so it keeps that meaning here instead of gaining a second
    /// spelling, and it wins when combined.
    #[test]
    fn the_target_flags_resolve_in_a_fixed_order() {
        assert!(matches!(
            HookTarget::pick(false, false, false),
            HookTarget::Explain
        ));
        assert!(matches!(
            HookTarget::pick(false, false, true),
            HookTarget::ProjectLocal
        ));
        assert!(matches!(
            HookTarget::pick(false, true, false),
            HookTarget::ProjectShared
        ));
        assert!(matches!(
            HookTarget::pick(true, false, false),
            HookTarget::Global
        ));
        assert!(matches!(
            HookTarget::pick(true, true, true),
            HookTarget::Global
        ));
    }
}

#[cfg(test)]
mod init_target_tests {
    use super::wants_project_store;
    use std::path::Path;

    /// `$VOLI_MEMORY_DIR` is documented as overriding everything, project
    /// detection included. When `init` defaulted to the machine-wide store this
    /// held for free; once a project store became the default, an override that
    /// lost would silently create `.voli/` in the caller's working directory.
    #[test]
    fn an_explicit_store_directory_beats_the_project_default() {
        assert!(!wants_project_store(true, Some(Path::new("/somewhere"))));
        assert!(!wants_project_store(false, Some(Path::new("/somewhere"))));
    }

    #[test]
    fn without_an_override_the_default_is_a_store_for_this_directory() {
        assert!(wants_project_store(true, None));
        // `--global` asked for the machine-wide store, so no project store.
        assert!(!wants_project_store(false, None));
    }
}

#[cfg(test)]
mod gitignore_tests {
    use super::{add_gitignore_entry, ignore_generated_prompt};

    fn ignored(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join(".gitignore")).unwrap_or_default()
    }

    #[test]
    fn an_entry_is_added_once_and_only_once() {
        let td = tempfile::tempdir().unwrap();
        assert!(add_gitignore_entry(td.path(), ".voli", ".voli/", "# c").unwrap());
        assert!(!add_gitignore_entry(td.path(), ".voli", ".voli/", "# c").unwrap());
        assert_eq!(ignored(td.path()).matches(".voli/").count(), 1);
    }

    /// The entry has to match, not merely appear: `.volirc` is a different file
    /// and must not be mistaken for an existing `.voli` rule.
    #[test]
    fn a_longer_name_starting_the_same_way_is_not_a_match() {
        let td = tempfile::tempdir().unwrap();
        std::fs::write(td.path().join(".gitignore"), ".volirc\n").unwrap();
        assert!(add_gitignore_entry(td.path(), ".voli", ".voli/", "# c").unwrap());
        let text = ignored(td.path());
        assert!(text.contains(".volirc"), "existing rule was lost: {text}");
        assert!(text.contains(".voli/"), "new rule missing: {text}");
    }

    #[test]
    fn adding_an_entry_keeps_what_was_already_ignored() {
        let td = tempfile::tempdir().unwrap();
        std::fs::write(td.path().join(".gitignore"), "target/\n*.log\n").unwrap();
        add_gitignore_entry(td.path(), ".voli", ".voli/", "# c").unwrap();
        let text = ignored(td.path());
        for kept in ["target/", "*.log", ".voli/"] {
            assert!(text.contains(kept), "{kept} missing from: {text}");
        }
    }

    /// The prompt is generated from stela, so a committed copy is a duplicate
    /// that goes stale the next time the wording changes.
    #[test]
    fn a_prompt_written_into_a_repository_is_ignored_there() {
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir(td.path().join(".git")).unwrap();
        let file = td.path().join("voli-memory-prompt.md");
        std::fs::write(&file, "prompt").unwrap();
        ignore_generated_prompt(&file);
        assert!(ignored(td.path()).contains("voli-memory-prompt*.md"));
    }

    /// Outside a repository there is nothing to ignore it in, and inventing a
    /// .gitignore in someone's home directory would be rude.
    #[test]
    fn a_prompt_written_outside_a_repository_creates_no_gitignore() {
        let td = tempfile::tempdir().unwrap();
        let file = td.path().join("voli-memory-prompt.md");
        std::fs::write(&file, "prompt").unwrap();
        ignore_generated_prompt(&file);
        assert!(!td.path().join(".gitignore").exists());
    }
}

#[cfg(test)]
mod paint_tests {
    use super::Paint;

    const SAMPLE: &str = "\
<<<VOLI_MEMORY_DATA>>>
voli memory - 2 live memories (1 core, 0 superseded).

## Core (never compressed)
* #287673:0 2026-08-01 voli is a no-admin package manager [voli,core]

## Timeline (detail decays with age)
- #287673:4 2026-08-01 the build command is cargo build --release [voli] (score 2.2)
<<<END_VOLI_MEMORY_DATA>>>";

    fn painted() -> Paint {
        Paint { on: true }
    }

    fn plain() -> Paint {
        Paint { on: false }
    }

    /// The invariant everything else rests on. The same text reaches an agent
    /// through --hook, through MCP, and through a pipe; one stray escape code in
    /// any of those is context it pays for and a parser can trip over.
    #[test]
    fn with_colour_off_the_text_is_returned_byte_for_byte() {
        assert_eq!(plain().memory(SAMPLE), SAMPLE);
        assert!(!plain().memory(SAMPLE).contains('\x1b'));

        // Lines that stress the parser, so byte-identity is a property of the
        // whole function rather than an accident of tidy sample data.
        for gnarly in [
            "- #287673:9 2026-08-01  two  spaces  inside",
            "- #287673:9 2026-08-01 trailing space ",
            "- #287673:9 not-a-date body follows",
            "-  #287673:9 2026-08-01 double space after the glyph",
            "* #287673:0",
            "~ #287673:1 2026-08-01 ••• (private, withheld)",
            "-",
            "",
        ] {
            assert_eq!(plain().memory(gnarly), gnarly, "changed: {gnarly:?}");
        }
    }

    /// Strip the escapes back out and the original must be underneath: colour is
    /// decoration, never an edit.
    #[test]
    fn painting_changes_no_text_only_its_colour() {
        let out = painted().memory(SAMPLE);
        assert!(out.contains('\x1b'), "nothing was painted");
        assert_eq!(strip_ansi(&out), SAMPLE);
    }

    #[test]
    fn the_parts_you_retype_are_the_parts_that_stand_out() {
        let out = painted().memory(SAMPLE);
        // The id is what goes into --supersedes and history, so it is coloured.
        assert!(
            out.contains("\x1b[33m#287673:0\x1b[0m"),
            "id not painted: {out}"
        );
        // A core record's glyph is distinct from an ordinary one's.
        let core = out.lines().find(|l| l.contains("#287673:0")).unwrap();
        let ordinary = out.lines().find(|l| l.contains("#287673:4")).unwrap();
        assert!(core.starts_with("\x1b[1;31m*"), "core glyph: {core}");
        assert!(
            ordinary.starts_with("\x1b[2m-"),
            "ordinary glyph: {ordinary}"
        );
    }

    /// A memory whose text happens to begin like a record must not be taken apart.
    #[test]
    fn prose_that_is_not_a_record_line_is_left_alone() {
        for line in [
            "voli memory - 2 live memories (1 core, 0 superseded).",
            "- nothing on record matches this task.",
            "* not followed by an id",
        ] {
            let out = painted().memory(line);
            assert_eq!(strip_ansi(&out), line, "text changed: {out}");
        }
    }

    /// `looks_like_date` is shape-checked so a memory starting with a number is
    /// not mistaken for a timestamp and dimmed into near-invisibility.
    #[test]
    fn only_a_real_date_is_treated_as_one() {
        assert!(super::looks_like_date("2026-08-01"));
        assert!(!super::looks_like_date("2026-8-1"));
        assert!(!super::looks_like_date("cargo-buil"));
        assert!(!super::looks_like_date("2026-08-01T"));
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c != '\x1b' {
                out.push(c);
                continue;
            }
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        }
        out
    }
}
