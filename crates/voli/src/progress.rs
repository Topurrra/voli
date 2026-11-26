//! `--progress`: one JSON event per line on stdout (schema 1), for apps that
//! drive voli and show their own progress (jnshell and the other JN apps).
//!
//! Events, in order, per package:
//!
//! ```text
//! {"event":"start","name","version"}
//! {"event":"download","name","bytes","total"}      at most ~10 a second
//! {"event":"verify","name"}  {"event":"extract","name"}
//! {"event":"installed"|"deleted","name","version","bins"}
//! {"event":"error","name","message","hint"}
//! ```
//!
//! and exactly one `{"event":"done","ok":true|false}` last. Anything for a
//! person goes to stderr while this is on, so stdout stays parseable.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use voli_core::{Action, Paths, State, Step};

/// Download events closer together than this are dropped (except the last).
const DOWNLOAD_EVERY: Duration = Duration::from_millis(100);

struct Sink {
    root: PathBuf,
    current: Option<String>,
    last_download: Option<Instant>,
    errors: usize,
    done: bool,
}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);

fn with_sink<R>(f: impl FnOnce(&mut Sink) -> R) -> Option<R> {
    let mut guard = SINK.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_mut().map(f)
}

/// Turn progress events on for this process.
pub fn enable(root: &Path) {
    let mut guard = SINK.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(Sink {
        root: root.to_path_buf(),
        current: None,
        last_download: None,
        errors: 0,
        done: false,
    });
}

pub fn enabled() -> bool {
    with_sink(|_| ()).is_some()
}

fn emit(value: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

pub fn start(name: &str, version: &str) {
    with_sink(|s| {
        s.current = Some(name.to_string());
        s.last_download = None;
        emit(&json!({ "event": "start", "name": name, "version": version }));
    });
}

fn download(done: u64, total: Option<u64>) {
    with_sink(|s| {
        let finished = total == Some(done);
        let due = s
            .last_download
            .is_none_or(|t| t.elapsed() >= DOWNLOAD_EVERY);
        if !(due || finished) {
            return;
        }
        s.last_download = Some(Instant::now());
        emit(&json!({
            "event": "download",
            "name": s.current.as_deref().unwrap_or(""),
            "bytes": done,
            "total": total,
        }));
    });
}

/// `installed`, with any extra fields (`already`, `from`, ...) merged in.
pub fn installed(name: &str, version: &str, bins: &[String], extra: Value) {
    with_sink(|_| {
        let mut v = json!({ "event": "installed", "name": name, "version": version, "bins": bins });
        merge(&mut v, extra);
        emit(&v);
    });
}

pub fn deleted(name: &str, version: &str, bins: &[String]) {
    with_sink(|_| {
        emit(&json!({ "event": "deleted", "name": name, "version": version, "bins": bins }));
    });
}

pub fn error(name: &str, problem: &crate::Problem) {
    with_sink(|s| {
        s.errors += 1;
        let mut v = json!({
            "event": "error",
            "name": name,
            "message": problem.summary,
            "hint": problem.fix,
        });
        if !problem.detail.is_empty() {
            merge(&mut v, json!({ "detail": problem.detail }));
        }
        emit(&v);
    });
}

/// The last event. A failure that never produced an `error` event (bad
/// arguments, say) gets a generic one first, so `ok:false` always has a reason.
pub fn finish(ok: bool) {
    let pending_generic = with_sink(|s| !s.done && !ok && s.errors == 0).unwrap_or(false);
    if pending_generic {
        error(
            "",
            &crate::Problem::new(
                "voli could not complete the command",
                "",
                "see the message voli printed on stderr",
            ),
        );
    }
    with_sink(|s| {
        if !s.done {
            s.done = true;
            emit(&json!({ "event": "done", "ok": ok }));
        }
    });
}

/// Map an install engine step to events.
pub fn step(step: &Step<'_>) {
    match step {
        Step::Downloading { name, version } => start(name, version),
        Step::Progress { done, total } => download(*done, *total),
        // The engine reports this once every artifact has passed its hash
        // check; extraction starts right after.
        Step::Installing { name, .. } => with_sink(|_| {
            emit(&json!({ "event": "verify", "name": name }));
            emit(&json!({ "event": "extract", "name": name }));
        })
        .unwrap_or(()),
        Step::Installed(report) => {
            let bins = bins_from_shims(&report.shims);
            installed(&report.name, &report.version, &bins, json!({}));
        }
        Step::Skipped { name, version } => {
            let bins = with_sink(|s| installed_bins(&s.root, name)).unwrap_or_default();
            installed(name, version, &bins, json!({ "already": true }));
        }
    }
}

/// Shim names from the shim file paths an install wrote (`rg.exe` -> `rg`).
pub fn bins_from_shims(shims: &[PathBuf]) -> Vec<String> {
    let mut bins: Vec<String> = shims
        .iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(str::to_string))
        .collect();
    bins.dedup();
    bins
}

/// Shim names an installed package owns, from its ledger.
pub fn installed_bins(root: &Path, name: &str) -> Vec<String> {
    let db = Paths::at(root).state_db();
    if !db.exists() {
        return Vec::new();
    }
    let Ok(state) = State::open(&db) else {
        return Vec::new();
    };
    let shims: Vec<PathBuf> = state
        .actions_for(name)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|a| match a {
            Action::ShimWritten { shim, .. } => Some(shim),
            _ => None,
        })
        .collect();
    let mut bins = bins_from_shims(&shims);
    bins.sort();
    bins.dedup();
    bins
}

fn merge(into: &mut Value, extra: Value) {
    if let (Some(dst), Value::Object(src)) = (into.as_object_mut(), extra) {
        for (k, v) in src {
            dst.insert(k, v);
        }
    }
}
