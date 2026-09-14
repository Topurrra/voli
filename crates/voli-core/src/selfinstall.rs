//! Self-install: put voli's own binaries under `<root>\bin\` and get the shims
//! dir onto the user PATH (spec §6, §11 step 5).
//!
//! Idempotent by design: binaries are updated in place (write to a `.new` file
//! then rename, moving a locked running exe aside as `.old` when needed — the
//! `.old` dance only matters on Windows, where a running image is locked), and
//! the PATH entry is added exactly once. The PATH addition is ledgered in
//! `state.sqlite` under the synthetic package `@voli` so it participates in the
//! same uninstall-by-replay machinery as everything else.
//!
//! On Windows PATH means `HKCU\Environment`; on unix the entry is recorded in
//! the env store (see `env`) and the user is told to ensure the shims dir is
//! on PATH (`install.sh` wires it into the shell profile). Env vars are never
//! written to shell rc files by voli itself.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::env;
use crate::install::{Action, exe_suffix};
use crate::paths::Paths;
use crate::state::State;

/// The synthetic package name under which voli's own PATH entry is ledgered.
pub const SELF_PACKAGE: &str = "@voli";

/// The binaries a full install lays down under `bin\` (Windows) or `bin/`
/// (unix, extensionless).
#[cfg(windows)]
const BINARIES: &[&str] = &["voli.exe", "voli-shim.exe", "voli-shim-gui.exe"];
#[cfg(not(windows))]
const BINARIES: &[&str] = &["voli", "voli-shim"];

#[derive(Debug, thiserror::Error)]
pub enum SelfInstallError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("state db error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("voli binary not found in source dir {0}")]
    SourceMissing(PathBuf),
}

/// What a self-install did.
#[derive(Debug, Clone)]
pub struct SelfInstallReport {
    pub bin_dir: PathBuf,
    pub shims_dir: PathBuf,
    /// File names actually copied into `bin\`.
    pub copied: Vec<String>,
    /// True if the shims dir was newly added to PATH (false if already present).
    pub path_added: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum SelfInstallStep {
    Binaries,
    Path,
    Finalizing,
}

/// Run self-install.
///
/// - `root`: the voli root to install into.
/// - `source_dir`: where to copy binaries from; `None` = the directory of the
///   currently running exe (its siblings). Injectable for tests.
/// - `env_subkey`: the registry env subkey to mutate ([`env::ENVIRONMENT`] in
///   production; a scratch subkey in tests).
pub fn self_install(
    root: &Path,
    source_dir: Option<&Path>,
    env_subkey: &str,
) -> Result<SelfInstallReport, SelfInstallError> {
    self_install_with_steps(root, source_dir, env_subkey, &mut |_| {})
}

pub fn self_install_with_steps(
    root: &Path,
    source_dir: Option<&Path>,
    env_subkey: &str,
    on_step: &mut dyn FnMut(SelfInstallStep),
) -> Result<SelfInstallReport, SelfInstallError> {
    let paths = Paths::at(root);
    paths.ensure()?; // apps, shims, cache, db

    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir)?;

    let src = match source_dir {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe()?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| io::Error::other("cannot locate current exe directory"))?,
    };

    // Copy whichever binaries exist; the voli binary itself is mandatory.
    on_step(SelfInstallStep::Binaries);
    let mut copied = Vec::new();
    for name in BINARIES {
        let from = src.join(name);
        if from.is_file() {
            let dst = bin_dir.join(name);
            replace_file(&from, &dst)?;
            #[cfg(not(windows))]
            mark_executable(&dst)?;
            copied.push((*name).to_string());
        }
    }
    let voli_bin = format!("voli{}", exe_suffix());
    if !copied.contains(&voli_bin) {
        return Err(SelfInstallError::SourceMissing(src));
    }

    // Put shims on the user PATH (prepend, idempotent). On Windows this edits
    // HKCU\Environment; on unix it records the entry in the env store and
    // install.sh / the shell profile makes it effective.
    on_step(SelfInstallStep::Path);
    let shims_dir = paths.shims();
    let shims_str = shims_dir.to_string_lossy().into_owned();
    let prior = env::add_to_path(env_subkey, &shims_str)?;
    let path_added = !prior
        .as_deref()
        .map(|p| env::path_has_segment(p, &shims_str))
        .unwrap_or(false);

    // Shim voli itself: only the shims dir is on PATH, and the voli binary
    // lives in bin — without this, `voli` is not resolvable in any shell
    // (launch-day bug).
    on_step(SelfInstallStep::Finalizing);
    let stub = bin_dir.join(format!("voli-shim{}", exe_suffix()));
    if stub.is_file() {
        fs::write(
            shims_dir.join("voli.shim"),
            shim_body_for(&bin_dir.join(&voli_bin)),
        )?;
        let shim_exe = shims_dir.join(format!("voli{}", exe_suffix()));
        replace_file(&stub, &shim_exe)?;
        #[cfg(not(windows))]
        mark_executable(&shim_exe)?;
    }

    // Ledger the PATH entry + self-shim under @voli, once.
    let mut state = State::open(&paths.state_db())?;
    if !state.is_installed(SELF_PACKAGE)? {
        let actions = [
            Action::PathAdded {
                segment: shims_str.clone(),
            },
            Action::ShimWritten {
                shim: shims_dir.join("voli.shim"),
                exe: shims_dir.join(format!("voli{}", exe_suffix())),
            },
        ];
        let manifest_json = format!("{{\"name\":\"{SELF_PACKAGE}\"}}");
        state.record_install(
            SELF_PACKAGE,
            env!("CARGO_PKG_VERSION"),
            &manifest_json,
            &actions,
        )?;
    }

    env::broadcast_change();

    Ok(SelfInstallReport {
        bin_dir,
        shims_dir,
        copied,
        path_added,
    })
}

/// Copy `src` over `dst`, coping with `dst` being a running (locked) exe.
///
/// Strategy: stage to `dst`+`.new`, try a direct atomic replace, and if that
/// fails (sharing violation on a running exe — Windows only) move the running
/// `dst` aside to `.old` first. The `.old` file may itself be locked (it's the
/// running process) so it is left for `voli cleanup` — same pattern as stale
/// version dirs (spec §3). On unix the rename always succeeds; the `.old`
/// path is dead code kept for symmetry.
fn replace_file(src: &Path, dst: &Path) -> io::Result<()> {
    // ponytail: skip work when source and destination are the same file
    // (self-install re-run from bin\voli.exe).
    if same_file(src, dst) {
        return Ok(());
    }

    let staged = with_suffix(dst, "new");
    fs::copy(src, &staged)?;

    if dst.exists() {
        if fs::rename(&staged, dst).is_ok() {
            return Ok(());
        }
        // Direct replace failed (dst locked): move it aside, then swap in.
        let old = with_suffix(dst, "old");
        let _ = fs::remove_file(&old);
        fs::rename(dst, &old)?;
        fs::rename(&staged, dst)?;
    } else {
        fs::rename(&staged, dst)?;
    }
    Ok(())
}

/// `path` with `.<suffix>` appended (keeps the original extension in the stem,
/// so `voli.exe` → `voli.exe.new`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(suffix);
    PathBuf::from(s)
}

/// Render the `voli.shim` body pointing at the installed voli binary.
/// `\r\n` on Windows, `\n` on unix (the shim parser accepts both).
fn shim_body_for(target: &Path) -> String {
    #[cfg(windows)]
    {
        format!("{}\r\n", target.display())
    }
    #[cfg(not(windows))]
    {
        format!("{}\n", target.display())
    }
}

/// `chmod +x` on unix; no-op on Windows.
#[cfg(not(windows))]
fn mark_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(perms.mode() | 0o111);
    fs::set_permissions(path, perms)
}

/// True if both paths resolve to the same existing file.
fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}
