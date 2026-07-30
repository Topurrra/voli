//! Integration tests for the transactional install/uninstall engine (§11 step 3).
//!
//! Each test gets an isolated tempdir root. Fixture zips are built in-process.
//! The shim stub is a dummy file pointed at by `VOLI_SHIM_STUB` (set once,
//! process-wide, guarded by a `Once`); if a real `voli-shim.exe` has been built
//! we prefer that.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Once;

use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use sha2::{Digest, Sha256};
use voli_core::{InstallError, State, install_local, uninstall};
use zip::write::SimpleFileOptions;

static STUB: Once = Once::new();

/// Ensure a shim stub exists and `VOLI_SHIM_STUB` points at it. Prefer a real
/// built voli-shim.exe next to the test binary; otherwise drop a dummy file.
fn ensure_stub() {
    STUB.call_once(|| {
        // target/debug/voli-shim.exe sits next to the test exe's parent.
        let real = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .and_then(|deps| deps.parent().map(|d| d.join("voli-shim.exe")))
            .filter(|p| p.exists());
        let stub = real.unwrap_or_else(|| {
            let p = std::env::temp_dir().join("voli-test-shim-stub.exe");
            fs::write(&p, b"dummy shim stub").unwrap();
            p
        });
        // SAFETY: set once, before any install runs; tests only ever read it.
        unsafe { std::env::set_var("VOLI_SHIM_STUB", stub) };
    });
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a zip in memory from (entry-name, contents) pairs. A name ending in
/// `/` is a directory entry.
fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            if name.ends_with('/') {
                w.add_directory(*name, opts).unwrap();
            } else {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
        }
        w.finish().unwrap();
    }
    buf
}

/// Build a 7z in memory from (entry-name, contents) pairs. A name ending in
/// `/` is a directory entry.
fn build_7z(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
    for (name, data) in entries {
        let is_dir = name.ends_with('/');
        let entry = ArchiveEntry {
            name: name.to_string(),
            has_stream: !is_dir,
            is_directory: is_dir,
            ..Default::default()
        };
        if is_dir {
            w.push_archive_entry::<&[u8]>(entry, None).unwrap();
        } else {
            w.push_archive_entry(entry, Some(*data)).unwrap();
        }
    }
    w.finish().unwrap().into_inner()
}

/// A standard fixture: ripgrep 1.0.0, wrapper dir stripped, one bin, one persist
/// dir carrying a file.
fn ripgrep_zip() -> Vec<u8> {
    build_zip(&[
        ("ripgrep-1.0.0/", b""),
        ("ripgrep-1.0.0/rg.exe", b"fake rg binary"),
        ("ripgrep-1.0.0/config/", b""),
        ("ripgrep-1.0.0/config/settings.txt", b"user=neo"),
    ])
}

/// Same fixture as [`ripgrep_zip`] but in 7z format.
fn ripgrep_7z() -> Vec<u8> {
    build_7z(&[
        ("ripgrep-1.0.0/", b""),
        ("ripgrep-1.0.0/rg.exe", b"fake rg binary"),
        ("ripgrep-1.0.0/config/", b""),
        ("ripgrep-1.0.0/config/settings.txt", b"user=neo"),
    ])
}

fn write_manifest(dir: &Path, sha256: &str) -> PathBuf {
    let toml = format!(
        r#"
name = "ripgrep"
version = "1.0.0"
kind = "app"
extract_dir = "ripgrep-1.0.0"
bin = ["rg.exe"]
persist = ["config"]

[source.x64]
url = "https://example.com/rg.zip"
sha256 = "{sha256}"
"#
    );
    let p = dir.join("ripgrep.toml");
    fs::write(&p, toml).unwrap();
    p
}

fn write_installer_manifest(dir: &Path, sha256: &str) -> PathBuf {
    let toml = format!(
        r#"
name = "ripgrep"
version = "1.0.0"
kind = "app"
extract_dir = "ripgrep-1.0.0"
bin = ["rg.exe"]

[source.x64]
url = "https://example.com/setup.exe"
sha256 = "{sha256}"
kind = "installer-archive"
"#
    );
    let p = dir.join("installer.toml");
    fs::write(&p, toml).unwrap();
    p
}

fn system_7z_available() -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join("7z.exe").is_file()))
        .unwrap_or(false)
        || [
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
        ]
        .iter()
        .any(|path| Path::new(path).is_file())
}

/// Recursively snapshot a tree as relative-path -> Some(bytes) for files or
/// None for dirs. Used to prove rollback leaves the root byte-identical.
fn snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let path = e.path();
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if e.file_type().unwrap().is_dir() {
                out.insert(rel, None);
                walk(base, &path, out);
            } else {
                out.insert(rel, Some(fs::read(&path).unwrap()));
            }
        }
    }
    walk(root, root, &mut out);
    out
}

/// Binary-wide scratch locations for the process-global env hooks, set ONCE
/// before any install runs and never removed. Without this, tests that install
/// while `VOLI_UNINSTALL_SUBKEY` is unset write to the user's REAL Apps &
/// Features registry (found polluted 2026-07-24), and any test that flips the
/// vars mid-run races every parallel sibling.
fn scratch_global_env() -> std::path::PathBuf {
    static INIT: std::sync::Once = std::sync::Once::new();
    let dir = std::env::temp_dir().join("voli-test-shortcuts-installbin");
    INIT.call_once(|| {
        let _ = std::fs::create_dir_all(&dir);
        // SAFETY: set once before any reader thread, same value for the whole
        // test binary, never mutated again.
        unsafe {
            std::env::set_var("VOLI_UNINSTALL_SUBKEY", "Software\\voli-scratch-installbin");
            std::env::set_var("VOLI_SHORTCUT_DIR", &dir);
        }
    });
    dir
}

fn setup() -> tempfile::TempDir {
    scratch_global_env();
    ensure_stub();
    tempfile::tempdir().unwrap()
}

#[test]
fn happy_path_install() {
    let td = setup();
    let root = td.path();
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&zip));

    let report = install_local(&manifest, &archive, root).expect("install should succeed");

    // Version dir + payload.
    let vdir = root.join("apps/ripgrep/1.0.0");
    assert!(vdir.join("rg.exe").is_file());
    assert_eq!(report.version_dir, vdir);

    // current junction resolves to the version dir.
    let current = root.join("apps/ripgrep/current");
    assert!(junction::exists(&current).unwrap());
    assert!(current.join("rg.exe").is_file());

    // Shim pair, target points through current\.
    let shim = root.join("shims/rg.shim");
    let shim_exe = root.join("shims/rg.exe");
    assert!(shim.is_file());
    assert!(shim_exe.is_file());
    let body = fs::read_to_string(&shim).unwrap();
    let first = body.lines().next().unwrap();
    assert!(
        first.ends_with("current\\rg.exe"),
        "shim target was {first}"
    );

    // persist: data moved out, junctioned back in.
    let persisted = root.join("apps/ripgrep/persist/config/settings.txt");
    assert_eq!(fs::read_to_string(&persisted).unwrap(), "user=neo");
    assert!(junction::exists(vdir.join("config")).unwrap());
    assert_eq!(
        fs::read_to_string(vdir.join("config/settings.txt")).unwrap(),
        "user=neo"
    );

    // Ledger.
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    let list = state.list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "ripgrep");
    assert!(!state.actions_for("ripgrep").unwrap().is_empty());

    // No staging leftovers.
    let staging: Vec<_> = fs::read_dir(root.join("cache")).unwrap().collect();
    assert!(staging.is_empty(), "cache should have no staging dirs");
}

#[test]
fn hash_mismatch_mutates_nothing() {
    let td = setup();
    let root = td.path();
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    // Wrong hash.
    let manifest = write_manifest(root, &"a".repeat(64));

    let err = install_local(&manifest, &archive, root).unwrap_err();
    assert!(matches!(err, InstallError::HashMismatch { .. }));

    assert!(!root.join("apps/ripgrep").exists());
    assert!(!root.join("shims/rg.shim").exists());
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(state.list().unwrap().is_empty());
}

#[test]
fn zip_slip_rejected_mutates_nothing() {
    let td = setup();
    let root = td.path();
    // Malicious entry escapes the extraction root.
    let zip = build_zip(&[("../evil.exe", b"pwned"), ("ripgrep-1.0.0/rg.exe", b"x")]);
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    // Real hash so we pass the gate and actually reach extraction.
    let manifest = write_manifest(root, &sha256_hex(&zip));

    let err = install_local(&manifest, &archive, root).unwrap_err();
    assert!(matches!(err, InstallError::ZipSlip(_)), "got {err:?}");

    assert!(!root.join("apps/ripgrep").exists());
    assert!(!root.join("evil.exe").exists());
    assert!(!root.parent().unwrap().join("evil.exe").exists());
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(state.list().unwrap().is_empty());
}

/// A drive prefix is only a `Component::Prefix` when it LEADS the path. Mid-path
/// it parsed as a normal component, and `PathBuf::push` of a drive-prefixed
/// component RESETS the buffer — so `dest.join(safe_rel("sub/C:/evil.exe"))` was
/// literally `C:evil.exe`, written drive-relative to the process working dir.
#[test]
fn drive_prefixed_entry_rejected_mutates_nothing() {
    let td = setup();
    let root = td.path();
    let zip = build_zip(&[
        ("sub/C:/evil.exe", b"pwned"),
        ("ripgrep-1.0.0/rg.exe", b"x"),
    ]);
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&zip));

    let err = install_local(&manifest, &archive, root).unwrap_err();
    assert!(matches!(err, InstallError::ZipSlip(_)), "got {err:?}");

    // The escape target: drive-relative to the CWD, i.e. <cwd-drive>\...\evil.exe.
    let escaped = std::env::current_dir().unwrap().join("evil.exe");
    assert!(!escaped.exists(), "entry escaped to {}", escaped.display());
    assert!(!root.join("apps/ripgrep").exists());
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(state.list().unwrap().is_empty());
}

#[test]
fn failure_mid_install_rolls_back_byte_identical() {
    let td = setup();
    let root = td.path();
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&zip));

    // Materialize the root exactly as install would find it, then poison the
    // shim write: a *directory* named rg.shim makes fs::write(rg.shim) fail,
    // after the version dir + junctions are already created.
    voli_core::Paths::at(root).ensure().unwrap();
    drop(State::open(&root.join("db/state.sqlite")).unwrap());
    fs::create_dir_all(root.join("shims/rg.shim")).unwrap();

    let before = snapshot(root);

    let err = install_local(&manifest, &archive, root).unwrap_err();
    // The poisoned shim write surfaces as an IO error.
    assert!(matches!(err, InstallError::Io(_)), "got {err:?}");

    let after = snapshot(root);
    assert_eq!(before, after, "rollback must leave the root byte-identical");
}

#[test]
fn uninstall_leaves_zero_trace_but_keeps_persist() {
    let td = setup();
    let root = td.path();
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&zip));

    install_local(&manifest, &archive, root).unwrap();
    let report = uninstall("ripgrep", root, false).unwrap();
    assert!(report.kept_persist);

    // Everything gone except persist.
    assert!(!root.join("apps/ripgrep/1.0.0").exists());
    assert!(!root.join("apps/ripgrep/current").exists());
    assert!(!root.join("shims/rg.shim").exists());
    assert!(!root.join("shims/rg.exe").exists());
    // persist survives with its data intact.
    assert_eq!(
        fs::read_to_string(root.join("apps/ripgrep/persist/config/settings.txt")).unwrap(),
        "user=neo"
    );

    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(state.list().unwrap().is_empty());
    assert!(state.actions_for("ripgrep").unwrap().is_empty());
}

/// A locked/undeletable file must NOT be reported as a successful uninstall.
/// Dropping the ledger row while files survive strands them: `voli delete` then
/// says NotInstalled and `cleanup` iterates the ledger, so nothing shipped can
/// ever reach them again.
#[test]
fn uninstall_that_cannot_remove_files_keeps_the_ledger_row() {
    let td = setup();
    let root = td.path();
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&zip));

    install_local(&manifest, &archive, root).unwrap();

    // Stand in for "the app is running": hold the payload open with no sharing
    // at all, so every delete of it fails with a sharing violation.
    let locked = root.join("apps/ripgrep/1.0.0/rg.exe");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&locked)
        .unwrap();

    let err = uninstall("ripgrep", root, false).unwrap_err();
    match &err {
        InstallError::UninstallIncomplete { name, remaining } => {
            assert_eq!(name, "ripgrep");
            assert!(remaining.iter().any(|p| p.ends_with("1.0.0")));
        }
        other => panic!("expected UninstallIncomplete, got {other:?}"),
    }

    // Files are still there, and so is the ledger row that knows about them.
    assert!(locked.exists());
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert_eq!(
        state.installed_version("ripgrep").unwrap().as_deref(),
        Some("1.0.0")
    );
    assert!(!state.actions_for("ripgrep").unwrap().is_empty());
    drop(state);

    // Once the file is free, the same command finishes the job.
    drop(handle);
    uninstall("ripgrep", root, true).unwrap();
    assert!(!root.join("apps/ripgrep").exists());
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(state.list().unwrap().is_empty());
}

#[test]
fn uninstall_purge_removes_everything() {
    let td = setup();
    let root = td.path();
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&zip));

    install_local(&manifest, &archive, root).unwrap();
    uninstall("ripgrep", root, true).unwrap();

    assert!(
        !root.join("apps/ripgrep").exists(),
        "purge removes the app dir entirely"
    );
}

#[test]
fn double_install_is_a_clean_error() {
    // Documented choice: re-installing an installed package errors (no mutation),
    // rather than an idempotent reinstall.
    let td = setup();
    let root = td.path();
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&zip));

    install_local(&manifest, &archive, root).unwrap();
    let err = install_local(&manifest, &archive, root).unwrap_err();
    assert!(
        matches!(err, InstallError::AlreadyInstalled(_)),
        "got {err:?}"
    );

    // Still exactly one install.
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert_eq!(state.list().unwrap().len(), 1);
}

#[test]
fn uninstall_unknown_package_errors() {
    let td = setup();
    let err = uninstall("nope", td.path(), false).unwrap_err();
    assert!(matches!(err, InstallError::NotInstalled(_)));
}

#[test]
fn happy_path_install_7z() {
    let td = setup();
    let root = td.path();
    let sz = ripgrep_7z();
    let archive = root.join("rg.7z");
    fs::write(&archive, &sz).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&sz));

    let report = install_local(&manifest, &archive, root).expect("install should succeed");

    let vdir = root.join("apps/ripgrep/1.0.0");
    assert!(vdir.join("rg.exe").is_file());
    assert_eq!(report.version_dir, vdir);

    let current = root.join("apps/ripgrep/current");
    assert!(junction::exists(&current).unwrap());
    assert!(current.join("rg.exe").is_file());

    let shim = root.join("shims/rg.shim");
    let shim_exe = root.join("shims/rg.exe");
    assert!(shim.is_file());
    assert!(shim_exe.is_file());
    let body = fs::read_to_string(&shim).unwrap();
    let first = body.lines().next().unwrap();
    assert!(
        first.ends_with("current\\rg.exe"),
        "shim target was {first}"
    );

    let persisted = root.join("apps/ripgrep/persist/config/settings.txt");
    assert_eq!(fs::read_to_string(&persisted).unwrap(), "user=neo");
    assert!(junction::exists(vdir.join("config")).unwrap());
    assert_eq!(
        fs::read_to_string(vdir.join("config/settings.txt")).unwrap(),
        "user=neo"
    );

    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    let list = state.list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "ripgrep");

    let staging: Vec<_> = fs::read_dir(root.join("cache")).unwrap().collect();
    assert!(staging.is_empty(), "cache should have no staging dirs");
}

#[test]
fn installer_archive_extracts_and_uninstalls_cleanly() {
    if !system_7z_available() {
        eprintln!("skipped: 7-Zip is not installed");
        return;
    }

    let td = setup();
    let root = td.path();
    let archive_bytes = ripgrep_7z();
    let archive = root.join("setup.exe");
    fs::write(&archive, &archive_bytes).unwrap();
    let manifest = write_installer_manifest(root, &sha256_hex(&archive_bytes));

    install_local(&manifest, &archive, root).expect("installer archive should extract");
    assert!(root.join("apps/ripgrep/current/rg.exe").is_file());

    uninstall("ripgrep", root, true).unwrap();
    assert!(!root.join("apps/ripgrep").exists());
    assert!(!root.join("shims/rg.shim").exists());
}

#[test]
fn zip_slip_7z_rejected_mutates_nothing() {
    let td = setup();
    let root = td.path();
    let sz = build_7z(&[("../evil.exe", b"pwned"), ("ripgrep-1.0.0/rg.exe", b"x")]);
    let archive = root.join("rg.7z");
    fs::write(&archive, &sz).unwrap();
    let manifest = write_manifest(root, &sha256_hex(&sz));

    let err = install_local(&manifest, &archive, root).unwrap_err();
    assert!(matches!(err, InstallError::ZipSlip(_)), "got {err:?}");

    assert!(!root.join("apps/ripgrep").exists());
    assert!(!root.join("evil.exe").exists());
    assert!(!root.parent().unwrap().join("evil.exe").exists());
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(state.list().unwrap().is_empty());
}

// ---- kind = "binary": one bare .exe, no archive ----
//
// The payload is a COPY OF THE SHIM STUB, which is a real exe whenever
// voli-shim has been built. That makes the installed `jq.exe` runnable, so
// `shims\jq.exe` can actually be executed: it launches the version dir's copy,
// which — being a shim with no `.shim` beside it — fails with 9009 naming its
// own sibling. Nothing but a correctly resolved chain produces that.

const BINARY_PAYLOAD_V1: &[u8] = b"MZ fake jq 1.0.0";

/// A real executable to install, when one is available (see `ensure_stub`).
fn runnable_payload() -> Option<Vec<u8>> {
    let stub = std::env::var_os("VOLI_SHIM_STUB")?;
    let bytes = fs::read(stub).ok()?;
    bytes.starts_with(b"MZ").then_some(bytes)
}

/// jq-style manifest: a single downloaded file, renamed to what belongs on PATH.
/// The URL basename (`jq-windows-amd64.exe`) is deliberately NOT the bin name.
fn write_binary_manifest(dir: &Path, version: &str, sha256: &str) -> PathBuf {
    let toml = format!(
        r#"
name = "jqbin"
version = "{version}"
kind = "app"
file_name = "jq.exe"
bin = ["jq.exe"]

[source.x64]
url = "https://example.com/download/jq-windows-amd64.exe"
sha256 = "{sha256}"
kind = "binary"
"#
    );
    let p = dir.join(format!("jqbin-{version}.toml"));
    fs::write(&p, toml).unwrap();
    p
}

#[test]
fn binary_source_installs_a_bare_exe_and_shims_it() {
    let td = setup();
    let root = td.path();
    let payload = runnable_payload().unwrap_or_else(|| BINARY_PAYLOAD_V1.to_vec());
    let download = root.join("jq-windows-amd64.exe");
    fs::write(&download, &payload).unwrap();
    let manifest = write_binary_manifest(root, "1.0.0", &sha256_hex(&payload));

    let report = install_local(&manifest, &download, root).expect("install should succeed");

    // The version dir holds exactly the one file, under the manifest's name —
    // not the URL's.
    let vdir = root.join("apps/jqbin/1.0.0");
    assert_eq!(report.version_dir, vdir);
    assert_eq!(fs::read(vdir.join("jq.exe")).unwrap(), payload);
    let entries: Vec<_> = fs::read_dir(&vdir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["jq.exe".to_string()]);
    assert!(!vdir.join("jq-windows-amd64.exe").exists());

    // Same transaction as an archive: current junction, shim pair, ledger.
    let current = root.join("apps/jqbin/current");
    assert!(junction::exists(&current).unwrap());
    let shim = root.join("shims/jq.shim");
    let shim_exe = root.join("shims/jq.exe");
    assert!(shim_exe.is_file());
    let first = fs::read_to_string(&shim).unwrap();
    let first = first.lines().next().unwrap().to_string();
    assert!(
        first.ends_with("current\\jq.exe"),
        "shim target was {first}"
    );
    assert!(Path::new(&first).is_file(), "shim target must resolve");
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert_eq!(state.list().unwrap().len(), 1);
    drop(state);

    // The download is left in the cache, not consumed.
    assert_eq!(fs::read(&download).unwrap(), payload);

    // Run it for real when the stub is a genuine shim exe.
    if runnable_payload().is_some() {
        let out = std::process::Command::new(&shim_exe).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(9009), "stderr: {stderr}");
        assert!(
            stderr.contains("jqbin") && stderr.contains("jq.shim"),
            "the shim must launch the installed copy, not itself: {stderr}"
        );
    }
}

#[test]
fn binary_hash_mismatch_mutates_nothing() {
    let td = setup();
    let root = td.path();
    let download = root.join("jq-windows-amd64.exe");
    fs::write(&download, BINARY_PAYLOAD_V1).unwrap();
    let manifest = write_binary_manifest(root, "1.0.0", &"a".repeat(64));

    let err = install_local(&manifest, &download, root).unwrap_err();
    assert!(matches!(err, InstallError::HashMismatch { .. }), "{err:?}");

    assert!(!root.join("apps/jqbin").exists());
    assert!(!root.join("shims/jq.shim").exists());
    assert!(!root.join("shims/jq.exe").exists());
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(state.list().unwrap().is_empty());
}

#[test]
fn binary_uninstall_leaves_zero_trace() {
    let td = setup();
    let root = td.path();
    let download = root.join("jq-windows-amd64.exe");
    fs::write(&download, BINARY_PAYLOAD_V1).unwrap();
    let manifest = write_binary_manifest(root, "1.0.0", &sha256_hex(BINARY_PAYLOAD_V1));

    // Materialize the root exactly as install finds it, so the comparison is of
    // the install's own footprint.
    voli_core::Paths::at(root).ensure().unwrap();
    drop(State::open(&root.join("db/state.sqlite")).unwrap());
    let mut before = snapshot(root);

    install_local(&manifest, &download, root).unwrap();
    let report = uninstall("jqbin", root, false).unwrap();
    assert!(!report.kept_persist);

    let mut after = snapshot(root);
    // The sqlite file's bytes move with any write, even one that is fully
    // undone; every other path must match byte for byte.
    for tree in [&mut before, &mut after] {
        tree.retain(|path, _| !path.starts_with("db"));
    }
    assert_eq!(before, after, "uninstall must leave zero trace");
}

/// The per-arch `extract_dir` override, end to end through the real install
/// path, plus the zero-trace uninstall on top of it.
///
/// The top-level `extract_dir` is deliberately WRONG (that wrapper is not in the
/// archive) and `[source.x64]` carries the right one. Before per-arch
/// `extract_dir` existed, this install died with `ExtractDirMissing` after the
/// archive was already extracted.
///
/// Host-independent by construction: the manifest is x64-only, so an arm64 dev
/// box selects the same source (reporting a `Missing` fallback) and resolves the
/// same override. Selecting arm64 itself is covered by the pure policy tests in
/// `manifest.rs`, which take the host arch as an argument.
#[test]
fn per_arch_extract_dir_installs_and_uninstalls_cleanly() {
    let td = setup();
    let root = td.path();
    let zip = build_zip(&[
        ("arch-1.0.0/", b""),
        ("arch-1.0.0/rg.exe", b"fake rg binary"),
    ]);
    let archive = root.join("arch.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest_path = root.join("archpkg.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
name = "archpkg"
version = "1.0.0"
kind = "app"
extract_dir = "arch-1.0.0-x86_64-pc-windows-msvc"
bin = ["rg.exe"]

[source.x64]
url = "https://example.com/arch.zip"
sha256 = "{}"
extract_dir = "arch-1.0.0"
"#,
            sha256_hex(&zip)
        ),
    )
    .unwrap();

    voli_core::Paths::at(root).ensure().unwrap();
    drop(State::open(&root.join("db/state.sqlite")).unwrap());
    let mut before = snapshot(root);

    let report = install_local(&manifest_path, &archive, root).expect("per-arch install");
    assert_eq!(report.arch, voli_core::Arch::X64);
    assert!(
        report.arch_note().starts_with("x64"),
        "the arch decision must be reported: {}",
        report.arch_note()
    );
    assert!(root.join("apps/archpkg/1.0.0/rg.exe").is_file());
    assert!(root.join("shims/rg.exe").is_file());

    uninstall("archpkg", root, false).unwrap();
    let mut after = snapshot(root);
    for tree in [&mut before, &mut after] {
        tree.retain(|path, _| !path.starts_with("db"));
    }
    assert_eq!(before, after, "uninstall must leave zero trace");
}

#[test]
fn binary_upgrade_flips_the_junction() {
    let td = setup();
    let root = td.path();
    let v1 = BINARY_PAYLOAD_V1;
    let v2 = b"MZ fake jq 2.0.0";
    let d1 = root.join("jq-1.exe");
    let d2 = root.join("jq-2.exe");
    fs::write(&d1, v1).unwrap();
    fs::write(&d2, v2).unwrap();

    let m1 = write_binary_manifest(root, "1.0.0", &sha256_hex(v1));
    install_local(&m1, &d1, root).unwrap();

    let m2 = voli_core::Manifest::from_toml_str(
        &fs::read_to_string(write_binary_manifest(root, "2.0.0", &sha256_hex(v2))).unwrap(),
    )
    .unwrap();
    let up = voli_core::upgrade_install(&m2, &d2, &[], root).unwrap();
    assert_eq!(up.from_version, "1.0.0");

    // current follows the new version; the old dir survives for `cleanup`.
    let current = root.join("apps/jqbin/current");
    assert_eq!(fs::read(current.join("jq.exe")).unwrap(), v2);
    assert_eq!(
        fs::read(root.join("apps/jqbin/1.0.0/jq.exe")).unwrap(),
        v1,
        "the old version dir stays until cleanup"
    );
    // The shim never changed — it points through current\.
    let first = fs::read_to_string(root.join("shims/jq.shim")).unwrap();
    assert!(first.lines().next().unwrap().ends_with("current\\jq.exe"));

    // Uninstall still removes every version dir.
    uninstall("jqbin", root, false).unwrap();
    assert!(!root.join("apps/jqbin").exists());
}

// ---- shortcut + Apps & Features integration test ----
// These mutate process-global env vars (VOLI_UNINSTALL_SUBKEY,
// VOLI_SHORTCUT_DIR), so they run as ONE test to avoid racing with
// each other and with other install tests in this binary.

fn write_manifest_with_shortcuts(dir: &Path, sha256: &str) -> PathBuf {
    // Unique package name: other tests in this binary install "ripgrep", and
    // the A&F registry base is now binary-wide — assertions here must not see
    // their keys come and go.
    let toml = format!(
        r#"
name = "rgshort"
version = "1.0.0"
kind = "app"
extract_dir = "ripgrep-1.0.0"
bin = ["rg.exe"]
shortcuts = ["rg.exe"]

[source.x64]
url = "https://example.com/rg.zip"
sha256 = "{sha256}"
"#
    );
    let p = dir.join("rgshort.toml");
    fs::write(&p, toml).unwrap();
    p
}

/// A shortcut name may nest: `Vendor\App` is a Start Menu subfolder, which
/// several published packages use (`Proton\Proton Pass`,
/// `Adventure Game Studio\AGS Editor`). Only the top-level Start Menu dir used
/// to be created, so those packages failed at install; and the subfolder must be
/// pruned on uninstall or it breaks zero-trace.
///
/// (The PowerShell-injection guard now lives in `install.rs` as a unit test on
/// `create_shortcut` itself — the manifest layer rejects `$` and a backtick, so
/// such a name can no longer reach an install.)
#[test]
fn nested_shortcut_creates_and_prunes_its_subfolder() {
    let td = setup();
    let root = td.path();
    let shortcut_dir = scratch_global_env();

    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    // Forward slash keeps the TOML free of escapes; the validator and the join
    // treat `/` and `\` identically, and real manifests use the latter.
    let name = "Vendor Co/My App (x64)";
    let toml = format!(
        r#"
name = "rglnk"
version = "1.0.0"
kind = "app"
extract_dir = "ripgrep-1.0.0"
bin = ["rg.exe"]
shortcuts = [{{ target = "rg.exe", name = "{name}" }}]

[source.x64]
url = "https://example.com/rg.zip"
sha256 = "{}"
"#,
        sha256_hex(&zip)
    );
    let manifest = root.join("rglnk.toml");
    fs::write(&manifest, toml).unwrap();

    install_local(&manifest, &archive, root).expect("install should succeed");

    let lnk = shortcut_dir.join(format!("{name}.lnk"));
    let subfolder = lnk.parent().unwrap().to_path_buf();
    assert!(
        lnk.is_file(),
        "nested shortcut should be created verbatim; {} is missing",
        lnk.display()
    );
    assert!(subfolder.is_dir(), "the Start Menu subfolder should exist");

    uninstall("rglnk", root, true).unwrap();
    assert!(!lnk.exists());
    assert!(
        !subfolder.exists(),
        "the subfolder we created must be pruned — zero trace"
    );
    assert!(
        shortcut_dir.is_dir(),
        "pruning must never climb past our own Start Menu dir"
    );
}

#[test]
fn shortcut_and_apps_features_lifecycle() {
    use voli_core::uninstall_reg;

    let td = setup();
    let root = td.path();

    // Binary-wide scratch env (set once in setup()) — never flipped mid-run,
    // so parallel sibling tests can't race between real and scratch registry.
    let shortcut_dir = scratch_global_env();
    let sk = "Software\\voli-scratch-installbin";

    // --- Part 1: shortcut created on install, removed on uninstall ---
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest_with_shortcuts(root, &sha256_hex(&zip));

    install_local(&manifest, &archive, root).expect("install should succeed");

    let lnk = shortcut_dir.join("rg.lnk");
    assert!(lnk.is_file(), "shortcut rg.lnk should exist after install");

    // Apps & Features key must exist with v1.0.0.
    assert!(uninstall_reg::key_exists(sk, "rgshort"));
    {
        let subkey = uninstall_reg::package_subkey(sk, "rgshort");
        let key = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(&subkey)
            .unwrap();
        let ver: String = key.get_value("DisplayVersion").unwrap();
        assert_eq!(ver, "1.0.0");
    }

    uninstall("rgshort", root, false).unwrap();
    assert!(
        !lnk.exists(),
        "shortcut rg.lnk should be removed after uninstall"
    );
    assert!(
        !uninstall_reg::key_exists(sk, "rgshort"),
        "A&F key should be removed"
    );

    // --- Part 2: Apps & Features key updated on upgrade ---
    // Re-install v1.0.0.
    install_local(&manifest, &archive, root).unwrap();
    assert!(uninstall_reg::key_exists(sk, "rgshort"));

    // Upgrade to v2.0.0.
    let zip2 = build_zip(&[
        ("ripgrep-2.0.0/", b""),
        ("ripgrep-2.0.0/rg.exe", b"fake rg binary v2"),
    ]);
    let archive2 = root.join("rg-2.0.0.zip");
    fs::write(&archive2, &zip2).unwrap();
    let toml2 = format!(
        r#"
name = "rgshort"
version = "2.0.0"
kind = "app"
extract_dir = "ripgrep-2.0.0"
bin = ["rg.exe"]
shortcuts = ["rg.exe"]

[source.x64]
url = "https://example.com/rg-2.0.0.zip"
sha256 = "{}"
"#,
        sha256_hex(&zip2)
    );
    let m2 = voli_core::Manifest::from_toml_str(&toml2).unwrap();
    voli_core::upgrade_install(&m2, &archive2, &[], root).unwrap();

    // DisplayVersion must now be 2.0.0.
    {
        let subkey = uninstall_reg::package_subkey(sk, "rgshort");
        let key = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(&subkey)
            .unwrap();
        let ver: String = key.get_value("DisplayVersion").unwrap();
        assert_eq!(
            ver, "2.0.0",
            "DisplayVersion should be updated after upgrade"
        );
        // EstimatedSize is in KB; tiny test fixtures round to 0.
        let _size: u32 = key.get_value("EstimatedSize").unwrap();
    }

    // Shortcut must still exist after upgrade (rewritten).
    assert!(lnk.is_file(), "shortcut should survive upgrade");

    // Cleanup our own package key; the binary-wide scratch base and env vars
    // stay for the whole process (other tests share them).
    uninstall("rgshort", root, true).unwrap();
}
