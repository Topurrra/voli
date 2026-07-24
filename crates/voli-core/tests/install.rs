//! Integration tests for the transactional install/uninstall engine (§11 step 3).
//!
//! Each test gets an isolated tempdir root. Fixture zips are built in-process.
//! The shim stub is a dummy file pointed at by `VOLI_SHIM_STUB` (set once,
//! process-wide, guarded by a `Once`); if a real `voli-shim.exe` has been built
//! we prefer that.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
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

fn setup() -> tempfile::TempDir {
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

// ---- shortcut + Apps & Features integration test ----
// These mutate process-global env vars (VOLI_UNINSTALL_SUBKEY,
// VOLI_SHORTCUT_DIR), so they run as ONE test to avoid racing with
// each other and with other install tests in this binary.

fn write_manifest_with_shortcuts(dir: &Path, sha256: &str) -> PathBuf {
    let toml = format!(
        r#"
name = "ripgrep"
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
    let p = dir.join("ripgrep.toml");
    fs::write(&p, toml).unwrap();
    p
}

#[test]
fn shortcut_and_apps_features_lifecycle() {
    use voli_core::uninstall_reg;

    let td = setup();
    let root = td.path();

    // Scratch dirs/subkeys — avoid touching the real registry.
    let shortcut_dir = td.path().join("shortcuts");
    let sk = "Software\\voli-test-shortcut-af";
    let _ = uninstall_reg::delete_base(sk);
    // SAFETY: test-local env overrides, restored at end.
    unsafe {
        std::env::set_var("VOLI_SHORTCUT_DIR", &shortcut_dir);
        std::env::set_var("VOLI_UNINSTALL_SUBKEY", sk);
    }

    // --- Part 1: shortcut created on install, removed on uninstall ---
    let zip = ripgrep_zip();
    let archive = root.join("rg.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_manifest_with_shortcuts(root, &sha256_hex(&zip));

    install_local(&manifest, &archive, root).expect("install should succeed");

    let lnk = shortcut_dir.join("rg.lnk");
    assert!(lnk.is_file(), "shortcut rg.lnk should exist after install");

    // Apps & Features key must exist with v1.0.0.
    assert!(uninstall_reg::key_exists(sk, "ripgrep"));
    {
        let subkey = uninstall_reg::package_subkey(sk, "ripgrep");
        let key = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(&subkey)
            .unwrap();
        let ver: String = key.get_value("DisplayVersion").unwrap();
        assert_eq!(ver, "1.0.0");
    }

    uninstall("ripgrep", root, false).unwrap();
    assert!(
        !lnk.exists(),
        "shortcut rg.lnk should be removed after uninstall"
    );
    assert!(
        !uninstall_reg::key_exists(sk, "ripgrep"),
        "A&F key should be removed"
    );

    // --- Part 2: Apps & Features key updated on upgrade ---
    // Re-install v1.0.0.
    install_local(&manifest, &archive, root).unwrap();
    assert!(uninstall_reg::key_exists(sk, "ripgrep"));

    // Upgrade to v2.0.0.
    let zip2 = build_zip(&[
        ("ripgrep-2.0.0/", b""),
        ("ripgrep-2.0.0/rg.exe", b"fake rg binary v2"),
    ]);
    let archive2 = root.join("rg-2.0.0.zip");
    fs::write(&archive2, &zip2).unwrap();
    let toml2 = format!(
        r#"
name = "ripgrep"
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
        let subkey = uninstall_reg::package_subkey(sk, "ripgrep");
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

    // Cleanup.
    uninstall("ripgrep", root, true).unwrap();
    let _ = uninstall_reg::delete_base(sk);
    unsafe {
        std::env::remove_var("VOLI_SHORTCUT_DIR");
        std::env::remove_var("VOLI_UNINSTALL_SUBKEY");
    }
}
