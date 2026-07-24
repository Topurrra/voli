//! Integration test for self-install (§11 step 5).
//!
//! Uses a tempdir root, dummy source binaries, and a throwaway registry subkey
//! so it never touches the real user Environment.

use std::fs;

use voli_core::{State, env, self_install};

const BINARIES: &[&str] = &["voli.exe", "voli-shim.exe", "voli-shim-gui.exe"];

#[test]
fn self_install_copies_binaries_and_records_path() {
    let root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    for b in BINARIES {
        fs::write(src.path().join(b), b"dummy binary").unwrap();
    }

    let subkey = "Software\\voli-test-selfinstall";
    let _ = env::delete_subkey(subkey);

    let report = self_install(root.path(), Some(src.path()), subkey).unwrap();

    // all three binaries landed in bin\
    for b in BINARIES {
        assert!(root.path().join("bin").join(b).is_file(), "missing bin/{b}");
    }
    assert_eq!(report.copied.len(), 3);
    assert!(report.path_added, "first run should add shims to PATH");

    // shims dir is on the scratch PATH
    let shims = root.path().join("shims").to_string_lossy().into_owned();
    let path = env::get(subkey, "Path").unwrap().unwrap();
    assert!(env::path_has_segment(&path, &shims), "shims not on PATH");

    // the PATH entry is ledgered under @voli
    let state = State::open(&root.path().join("db").join("state.sqlite")).unwrap();
    assert!(state.is_installed("@voli").unwrap());

    // idempotent: re-running does not duplicate the PATH entry
    let r2 = self_install(root.path(), Some(src.path()), subkey).unwrap();
    assert!(!r2.path_added, "second run must not re-add PATH");
    let path2 = env::get(subkey, "Path").unwrap().unwrap();
    assert_eq!(path, path2, "PATH changed on idempotent re-run");

    env::delete_subkey(subkey).unwrap();
}

#[test]
fn self_install_errors_without_voli_exe() {
    let root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    // only the shim, no voli.exe
    fs::write(src.path().join("voli-shim.exe"), b"x").unwrap();

    let subkey = "Software\\voli-test-selfinstall-missing";
    let _ = env::delete_subkey(subkey);

    let err = self_install(root.path(), Some(src.path()), subkey);
    assert!(err.is_err(), "should fail without voli.exe");

    let _ = env::delete_subkey(subkey);
}
