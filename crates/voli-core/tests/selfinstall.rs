//! Integration test for self-install (§11 step 5).
//!
//! Uses a tempdir root, dummy source binaries, and a throwaway env subkey
//! so it never touches the real user Environment.

use std::fs;

use voli_core::{State, env, self_install};

#[cfg(windows)]
const BINARIES: &[&str] = &["voli.exe", "voli-shim.exe", "voli-shim-gui.exe"];
#[cfg(not(windows))]
const BINARIES: &[&str] = &["voli", "voli-shim"];

#[cfg(windows)]
const VOLI_BIN: &str = "voli.exe";
#[cfg(not(windows))]
const VOLI_BIN: &str = "voli";

#[cfg(windows)]
const SHIM_BIN: &str = "voli-shim.exe";
#[cfg(not(windows))]
const SHIM_BIN: &str = "voli-shim";

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

    // all binaries landed in bin/
    for b in BINARIES {
        assert!(root.path().join("bin").join(b).is_file(), "missing bin/{b}");
    }
    assert_eq!(report.copied.len(), BINARIES.len());
    assert!(report.path_added, "first run should add shims to PATH");

    // shims dir is on the scratch PATH
    let shims = root.path().join("shims").to_string_lossy().into_owned();
    let path = env::get(subkey, "Path").unwrap().unwrap();
    assert!(env::path_has_segment(&path, &shims), "shims not on PATH");

    // the PATH entry is ledgered under @voli
    let state = State::open(&root.path().join("db").join("state.sqlite")).unwrap();
    assert!(state.is_installed("@voli").unwrap());

    // self-shim for voli exists and is executable (unix) alongside the .shim
    let shim_exe = root.path().join("shims").join(VOLI_BIN);
    assert!(
        shim_exe.is_file(),
        "self-shim {} missing",
        shim_exe.display()
    );
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(&shim_exe).unwrap().permissions().mode() & 0o111,
            0,
            "self-shim must be executable"
        );
    }

    // idempotent: re-running does not duplicate the PATH entry
    let r2 = self_install(root.path(), Some(src.path()), subkey).unwrap();
    assert!(!r2.path_added, "second run must not re-add PATH");
    let path2 = env::get(subkey, "Path").unwrap().unwrap();
    assert_eq!(path, path2, "PATH changed on idempotent re-run");

    env::delete_subkey(subkey).unwrap();
}

#[test]
fn self_install_errors_without_voli_binary() {
    let root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    // only the shim, no voli binary
    fs::write(src.path().join(SHIM_BIN), b"x").unwrap();

    let subkey = "Software\\voli-test-selfinstall-missing";
    let _ = env::delete_subkey(subkey);

    let err = self_install(root.path(), Some(src.path()), subkey);
    assert!(err.is_err(), "should fail without the voli binary");

    let _ = env::delete_subkey(subkey);
}
