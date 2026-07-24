//! Integration test for `voli doctor` (§11 step 5).
//!
//! Builds a healthy root by hand, runs the real `voli` binary against it with a
//! scratch registry subkey (VOLI_ENV_SUBKEY), and asserts exit 0. Then breaks a
//! shim target and asserts a FAIL exit (1).

use std::fs;
use std::path::Path;
use std::process::Command;

use voli_core::{Action, State, env};

const SUBKEY: &str = "Software\\voli-test-doctor";

/// Lay down a healthy root: bin binaries, shims, one installed package with a
/// resolvable `current` junction and a shim whose target exists.
fn build_healthy_root(root: &Path) {
    for d in ["bin", "shims", "db", "apps"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    for b in ["voli.exe", "voli-shim.exe", "voli-shim-gui.exe"] {
        fs::write(root.join("bin").join(b), b"dummy").unwrap();
    }

    // apps\demo\current\rg.exe is the real target the shim points at.
    let current = root.join("apps").join("demo").join("current");
    fs::create_dir_all(&current).unwrap();
    let target = current.join("rg.exe");
    fs::write(&target, b"real").unwrap();

    // shims\rg.shim (line 1 = target) + shims\rg.exe stub.
    let shim = root.join("shims").join("rg.shim");
    fs::write(&shim, format!("{}\n", target.display())).unwrap();
    let shim_exe = root.join("shims").join("rg.exe");
    fs::write(&shim_exe, b"stub").unwrap();

    // ledger one package with that shim.
    let mut state = State::open(&root.join("db").join("state.sqlite")).unwrap();
    let actions = vec![Action::ShimWritten {
        shim: shim.clone(),
        exe: shim_exe.clone(),
    }];
    state
        .record_install("demo", "1.0.0", "{}", &actions)
        .unwrap();
}

fn run_doctor(root: &Path) -> i32 {
    Command::new(env!("CARGO_BIN_EXE_voli"))
        .arg("doctor")
        .env("VOLI_ROOT", root)
        .env("VOLI_ENV_SUBKEY", SUBKEY)
        .status()
        .unwrap()
        .code()
        .unwrap()
}

#[test]
fn doctor_healthy_then_broken() {
    let root = tempfile::tempdir().unwrap();
    build_healthy_root(root.path());

    // shims dir on the scratch PATH so the PATH check passes.
    let _ = env::delete_subkey(SUBKEY);
    let shims = root.path().join("shims").to_string_lossy().into_owned();
    env::add_to_path(SUBKEY, &shims).unwrap();

    // healthy → exit 0
    assert_eq!(run_doctor(root.path()), 0, "healthy root should pass");

    // break the shim target → FAIL → exit 1
    fs::remove_file(
        root.path()
            .join("apps")
            .join("demo")
            .join("current")
            .join("rg.exe"),
    )
    .unwrap();
    assert_eq!(run_doctor(root.path()), 1, "broken shim target should fail");

    env::delete_subkey(SUBKEY).unwrap();
}
