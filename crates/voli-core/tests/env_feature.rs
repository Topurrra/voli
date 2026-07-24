//! Env-var consent feature tests (spec §8, §11 step 10 deliverable 4).
//!
//! Each test installs a fixture whose manifest carries `[env]` against a
//! throwaway registry subkey (passed explicitly, so tests run in parallel and
//! never touch the real user Environment) and proves:
//!   - values are set and ledgered with their prior state;
//!   - uninstall restores the exact prior (pre-existing value restored, an
//!     absent key deleted, a PATH segment removed precisely);
//!   - `--no-env` (consent returns false) applies nothing.

#![cfg(windows)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Once;

use sha2::{Digest, Sha256};
use voli_core::{Action, Manifest, State, env, install_manifest, uninstall_env};
use zip::write::SimpleFileOptions;

static STUB: Once = Once::new();

fn ensure_stub() {
    STUB.call_once(|| {
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
        // SAFETY: set once, before any install runs.
        unsafe {
            std::env::set_var("VOLI_SHIM_STUB", stub);
            // Binary-wide scratch registry/shortcut hooks: without these, any
            // in-process install writes to the user REAL Apps & Features
            // registry (found polluted 2026-07-24).
            std::env::set_var(
                "VOLI_UNINSTALL_SUBKEY",
                concat!("Software\\voli-scratch-", env!("CARGO_CRATE_NAME")),
            );
            let sdir =
                std::env::temp_dir().join(concat!("voli-scratch-lnk-", env!("CARGO_CRATE_NAME")));
            let _ = fs::create_dir_all(&sdir);
            std::env::set_var("VOLI_SHORTCUT_DIR", sdir);
        };
    });
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// A zip with a wrapper dir `app-1.0.0/` holding `app.exe` and a `bin/` subdir.
fn app_zip() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.add_directory("app-1.0.0/", opts).unwrap();
        w.start_file("app-1.0.0/app.exe", opts).unwrap();
        w.write_all(b"fake app").unwrap();
        w.add_directory("app-1.0.0/bin/", opts).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Manifest for `app` with a JAVA_HOME (plain set) and a PATH (prepend) env.
fn app_manifest(sha: &str) -> Manifest {
    let toml = format!(
        r#"
name = "app"
version = "1.0.0"
kind = "app"
extract_dir = "app-1.0.0"
bin = ["app.exe"]

[source.x64]
url = "https://example.com/app.zip"
sha256 = "{sha}"

[env]
JAVA_HOME = "{{dir}}"
PATH = "{{dir}}\\bin"
"#
    );
    Manifest::from_toml_str(&toml).unwrap()
}

fn scratch(name: &str) -> String {
    format!("Software\\voli-test-envfeat\\{name}")
}

#[test]
fn env_applied_ledgered_and_uninstall_restores_absent() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let sk = scratch("absent");
    let _ = env::delete_subkey(&sk);

    let zip = app_zip();
    let archive = root.join("app.zip");
    fs::write(&archive, &zip).unwrap();
    let m = app_manifest(&sha256_hex(&zip));

    let current = root.join("apps").join("app").join("current");
    let current_str = current.to_string_lossy().into_owned();
    let expect_java = current_str.clone();
    let expect_path_seg = format!("{current_str}\\bin");

    // Consent = apply. JAVA_HOME + PATH did not exist before → priors are None.
    let report = install_manifest(&m, &archive, &[], root, &sk, &mut |_, _| true).unwrap();
    assert_eq!(report.env_applied.len(), 2);

    // Registry now carries our values.
    assert_eq!(
        env::get(&sk, "JAVA_HOME").unwrap().as_deref(),
        Some(expect_java.as_str())
    );
    let path_now = env::get(&sk, "Path").unwrap().unwrap();
    assert!(
        env::path_has_segment(&path_now, &expect_path_seg),
        "PATH should contain our segment, got {path_now}"
    );

    // Ledger records EnvSet (value + prior=None) and PathAdded (exact segment).
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    let actions = state.actions_for("app").unwrap();
    let env_set = actions.iter().find_map(|a| match a {
        Action::EnvSet { key, value, prior } if key == "JAVA_HOME" => {
            Some((value.clone(), prior.clone()))
        }
        _ => None,
    });
    assert_eq!(env_set, Some((expect_java.clone(), None)));
    let path_added = actions
        .iter()
        .any(|a| matches!(a, Action::PathAdded { segment } if *segment == expect_path_seg));
    assert!(path_added, "PathAdded segment must be ledgered exactly");
    drop(state);

    // Uninstall restores prior: JAVA_HOME deleted (was absent), segment removed.
    uninstall_env("app", root, false, &sk).unwrap();
    assert_eq!(
        env::get(&sk, "JAVA_HOME").unwrap(),
        None,
        "absent key must be deleted"
    );
    let path_after = env::get(&sk, "Path").unwrap().unwrap_or_default();
    assert!(
        !env::path_has_segment(&path_after, &expect_path_seg),
        "our PATH segment must be gone, got {path_after}"
    );

    env::delete_subkey(&sk).unwrap();
}

#[test]
fn uninstall_restores_preexisting_value() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let sk = scratch("preexisting");
    let _ = env::delete_subkey(&sk);

    // Seed a pre-existing JAVA_HOME and a PATH with an unrelated segment.
    env::set(&sk, "JAVA_HOME", "C:\\old\\jdk").unwrap();
    env::set(&sk, "Path", "C:\\keep\\me").unwrap();

    let zip = app_zip();
    let archive = root.join("app.zip");
    fs::write(&archive, &zip).unwrap();
    let m = app_manifest(&sha256_hex(&zip));

    install_manifest(&m, &archive, &[], root, &sk, &mut |_, _| true).unwrap();
    // Our value now, prior recorded.
    assert_ne!(
        env::get(&sk, "JAVA_HOME").unwrap().as_deref(),
        Some("C:\\old\\jdk")
    );

    uninstall_env("app", root, false, &sk).unwrap();

    // Prior JAVA_HOME restored exactly; the pre-existing PATH segment survives,
    // ours removed.
    assert_eq!(
        env::get(&sk, "JAVA_HOME").unwrap().as_deref(),
        Some("C:\\old\\jdk")
    );
    let path_after = env::get(&sk, "Path").unwrap().unwrap();
    assert!(
        env::path_has_segment(&path_after, "C:\\keep\\me"),
        "got {path_after}"
    );
    let seg = format!("{}\\bin", root.join("apps/app/current").to_string_lossy());
    assert!(!env::path_has_segment(&path_after, &seg));

    env::delete_subkey(&sk).unwrap();
}

#[test]
fn no_env_consent_applies_nothing() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let sk = scratch("noenv");
    let _ = env::delete_subkey(&sk);

    let zip = app_zip();
    let archive = root.join("app.zip");
    fs::write(&archive, &zip).unwrap();
    let m = app_manifest(&sha256_hex(&zip));

    // Consent = skip (mirrors `--no-env`).
    let report = install_manifest(&m, &archive, &[], root, &sk, &mut |_, _| false).unwrap();
    assert!(report.env_applied.is_empty());
    assert_eq!(
        report.env_requested.len(),
        2,
        "requested is reported even when skipped"
    );

    // Nothing written, nothing ledgered.
    assert_eq!(env::get(&sk, "JAVA_HOME").unwrap(), None);
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    let has_env = state
        .actions_for("app")
        .unwrap()
        .iter()
        .any(|a| matches!(a, Action::EnvSet { .. } | Action::PathAdded { .. }));
    assert!(!has_env, "no env actions should be ledgered when skipped");

    // App still installed and healthy otherwise.
    assert!(root.join("apps/app/1.0.0/app.exe").is_file());

    let _ = env::delete_subkey(&sk);
}
