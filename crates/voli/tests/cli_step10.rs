//! CLI-level tests for step 10 (spec §8, §9): the env-consent auto-apply path,
//! doctor's env-drift WARN, and `upgrade --all` skipping pinned packages.
//!
//! These drive the real `voli` binary (so the TTY / prompt / pin-filter logic
//! that lives in the CLI is exercised) against a scratch VOLI_ENV_SUBKEY and an
//! isolated VOLI_ROOT.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Once;

use sha2::{Digest, Sha256};
use voli_core::{Manifest, State, env, install_local};
use zip::write::SimpleFileOptions;

static STUB: Once = Once::new();

/// Point `VOLI_SHIM_STUB` at the built voli-shim.exe (in target/debug, the
/// parent of the test binary's deps/ dir) so in-process installs can copy it.
fn ensure_stub() {
    STUB.call_once(|| {
        let stub = std::env::current_exe()
            .ok()
            .and_then(|p| {
                p.parent()
                    .and_then(|d| d.parent())
                    .map(|d| d.join("voli-shim.exe"))
            })
            .filter(|p| p.exists())
            .unwrap_or_else(|| {
                let p = std::env::temp_dir().join("voli-test-shim-stub.exe");
                fs::write(&p, b"dummy shim stub").unwrap();
                p
            });
        // SAFETY: set once, before any install runs.
        unsafe { std::env::set_var("VOLI_SHIM_STUB", stub) };
    });
}

fn sha256_hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Zip with wrapper `app-1.0.0/` + `app.exe` + `bin/`.
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

fn skill_zip() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.add_directory("tdd/", options).unwrap();
        writer.start_file("tdd/SKILL.md", options).unwrap();
        writer
            .write_all(
                b"---\nname: tdd\ndescription: Test-driven development workflow\n---\n# TDD\n\nWrite the test first.\n",
            )
            .unwrap();
        writer.finish().unwrap();
    }
    buf
}

fn write_env_manifest(dir: &Path, sha: &str) -> std::path::PathBuf {
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
"#
    );
    let p = dir.join("app.toml");
    fs::write(&p, toml).unwrap();
    p
}

fn voli(root: &Path, subkey: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_voli"))
        .args(args)
        .env("VOLI_ROOT", root)
        .env("VOLI_ENV_SUBKEY", subkey)
        .stdin(Stdio::null()) // non-TTY: install auto-applies env (spec §8/§9)
        .output()
        .unwrap()
}

#[test]
fn delete_commands_are_primary_and_old_names_remain_aliases() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let subkey = "Software\\voli-test-cli\\delete-aliases";
    let help = voli(root, subkey, &["--help"]);
    let stdout = String::from_utf8_lossy(&help.stdout);

    assert!(stdout.contains("\n  delete "));
    assert!(stdout.contains("\n  self-delete "));
    assert!(!stdout.contains("\n  uninstall "));
    assert!(!stdout.contains("\n  self-uninstall "));

    for command in ["delete", "uninstall", "self-delete", "self-uninstall"] {
        let output = voli(root, subkey, &[command, "--help"]);
        assert!(output.status.success(), "{command} should parse");
    }
}

#[test]
fn local_skill_install_list_and_targeted_delete() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("voli");
    let home = temp.path().join("home");
    let project = temp.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let archive_bytes = skill_zip();
    let archive = temp.path().join("tdd.zip");
    fs::write(&archive, &archive_bytes).unwrap();
    let manifest = temp.path().join("tdd.toml");
    let env_subkey = "Software\\voli-test-cli\\skill-env";
    let uninstall_subkey = "Software\\voli-test-cli\\skill-uninstall";
    let _ = env::delete_subkey(env_subkey);
    let _ = voli_core::uninstall_reg::delete_base(uninstall_subkey);
    fs::write(
        &manifest,
        format!(
            r#"name = "tdd"
version = "1.0.0"
kind = "skill"

[source.any]
url = "https://example.com/tdd.zip"
sha256 = "{}"
"#,
            sha256_hex(&archive_bytes)
        ),
    )
    .unwrap();

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_voli"))
            .args(args)
            .env("VOLI_ROOT", &root)
            .env("VOLI_ENV_SUBKEY", env_subkey)
            .env("VOLI_UNINSTALL_SUBKEY", uninstall_subkey)
            .env("USERPROFILE", &home)
            .env("HOME", &home)
            .current_dir(&project)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let install = run(&[
        "--json",
        "install",
        manifest.to_str().unwrap(),
        "--archive",
        archive.to_str().unwrap(),
        "--for",
        "codex",
        "--for",
        "zed",
    ]);
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let install_json: serde_json::Value = serde_json::from_slice(&install.stdout).unwrap();
    assert_eq!(install_json["installed"][0]["kind"], "skill");
    assert_eq!(install_json["installed"][0]["target"], "codex");
    assert_eq!(install_json["installed"][0]["scope"], "global");
    assert_eq!(install_json["installed"].as_array().unwrap().len(), 2);
    assert!(home.join(".agents/skills/tdd/SKILL.md").is_file());

    let list = run(&["list"]);
    assert!(list.status.success());
    assert!(String::from_utf8_lossy(&list.stdout).contains("skill/tdd  1.0.0  [codex:global]"));

    let delete = run(&["delete", "skill/tdd", "--for", "codex"]);
    assert!(
        delete.status.success(),
        "{}",
        String::from_utf8_lossy(&delete.stderr)
    );
    assert!(home.join(".agents/skills/tdd").exists());
    assert!(
        run(&["delete", "skill/tdd", "--for", "zed"])
            .status
            .success()
    );
    assert!(!home.join(".agents").exists());

    let project_install = run(&[
        "install",
        manifest.to_str().unwrap(),
        "--archive",
        archive.to_str().unwrap(),
        "--for",
        "cursor",
        "--project",
    ]);
    assert!(
        project_install.status.success(),
        "{}",
        String::from_utf8_lossy(&project_install.stderr)
    );
    assert!(project.join(".agents/skills/tdd/SKILL.md").is_file());
    assert!(
        run(&["delete", "skill/tdd", "--for", "cursor", "--project"])
            .status
            .success()
    );
    assert!(!project.join(".agents").exists());

    let missing = run(&[
        "install",
        manifest.to_str().unwrap(),
        "--archive",
        archive.to_str().unwrap(),
    ]);
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("require --for"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
    let _ = env::delete_subkey(env_subkey);
    let _ = voli_core::uninstall_reg::delete_base(uninstall_subkey);
}

#[test]
fn non_tty_install_auto_applies_env_and_uninstall_restores() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let sk = "Software\\voli-test-cli\\autoapply";
    let _ = env::delete_subkey(sk);

    let zip = app_zip();
    let archive = root.join("app.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_env_manifest(root, &sha256_hex(&zip));

    // Non-TTY install: no --yes, but null stdin => auto-applies without prompting.
    let out = voli(
        root,
        sk,
        &[
            "install",
            manifest.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let expect = root
        .join("apps")
        .join("app")
        .join("current")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        env::get(sk, "JAVA_HOME").unwrap().as_deref(),
        Some(expect.as_str())
    );

    // `voli env app` reports it.
    let env_out = voli(root, sk, &["env", "app/app"]);
    assert!(env_out.status.success());
    assert!(String::from_utf8_lossy(&env_out.stdout).contains("JAVA_HOME"));
    assert!(voli(root, sk, &["pin", "app/app"]).status.success());
    assert!(voli(root, sk, &["unpin", "app/app"]).status.success());

    // Uninstall restores prior (JAVA_HOME was absent => deleted).
    let un = voli(root, sk, &["delete", "app"]);
    assert!(un.status.success());
    assert_eq!(
        env::get(sk, "JAVA_HOME").unwrap(),
        None,
        "zero-trace: key deleted"
    );

    let _ = env::delete_subkey(sk);
}

#[test]
fn no_env_flag_skips_application() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let sk = "Software\\voli-test-cli\\noenv";
    let _ = env::delete_subkey(sk);

    let zip = app_zip();
    let archive = root.join("app.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_env_manifest(root, &sha256_hex(&zip));

    let out = voli(
        root,
        sk,
        &[
            "install",
            manifest.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--no-env",
        ],
    );
    assert!(out.status.success());
    assert_eq!(
        env::get(sk, "JAVA_HOME").unwrap(),
        None,
        "--no-env applies nothing"
    );

    let _ = env::delete_subkey(sk);
}

#[test]
fn doctor_warns_on_env_drift() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let sk = "Software\\voli-test-cli\\drift";
    let _ = env::delete_subkey(sk);

    let zip = app_zip();
    let archive = root.join("app.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_env_manifest(root, &sha256_hex(&zip));
    voli(
        root,
        sk,
        &[
            "install",
            manifest.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
        ],
    );

    // User edits what voli set → drift.
    env::set(sk, "JAVA_HOME", "C:\\hand\\edited").unwrap();

    // (This root was never `voli setup`, so PATH/bin checks fail — that's fine;
    // we assert only that drift surfaces as a WARN, never a FAIL, and is not
    // auto-fixed.)
    let out = voli(root, sk, &["doctor", "--json"]);
    let text = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let drift = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == "env drift")
        .expect("doctor should report an env-drift check");
    assert_eq!(drift["status"], "WARN", "drift must WARN, not FAIL");

    // Never auto-fixed: the hand-edited value stands.
    assert_eq!(
        env::get(sk, "JAVA_HOME").unwrap().as_deref(),
        Some("C:\\hand\\edited")
    );

    let _ = env::delete_subkey(sk);
}

#[test]
fn upgrade_all_skips_pinned() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let sk = "Software\\voli-test-cli\\pin";

    // Install v1 locally (no network), then advertise a newer v2 in the index.
    let zip = app_zip();
    let archive = root.join("app.zip");
    fs::write(&archive, &zip).unwrap();
    let manifest = write_env_manifest(root, &sha256_hex(&zip));
    install_local(&manifest, &archive, root).unwrap();

    let m1 = Manifest::from_toml_str(
        r#"name="app"
version="1.0.0"
kind="app"
bin=["app.exe"]
[source.x64]
url="https://example.com/app-1.0.0.zip"
sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#,
    )
    .unwrap();
    let m2 = Manifest::from_toml_str(
        r#"name="app"
version="2.0.0"
kind="app"
bin=["app.exe"]
[source.x64]
url="https://example.com/app-2.0.0.zip"
sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#,
    )
    .unwrap();
    voli_core::index::build(&[m1, m2], &voli_core::index::index_db_path(root)).unwrap();

    // Pin it.
    {
        let mut state = State::open(&voli_core::Paths::at(root).state_db()).unwrap();
        assert!(state.set_pinned("app", true).unwrap());
    }

    // `upgrade --all` must skip the pinned package (never downloads v2).
    let out = voli(root, sk, &["upgrade", "--all"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("pinned"),
        "expected a pinned-skip note:\n{text}"
    );

    // Still v1 — the pin held.
    let state = State::open(&voli_core::Paths::at(root).state_db()).unwrap();
    assert_eq!(
        state.installed_version("app").unwrap().as_deref(),
        Some("1.0.0")
    );
}
