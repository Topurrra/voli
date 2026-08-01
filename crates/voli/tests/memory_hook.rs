//! What the session-start hook is allowed to put in front of a model.
//!
//! These drive the real binary, because the rules that matter here are about the
//! process as a whole: what reaches stdout, and what the exit code is. A hook
//! runs before the session the user is trying to start, so both are load-bearing
//! — a noisy failure at that moment is worse than contributing nothing.

use std::path::Path;
use std::process::Command;

fn voli(args: &[&str], memory_dir: &Path) -> (String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_voli"))
        .args(args)
        .env("VOLI_MEMORY_DIR", memory_dir)
        .env("VOLI_MEMORY_PASSPHRASE", "hook-test")
        // Never inherit a developer's masking override into a test.
        .env_remove("VOLI_MEMORY_SHOW_SECRETS")
        .output()
        .expect("run voli");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// An empty store renders a fence saying "0 live memories". Injecting that
/// spends an agent's context to tell it there is no context.
#[test]
fn an_empty_store_contributes_nothing_to_the_session() {
    let td = tempfile::tempdir().unwrap();
    let dir = td.path().join("store");
    let (_, code) = voli(&["memory", "init"], &dir);
    assert_eq!(code, 0, "init should succeed");

    let (stdout, code) = voli(&["memory", "read", "--hook"], &dir);
    assert_eq!(stdout, "", "an empty store must inject nothing");
    assert_eq!(code, 0, "and must not fail the session it is starting");
}

#[test]
fn a_store_with_a_memory_injects_it_under_the_documented_key() {
    let td = tempfile::tempdir().unwrap();
    let dir = td.path().join("store");
    voli(&["memory", "init"], &dir);
    voli(
        &[
            "memory",
            "note",
            "the build command is cargo build --release",
        ],
        &dir,
    );

    let (stdout, code) = voli(&["memory", "read", "--hook"], &dir);
    assert_eq!(code, 0);
    let payload: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("not JSON ({e}): {stdout}"));
    let out = &payload["hookSpecificOutput"];
    assert_eq!(out["hookEventName"], "SessionStart");
    let context = out["additionalContext"].as_str().unwrap_or_default();
    assert!(
        context.contains("cargo build --release"),
        "the memory did not reach the agent: {context}"
    );
}

/// No store at all is the common case on a machine that never ran `init`, and it
/// must be indistinguishable from having nothing to say.
#[test]
fn a_missing_store_is_silent_rather_than_an_error() {
    let td = tempfile::tempdir().unwrap();
    let (stdout, code) = voli(&["memory", "read", "--hook"], &td.path().join("absent"));
    assert_eq!(stdout, "");
    assert_eq!(code, 0);
}
