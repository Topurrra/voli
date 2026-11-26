//! Machine consumers (JN apps, MCP clients, scripts) run voli with piped
//! output, often from a copy of voli.exe that is not under `<root>\bin`.
//! The "run `voli setup`" nudge is for a person at a terminal; it must not
//! land in their captured stderr on every call.

use std::process::Command;

fn voli(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_voli"))
        .args(args)
        .env("VOLI_ROOT", root)
        .env(
            "VOLI_ENV_SUBKEY",
            r"Software\voli-test-cli-quiet\Environment",
        )
        .output()
        .expect("run voli")
}

#[test]
fn setup_nudge_stays_out_of_piped_and_json_output() {
    let td = tempfile::tempdir().unwrap();
    for args in [&["--json", "list"][..], &["list"][..]] {
        let out = voli(td.path(), args);
        assert!(out.status.success(), "voli {args:?} failed: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("voli setup"),
            "voli {args:?} printed the setup nudge to a pipe: {stderr}"
        );
    }
}
