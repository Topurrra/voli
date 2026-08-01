//! The one rule the MCP module states about itself, enforced end to end.
//!
//! `crates/voli/src/mcp.rs` says: "stdout is the wire. One JSON object per line,
//! nothing else, ever." Every unit test in that module calls the pump in-process,
//! so none of them executes `main()` — which means a `println!` added anywhere on
//! the startup path (a banner, a setup nudge, a deprecation notice) would break
//! every MCP client while the suite stayed green. This test drives the real
//! binary, so that regression has somewhere to fail.

use std::io::Write;
use std::process::{Command, Stdio};

/// Feed `stdin` to a real `voli memory serve --mcp` and return (stdout, stderr).
fn serve(stdin: &str, memory_dir: &std::path::Path) -> (String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_voli"))
        .args(["memory", "serve", "--mcp"])
        .env("VOLI_MEMORY_DIR", memory_dir)
        // Never inherit the developer's own masking override into a test.
        .env_remove("VOLI_MEMORY_SHOW_SECRETS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn voli");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write requests");
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn every_line_the_server_writes_to_stdout_is_a_json_rpc_object() {
    let td = tempfile::tempdir().unwrap();
    // No store is initialised on purpose: the protocol must hold even when the
    // memory itself cannot be opened, which is when a stray human-readable
    // diagnostic is most tempting.
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"memory_read","arguments":{}}}"#,
        "\n",
    );
    let (stdout, _stderr) = serve(requests, td.path());

    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "server wrote nothing to stdout");
    for line in &lines {
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line}"));
        assert!(parsed.is_object(), "stdout line is not an object: {line}");
        assert_eq!(parsed["jsonrpc"], "2.0", "missing jsonrpc version: {line}");
    }
    // Three requests carried an id; the notification must not have been answered.
    assert_eq!(lines.len(), 3, "expected one reply per request: {lines:?}");
}

#[test]
fn a_missing_store_still_speaks_protocol_rather_than_prose() {
    let td = tempfile::tempdir().unwrap();
    let missing = td.path().join("no-store-here");
    let request = concat!(
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"memory_read","arguments":{}}}"#,
        "\n",
    );
    let (stdout, _) = serve(request, &missing);
    let line = stdout
        .lines()
        .find(|l| !l.trim().is_empty())
        .expect("a reply");
    let parsed: serde_json::Value =
        serde_json::from_str(line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"));
    assert_eq!(parsed["id"], 7);
}
