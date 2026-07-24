//! End-to-end shim chain test. `harness = false` so we control argv: when this
//! test binary is invoked with the `__voli_echo__` marker it acts as the
//! target executable (echoes each arg on its own line, exits with
//! $VOLI_ECHO_EXIT). Otherwise it runs the assertions below. This avoids
//! shipping a separate fixture binary — the test IS the echo helper.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const MARKER: &str = "__voli_echo__";

fn echo_mode() -> ! {
    // argv: [exe, MARKER, <forwarded args...>]
    for arg in std::env::args().skip(2) {
        println!("{arg}");
    }
    let code = std::env::var("VOLI_ECHO_EXIT")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0);
    std::process::exit(code);
}

fn main() {
    let mut argv = std::env::args();
    let _exe = argv.next();
    if argv.next().as_deref() == Some(MARKER) {
        echo_mode();
    }
    run();
    println!("all shim chain tests passed");
}

fn run() {
    let shim_bin = PathBuf::from(env!("CARGO_BIN_EXE_voli-shim"));
    let self_exe = std::env::current_exe().expect("current_exe");

    // Unique temp dir next to the target dir; copy the shim in as "tool.exe" so
    // its sibling ".shim" is "tool.shim".
    let dir = std::env::temp_dir().join(format!("voli-shim-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    let shim_copy = dir.join("tool.exe");
    fs::copy(&shim_bin, &shim_copy).expect("copy shim");

    // Point the shim at this test binary, running in echo mode.
    let shim_file = dir.join("tool.shim");
    fs::write(&shim_file, format!("{}\n{MARKER}", self_exe.display())).expect("write .shim");

    // --- arg fidelity: spaces and quotes must survive the shim -> child hop ---
    let tricky = ["hello world", "plain", "a\"b", "trailing "];
    let out = Command::new(&shim_copy)
        .args(tricky)
        .env("VOLI_ECHO_EXIT", "7")
        .output()
        .expect("run shim");

    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let got: Vec<&str> = stdout.lines().collect();
    assert_eq!(got, tricky, "args did not survive the shim chain: {got:?}");

    // --- exit code 7 propagates ---
    assert_eq!(out.status.code(), Some(7), "exit code 7 not propagated");

    // --- exit code 3010 (>255) propagates unchanged ---
    let out2 = Command::new(&shim_copy)
        .arg("x")
        .env("VOLI_ECHO_EXIT", "3010")
        .output()
        .expect("run shim (3010)");
    assert_eq!(
        out2.status.code(),
        Some(3010),
        "exit code 3010 not propagated"
    );

    // --- missing .shim -> clear failure, EXIT_SHIM_ERROR (9009) ---
    let orphan = dir.join("orphan.exe");
    fs::copy(&shim_bin, &orphan).expect("copy orphan shim");
    let out3 = Command::new(&orphan).output().expect("run orphan shim");
    assert_eq!(
        out3.status.code(),
        Some(voli_shim::EXIT_SHIM_ERROR),
        "missing .shim should exit 9009"
    );
    assert!(
        String::from_utf8_lossy(&out3.stderr).contains("cannot read shim file"),
        "missing .shim should explain itself on stderr"
    );

    let _ = fs::remove_dir_all(&dir);
}
