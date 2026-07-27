//! Windows-only proof for install's shim re-icon step (§6): a shim must (a) end
//! up wearing the target exe's own icon instead of voli's bear stub icon, and
//! (b) still run and forward exit codes/args after the in-place resource swap —
//! and it must be a clean no-op when the target has no icon. Gated to Windows so
//! the Linux build of voli-index-tool stays green.
#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use voli_core::shim_icon::{copy_exe_icon, primary_group_icon};

/// The real bear-icon stub, built next to the test exe (`target\debug\`). The
/// re-icon operates on a genuine shim PE, so a dummy file won't do — skip if it
/// hasn't been built.
fn shim_stub() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf)) // ...\deps
        .and_then(|deps| deps.parent().map(|d| d.join("voli-shim.exe"))) // ...\debug\voli-shim.exe
        .filter(|p| p.exists())
}

fn system_exe(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("SystemRoot")?)
        .join("System32")
        .join(name);
    p.exists().then_some(p)
}

fn scratch(sub: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("voli-icon-{}-{sub}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn reicons_shim_from_target_and_it_still_runs() {
    let (Some(stub), Some(cmd)) = (shim_stub(), system_exe("cmd.exe")) else {
        eprintln!("skipped: voli-shim.exe not built or cmd.exe missing");
        return;
    };
    // Any real exe with an embedded icon works as the icon source; notepad/cmd
    // are always present and their icon is definitely not voli's bear.
    let Some(icon_src) = system_exe("notepad.exe").or(Some(cmd.clone())) else {
        eprintln!("skipped: no system exe with an icon");
        return;
    };

    let dir = scratch("reicon");
    let shim = dir.join("tool.exe");
    fs::copy(&stub, &shim).unwrap();

    // Baseline: a fresh copy wears the bear stub icon.
    let bear = primary_group_icon(&shim).expect("stub must carry an icon group");

    let changed = copy_exe_icon(&icon_src, &shim).expect("re-icon must not error");
    assert!(
        changed,
        "source exe has an icon, so a copy should be reported"
    );

    // (b) The icon actually changed, and it is the source exe's own icon.
    let after = primary_group_icon(&shim).expect("re-iconed shim must still carry an icon group");
    assert_ne!(
        after, bear,
        "icon group must change away from the bear stub"
    );
    assert_eq!(
        after,
        primary_group_icon(&icon_src).unwrap(),
        "shim must now carry the source exe's own icon group"
    );

    // (a) The re-iconed PE still launches its target and forwards the exit code.
    fs::write(
        dir.join("tool.shim"),
        format!("{}\n/c exit 7", cmd.display()),
    )
    .unwrap();
    assert_eq!(
        Command::new(&shim).status().unwrap().code(),
        Some(7),
        "re-iconed shim must still run and forward the exit code"
    );

    // ...and still forwards the caller's args to the target.
    fs::write(dir.join("tool.shim"), format!("{}\n/c echo", cmd.display())).unwrap();
    let out = Command::new(&shim).arg("VOLIOK").output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("VOLIOK"),
        "re-iconed shim must still forward args"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn target_without_icon_is_a_clean_noop() {
    let (Some(stub), Some(cmd)) = (shim_stub(), system_exe("cmd.exe")) else {
        eprintln!("skipped: voli-shim.exe not built or cmd.exe missing");
        return;
    };

    let dir = scratch("noop");
    let shim = dir.join("tool.exe");
    fs::copy(&stub, &shim).unwrap();
    let bear = primary_group_icon(&shim).expect("stub must carry an icon group");

    // The test binary is a valid PE that carries no icon → re-icon is a no-op.
    let no_icon = std::env::current_exe().unwrap();
    let changed = copy_exe_icon(&no_icon, &shim).expect("no-op must not error");
    assert!(!changed, "a target with no icon must report no copy");
    assert_eq!(
        primary_group_icon(&shim).expect("shim keeps its icon group"),
        bear,
        "shim must keep the bear stub icon when the target has none"
    );

    // The untouched shim still runs.
    fs::write(
        dir.join("tool.shim"),
        format!("{}\n/c exit 3", cmd.display()),
    )
    .unwrap();
    assert_eq!(Command::new(&shim).status().unwrap().code(), Some(3));

    let _ = fs::remove_dir_all(&dir);
}
