//! voli-shim: the tiny stub copied next to each shimmed binary (spec §6).
//!
//! At runtime it reads the sibling `<own-name>.shim` file, spawns the real
//! target, forwards args and stdio, and propagates the exit code.
//!
//! Phase 1 step 4 is a compiling stub only. Ctrl-C forwarding and the GUI
//! subsystem variant come later.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Parsed `.shim` file: target executable plus any prepended args.
#[derive(Debug, PartialEq, Eq)]
struct Shim {
    target: PathBuf,
    prepend_args: Vec<String>,
}

/// Parse a `.shim` file body.
///
/// Line 1 is the target path. Line 2 (optional) is a space-separated list of
/// args prepended before the caller's own args.
fn parse_shim(contents: &str) -> Option<Shim> {
    let mut lines = contents.lines();
    let target = lines.next()?.trim();
    if target.is_empty() {
        return None;
    }
    // ponytail: naive whitespace split; a real quoted-arg parser lands with the
    // rest of the shim in a later phase.
    let prepend_args = lines
        .next()
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    Some(Shim {
        target: PathBuf::from(target),
        prepend_args,
    })
}

/// Locate `<exe>.shim` sibling of the running shim binary.
fn shim_path(exe: &Path) -> PathBuf {
    exe.with_extension("shim")
}

fn main() {
    let exe = std::env::current_exe().expect("cannot resolve own exe path");
    let shim_file = shim_path(&exe);
    let contents = std::fs::read_to_string(&shim_file)
        .unwrap_or_else(|e| panic!("cannot read shim file {}: {e}", shim_file.display()));
    let shim = parse_shim(&contents)
        .unwrap_or_else(|| panic!("malformed shim file {}", shim_file.display()));

    // TODO(phase1-step4): install a console Ctrl-C handler that ignores the
    // signal in the shim so the child receives it, and add a GUI-subsystem
    // variant that does not attach a console.
    let status = Command::new(&shim.target)
        .args(&shim.prepend_args)
        .args(std::env::args_os().skip(1))
        .status()
        .unwrap_or_else(|e| panic!("failed to launch {}: {e}", shim.target.display()));

    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_target_only() {
        let s = parse_shim("C:\\voli\\apps\\ripgrep\\current\\rg.exe\n").unwrap();
        assert_eq!(
            s.target,
            PathBuf::from("C:\\voli\\apps\\ripgrep\\current\\rg.exe")
        );
        assert!(s.prepend_args.is_empty());
    }

    #[test]
    fn parses_target_and_args() {
        let s = parse_shim("rg.exe\n--color always --hidden").unwrap();
        assert_eq!(s.target, PathBuf::from("rg.exe"));
        assert_eq!(s.prepend_args, vec!["--color", "always", "--hidden"]);
    }

    #[test]
    fn empty_is_none() {
        assert!(parse_shim("").is_none());
        assert!(parse_shim("\n").is_none());
    }
}
