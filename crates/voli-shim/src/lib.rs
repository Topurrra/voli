//! voli-shim shared core (spec §6).
//!
//! Both shim binaries (`voli-shim` console, `voli-shim-gui`) are tiny: they
//! resolve their sibling `<own-name>.shim` file, then launch the real target
//! forwarding args and stdio. This module holds the parsing + resolution they
//! share; the console/exit-code/Ctrl-C and GUI-detach behaviour lives in the
//! two `src/bin/*` entry points.

use std::fmt;
use std::path::{Path, PathBuf};

/// Exit code for shim-level failures (bad/missing `.shim`, missing target).
/// 9009 is the Windows "command not found" convention — the caller asked for a
/// command that could not be run.
pub const EXIT_SHIM_ERROR: i32 = 9009;

/// Parsed `.shim` file: target executable plus any prepended args.
#[derive(Debug, PartialEq, Eq)]
pub struct Shim {
    pub target: PathBuf,
    pub prepend_args: Vec<String>,
}

/// Everything that can go wrong resolving a shim. Rendered to stderr (console
/// variant) verbatim; the GUI variant just exits non-zero.
#[derive(Debug)]
pub enum ShimError {
    NoExePath(std::io::Error),
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Malformed {
        path: PathBuf,
    },
    TargetMissing {
        path: PathBuf,
        target: PathBuf,
    },
}

impl fmt::Display for ShimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShimError::NoExePath(e) => write!(f, "cannot resolve own exe path: {e}"),
            ShimError::Read { path, source } => {
                write!(f, "cannot read shim file {}: {source}", path.display())
            }
            ShimError::Malformed { path } => {
                write!(
                    f,
                    "malformed shim file {} (empty target line)",
                    path.display()
                )
            }
            ShimError::TargetMissing { path, target } => write!(
                f,
                "shim target does not exist: {} (referenced by {})",
                target.display(),
                path.display()
            ),
        }
    }
}

impl std::error::Error for ShimError {}

/// Parse a `.shim` file body.
///
/// Line 1 is the target path. Line 2 (optional) is a whitespace-separated list
/// of args prepended before the caller's own args. Tolerant of a leading UTF-8
/// BOM and of CRLF line endings (`str::lines` strips the `\r`).
pub fn parse_shim(contents: &str) -> Option<Shim> {
    // A UTF-8 BOM survives `read_to_string` as U+FEFF at the head of the string.
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let mut lines = contents.lines();
    let target = lines.next()?.trim();
    if target.is_empty() {
        return None;
    }
    // ponytail: whitespace split, not a full quoted-arg parser. The registry
    // writes shim args itself and keeps them flag-shaped ("--color always");
    // upgrade to a real tokenizer only if a manifest ever needs a quoted arg.
    let prepend_args = lines
        .next()
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    Some(Shim {
        target: PathBuf::from(target),
        prepend_args,
    })
}

/// `<exe>.shim` sibling of the running shim binary (`rg.exe` -> `rg.shim`).
pub fn shim_path(exe: &Path) -> PathBuf {
    exe.with_extension("shim")
}

/// Full resolution used by both binaries: find own exe, read the sibling
/// `.shim`, parse it, and confirm the target exists (so the error names the
/// missing target rather than a generic spawn failure).
pub fn resolve() -> Result<Shim, ShimError> {
    let exe = std::env::current_exe().map_err(ShimError::NoExePath)?;
    let path = shim_path(&exe);
    let contents = std::fs::read_to_string(&path).map_err(|source| ShimError::Read {
        path: path.clone(),
        source,
    })?;
    let shim = parse_shim(&contents).ok_or(ShimError::Malformed { path: path.clone() })?;
    if !shim.target.exists() {
        return Err(ShimError::TargetMissing {
            path,
            target: shim.target.clone(),
        });
    }
    Ok(shim)
}

/// Make the shim ignore CTRL_C/CTRL_BREAK so it survives to wait for the child
/// and propagate its exit code. The child shares this console and still
/// receives the event (default handling terminates it, or it installs its own
/// handler) — we only opt the *shim* out.
///
/// Manual test (cannot be exercised headlessly): shim a REPL such as `python`,
/// press Ctrl-C — the interpreter's KeyboardInterrupt fires, the shell prompt
/// does not return early, and the shim exits with the child's code. Verify in
/// cmd.exe, PowerShell and git-bash.
#[cfg(windows)]
pub fn ignore_console_ctrl() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    // Returns TRUE (1) for CTRL_C_EVENT (0) and CTRL_BREAK_EVENT (1) so the
    // shim treats them as handled and keeps running; FALSE for close/logoff/
    // shutdown so the OS still gets to tear us down normally.
    unsafe extern "system" fn handler(ctrl_type: u32) -> i32 {
        i32::from(ctrl_type == 0 || ctrl_type == 1)
    }

    // add = TRUE (1); ignore the return — worst case Ctrl-C isn't trapped.
    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}

/// No-op off Windows so the crate still builds for local dev/tests on other OSes.
#[cfg(not(windows))]
pub fn ignore_console_ctrl() {}

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
    fn strips_utf8_bom() {
        let s = parse_shim("\u{feff}C:\\x\\rg.exe\n--flag").unwrap();
        assert_eq!(s.target, PathBuf::from("C:\\x\\rg.exe"));
        assert_eq!(s.prepend_args, vec!["--flag"]);
    }

    #[test]
    fn handles_crlf() {
        let s = parse_shim("rg.exe\r\n--color always\r\n").unwrap();
        assert_eq!(s.target, PathBuf::from("rg.exe"));
        assert_eq!(s.prepend_args, vec!["--color", "always"]);
    }

    #[test]
    fn missing_arg_line_is_empty() {
        let s = parse_shim("rg.exe").unwrap();
        assert!(s.prepend_args.is_empty());
    }

    #[test]
    fn empty_is_none() {
        assert!(parse_shim("").is_none());
        assert!(parse_shim("\n").is_none());
        assert!(parse_shim("\u{feff}").is_none());
        assert!(parse_shim("   \n").is_none());
    }
}
