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

/// Parsed `.shim` file: target executable, args prepended before the caller's
/// own args, and env vars injected into the child process (unix shim-injected
/// env; Windows shims ignore `env` — the registry carries it there).
#[derive(Debug, PartialEq, Eq)]
pub struct Shim {
    pub target: PathBuf,
    pub prepend_args: Vec<String>,
    pub env: Vec<(String, String)>,
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
/// of args prepended before the caller's own args — unless it parses as a
/// `KEY=VALUE` env assignment (see [`parse_env_line`]), in which case the shim
/// carries no args and env parsing starts there. Every subsequent line that
/// parses as `KEY=VALUE` is an env var to inject (unix shim-injected env);
/// other lines are ignored. Tolerant of a leading UTF-8 BOM and of CRLF line
/// endings (`str::lines` strips the `\r`).
///
/// The `KEY=VALUE`-as-args collision (a manifest `args` line that is literally
/// `FOO=bar`) resolves to env: registry args are flag-shaped, and a bare
/// assignment is what env injection looks like.
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
    let rest: Vec<&str> = lines.collect();
    let (prepend_args, env_start) = match rest.first() {
        None => (Vec::new(), 0),
        Some(second) if parse_env_line(second).is_some() => (Vec::new(), 0),
        Some(second) => (second.split_whitespace().map(str::to_string).collect(), 1),
    };
    let env = rest[env_start..]
        .iter()
        .filter_map(|l| parse_env_line(l))
        .collect();
    Some(Shim {
        target: PathBuf::from(target),
        prepend_args,
        env,
    })
}

/// Parse one `KEY=VALUE` env line. The key must be an env-identifier
/// (`[A-Za-z_][A-Za-z0-9_]*`); the value is everything after the first `=`
/// (may be empty). A trailing `\r` (CRLF files) is stripped first.
pub fn parse_env_line(line: &str) -> Option<(String, String)> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return None,
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((key.to_string(), value.to_string()))
}

impl Shim {
    /// Inject this shim's env into the current process (before spawn/exec).
    /// `PATH` values are prepended (`:`-separated on unix, `;` on Windows)
    /// when not already present; every other var is set outright. Env lines
    /// are written by voli at install time from consented manifest `[env]`,
    /// so no validation happens here — but an empty value never unsets.
    pub fn apply_env(&self) {
        for (key, value) in &self.env {
            if value.is_empty() {
                continue;
            }
            if key.eq_ignore_ascii_case("path") {
                #[cfg(windows)]
                const SEP: char = ';';
                #[cfg(not(windows))]
                const SEP: char = ':';
                #[cfg(windows)]
                let var = "Path";
                #[cfg(not(windows))]
                let var = "PATH";
                let current = std::env::var_os(var).unwrap_or_default();
                let current = current.to_string_lossy().into_owned();
                let already = current.split(SEP).any(|s| {
                    #[cfg(windows)]
                    {
                        s.trim().trim_end_matches(['\\', '/']).to_ascii_lowercase()
                            == value
                                .trim()
                                .trim_end_matches(['\\', '/'])
                                .to_ascii_lowercase()
                    }
                    #[cfg(not(windows))]
                    {
                        s.trim().trim_end_matches('/') == value.trim().trim_end_matches('/')
                    }
                });
                if !already {
                    let next = if current.is_empty() {
                        value.clone()
                    } else {
                        format!("{value}{SEP}{current}")
                    };
                    // SAFETY: single-threaded at shim startup; no other thread
                    // reads env concurrently in these tiny binaries.
                    unsafe { std::env::set_var(var, next) };
                }
            } else {
                // SAFETY: see above.
                unsafe { std::env::set_var(key, value) };
            }
        }
    }
}

/// `<exe>.shim` sibling of the running shim binary (`rg.exe` -> `rg.shim` on
/// Windows; `rg` -> `rg.shim` on unix). On unix the extension is APPENDED
/// (`my.tool` -> `my.tool.shim`): `with_extension` would replace `.tool`.
pub fn shim_path(exe: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        exe.with_extension("shim")
    }
    #[cfg(not(windows))]
    {
        let mut s = exe.as_os_str().to_os_string();
        s.push(".shim");
        PathBuf::from(s)
    }
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
        assert!(s.env.is_empty());
    }

    #[test]
    fn parses_target_and_args() {
        let s = parse_shim("rg.exe\n--color always --hidden").unwrap();
        assert_eq!(s.target, PathBuf::from("rg.exe"));
        assert_eq!(s.prepend_args, vec!["--color", "always", "--hidden"]);
        assert!(s.env.is_empty());
    }

    #[test]
    fn strips_utf8_bom() {
        let s = parse_shim("\u{feff}C:\\x\\rg.exe\n--flag").unwrap();
        assert_eq!(s.target, PathBuf::from("C:\\x\\rg.exe"));
        assert_eq!(s.prepend_args, vec!["--flag"]);
        assert!(s.env.is_empty());
    }

    #[test]
    fn handles_crlf() {
        let s = parse_shim("rg.exe\r\n--color always\r\n").unwrap();
        assert_eq!(s.target, PathBuf::from("rg.exe"));
        assert_eq!(s.prepend_args, vec!["--color", "always"]);
        assert!(s.env.is_empty());
    }

    #[test]
    fn missing_arg_line_is_empty() {
        let s = parse_shim("rg.exe").unwrap();
        assert!(s.prepend_args.is_empty());
        assert!(s.env.is_empty());
    }

    #[test]
    fn empty_is_none() {
        assert!(parse_shim("").is_none());
        assert!(parse_shim("\n").is_none());
        assert!(parse_shim("\u{feff}").is_none());
        assert!(parse_shim("   \n").is_none());
    }

    #[test]
    fn parses_env_after_args() {
        let s =
            parse_shim("/apps/jdk/bin/java\n\nJAVA_HOME=/apps/jdk\nPATH=/apps/jdk/bin\n").unwrap();
        assert_eq!(s.target, PathBuf::from("/apps/jdk/bin/java"));
        assert!(s.prepend_args.is_empty());
        assert_eq!(
            s.env,
            vec![
                ("JAVA_HOME".to_string(), "/apps/jdk".to_string()),
                ("PATH".to_string(), "/apps/jdk/bin".to_string()),
            ]
        );
    }

    #[test]
    fn parses_args_and_env_together() {
        let s = parse_shim("/bin/tool\n--color always\nGREETING=hi\n").unwrap();
        assert_eq!(s.prepend_args, vec!["--color", "always"]);
        assert_eq!(s.env, vec![("GREETING".to_string(), "hi".to_string())]);
    }

    #[test]
    fn env_without_args_starts_on_line_two() {
        let s = parse_shim("/bin/tool\nGREETING=hi\n").unwrap();
        assert!(s.prepend_args.is_empty());
        assert_eq!(s.env, vec![("GREETING".to_string(), "hi".to_string())]);
    }

    #[test]
    fn non_env_lines_after_target_are_ignored() {
        // A second line that is neither args-shaped... everything non-empty on
        // line 2 IS args; lines 3+ that are not KEY=VALUE are dropped.
        let s = parse_shim("/bin/tool\n--flag\nnot an env line\nFOO=bar\n").unwrap();
        assert_eq!(s.prepend_args, vec!["--flag"]);
        assert_eq!(s.env, vec![("FOO".to_string(), "bar".to_string())]);
    }

    #[test]
    fn env_line_validation() {
        assert_eq!(
            parse_env_line("A=1"),
            Some(("A".to_string(), "1".to_string()))
        );
        assert_eq!(
            parse_env_line("_x9=v=w"),
            Some(("_x9".to_string(), "v=w".to_string()))
        );
        assert_eq!(parse_env_line("E="), Some(("E".to_string(), String::new())));
        assert_eq!(parse_env_line("--flag"), None);
        assert_eq!(parse_env_line("9A=1"), None);
        assert_eq!(parse_env_line("A-B=1"), None);
        assert_eq!(parse_env_line("no equals"), None);
        assert_eq!(parse_env_line(""), None);
    }

    #[test]
    fn shim_path_appends_on_unix_replaces_on_windows() {
        #[cfg(windows)]
        assert_eq!(
            shim_path(Path::new("C:\\s\\rg.exe")),
            PathBuf::from("C:\\s\\rg.shim")
        );
        #[cfg(not(windows))]
        {
            assert_eq!(shim_path(Path::new("/s/rg")), PathBuf::from("/s/rg.shim"));
            // Dotted names keep their full stem: with_extension would eat it.
            assert_eq!(
                shim_path(Path::new("/s/my.tool")),
                PathBuf::from("/s/my.tool.shim")
            );
        }
    }
}
