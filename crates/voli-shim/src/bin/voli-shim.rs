//! Console shim variant (spec §6): shares the child's console, ignores Ctrl-C
//! so the child handles it, waits, and propagates the exit code (incl. >255).
//! Injected `.shim` env vars are applied before launch; on unix the child
//! replaces this process image (`exec`) so no extra process lingers.

use std::process::Command;
use voli_shim::{EXIT_SHIM_ERROR, ignore_console_ctrl, resolve};

fn main() {
    let shim = match resolve() {
        Ok(shim) => shim,
        Err(e) => {
            eprintln!("voli-shim: {e}");
            std::process::exit(EXIT_SHIM_ERROR);
        }
    };

    ignore_console_ctrl();
    shim.apply_env();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Replaces this process: stdio, args, and the injected env carry over;
        // signals and the exit code are the child's, with no reaping needed.
        let err = Command::new(&shim.target)
            .args(&shim.prepend_args)
            .args(std::env::args_os().skip(1))
            .exec();
        eprintln!(
            "voli-shim: failed to launch {}: {err}",
            shim.target.display()
        );
        std::process::exit(EXIT_SHIM_ERROR);
    }

    #[cfg(not(unix))]
    {
        // Inherits stdio + console by default, so pipes/redirects Just Work.
        let status = Command::new(&shim.target)
            .args(&shim.prepend_args)
            .args(std::env::args_os().skip(1))
            .status()
            .unwrap_or_else(|e| {
                eprintln!("voli-shim: failed to launch {}: {e}", shim.target.display());
                std::process::exit(EXIT_SHIM_ERROR);
            });

        // Windows exit codes are u32; ExitStatus::code() returns the raw value as
        // i32 (3010 stays 3010; a >i32::MAX code round-trips through exit()). None
        // only if killed by a signal, which doesn't happen on Windows.
        std::process::exit(status.code().unwrap_or(1));
    }
}
