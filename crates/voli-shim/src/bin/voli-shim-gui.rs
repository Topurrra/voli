//! GUI shim variant (spec §6): compiled into the "windows" subsystem so it has
//! no console (no flash), launches the target DETACHED and exits immediately
//! without waiting — GUI apps own their own lifetime.
#![windows_subsystem = "windows"]

use std::process::Command;
use voli_shim::{EXIT_SHIM_ERROR, resolve};

fn main() {
    let shim = match resolve() {
        Ok(shim) => shim,
        // ponytail: no console to print to; a MessageBox on failure is the
        // upgrade if silent-exit ever confuses users. This path only fires on a
        // corrupt install (shim written, target/.shim missing).
        Err(_) => std::process::exit(EXIT_SHIM_ERROR),
    };

    // spawn (not status): fire-and-forget. Dropping the child handle does not
    // kill it — the target keeps running after this process exits.
    match Command::new(&shim.target)
        .args(&shim.prepend_args)
        .args(std::env::args_os().skip(1))
        .spawn()
    {
        Ok(_child) => std::process::exit(0),
        Err(_) => std::process::exit(EXIT_SHIM_ERROR),
    }
}
