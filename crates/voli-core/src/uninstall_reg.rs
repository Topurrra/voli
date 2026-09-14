//! Apps & Features registration via per-user Uninstall registry keys.
//!
//! Windows only. On Linux/macOS there is no central uninstall registry —
//! removal is the ledger replay itself — so every function below is a
//! successful no-op that keeps the install engine's action log portable.
//!
//! On every package install (Windows), writes a key under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\voli.<name>`
//! so the package appears in Windows Settings → Apps with a working
//! Uninstall button that routes through `voli delete`.
//!
//! The base subkey is injectable (`subkey` parameter): production passes
//! [`UNINSTALL_BASE`]; tests pass a throwaway subkey so they never touch
//! the real Uninstall key. Override with `VOLI_UNINSTALL_SUBKEY`.

use std::io;
use std::path::Path;

/// The real Uninstall base subkey.
pub const UNINSTALL_BASE: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

/// Resolve the base subkey: `VOLI_UNINSTALL_SUBKEY` if set (test hook),
/// else [`UNINSTALL_BASE`].
pub fn uninstall_base() -> String {
    std::env::var("VOLI_UNINSTALL_SUBKEY").unwrap_or_else(|_| UNINSTALL_BASE.to_string())
}

/// The full subkey for a package: `<base>\voli.<name>`.
pub fn package_subkey(base: &str, name: &str) -> String {
    format!("{base}\\voli.{name}")
}

#[cfg(windows)]
mod backend {
    use super::*;
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};

    /// Write (or overwrite) the Uninstall key for a package.
    #[allow(clippy::too_many_arguments)]
    pub fn write_key(
        base: &str,
        name: &str,
        version: &str,
        install_location: &Path,
        display_icon: &str,
        voli_exe: &Path,
        estimated_size_kb: u64,
    ) -> io::Result<()> {
        let subkey = super::package_subkey(base, name);
        let (key, _) =
            RegKey::predef(HKEY_CURRENT_USER).create_subkey_with_flags(&subkey, KEY_WRITE)?;

        let uninstall = format!("\"{}\" delete {name}", voli_exe.display());
        let quiet = format!("{uninstall} --yes");

        key.set_value("DisplayName", &format!("{name} (voli)"))?;
        key.set_value("DisplayVersion", &version.to_string())?;
        key.set_value("Publisher", &"voli registry".to_string())?;
        key.set_value(
            "InstallLocation",
            &install_location.to_string_lossy().into_owned(),
        )?;
        key.set_value("DisplayIcon", &display_icon.to_string())?;
        key.set_value("UninstallString", &uninstall)?;
        key.set_value("QuietUninstallString", &quiet)?;
        key.set_value("NoModify", &1u32)?;
        key.set_value("NoRepair", &1u32)?;
        key.set_value("EstimatedSize", &(estimated_size_kb as u32))?;

        Ok(())
    }

    /// Delete the Uninstall key for a package. No-op if absent.
    pub fn delete_key(base: &str, name: &str) -> io::Result<()> {
        let subkey = super::package_subkey(base, name);
        match RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&subkey) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Check whether the Uninstall key exists for a package.
    pub fn key_exists(base: &str, name: &str) -> bool {
        let subkey = super::package_subkey(base, name);
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(&subkey)
            .is_ok()
    }

    /// List all `voli.*` subkeys under `base` (for doctor orphan detection).
    pub fn list_voli_keys(base: &str) -> io::Result<Vec<String>> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let base_key = match hkcu.open_subkey(base) {
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut names = Vec::new();
        for subkey in base_key.enum_keys() {
            let subkey = subkey?;
            if let Some(pkg) = subkey.strip_prefix("voli.") {
                names.push(pkg.to_string());
            }
        }
        Ok(names)
    }

    /// Delete a whole base subkey tree. Test cleanup only — never call on
    /// [`super::UNINSTALL_BASE`].
    pub fn delete_base(base: &str) -> io::Result<()> {
        match RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(base) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(not(windows))]
mod backend {
    use super::*;

    /// No central uninstall registry on unix — always succeeds without writing.
    #[allow(clippy::too_many_arguments)]
    pub fn write_key(
        _base: &str,
        _name: &str,
        _version: &str,
        _install_location: &Path,
        _display_icon: &str,
        _voli_exe: &Path,
        _estimated_size_kb: u64,
    ) -> io::Result<()> {
        Ok(())
    }

    /// No central uninstall registry on unix — always succeeds.
    pub fn delete_key(_base: &str, _name: &str) -> io::Result<()> {
        Ok(())
    }

    /// No central uninstall registry on unix — never present.
    pub fn key_exists(_base: &str, _name: &str) -> bool {
        false
    }

    /// No central uninstall registry on unix — no orphans possible.
    pub fn list_voli_keys(_base: &str) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Test cleanup only — no-op on unix (nothing is stored).
    pub fn delete_base(_base: &str) -> io::Result<()> {
        Ok(())
    }
}

pub use backend::{delete_base, delete_key, key_exists, list_voli_keys, write_key};

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn scratch(name: &str) -> String {
        format!("Software\\voli-test-uninstall\\{name}")
    }

    #[test]
    fn write_then_exists_then_delete() {
        let base = scratch("basic");
        let _ = delete_base(&base);

        assert!(!key_exists(&base, "ripgrep"));

        write_key(
            &base,
            "ripgrep",
            "14.1.1",
            Path::new(r"C:\voli\apps\ripgrep\current"),
            r"C:\voli\apps\ripgrep\current\rg.exe",
            Path::new(r"C:\voli\bin\voli.exe"),
            4096,
        )
        .unwrap();

        assert!(key_exists(&base, "ripgrep"));

        // Verify values.
        let subkey = package_subkey(&base, "ripgrep");
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(&subkey)
            .unwrap();
        let display: String = key.get_value("DisplayName").unwrap();
        assert_eq!(display, "ripgrep (voli)");
        let ver: String = key.get_value("DisplayVersion").unwrap();
        assert_eq!(ver, "14.1.1");
        let no_mod: u32 = key.get_value("NoModify").unwrap();
        assert_eq!(no_mod, 1);
        let size: u32 = key.get_value("EstimatedSize").unwrap();
        assert_eq!(size, 4096);
        let command: String = key.get_value("UninstallString").unwrap();
        assert_eq!(command, r#""C:\voli\bin\voli.exe" delete ripgrep"#);

        delete_key(&base, "ripgrep").unwrap();
        assert!(!key_exists(&base, "ripgrep"));

        delete_base(&base).unwrap();
    }

    #[test]
    fn list_finds_voli_keys() {
        let base = scratch("list");
        let _ = delete_base(&base);

        write_key(&base, "aaa", "1.0", Path::new("x"), "x", Path::new("v"), 1).unwrap();
        write_key(&base, "bbb", "2.0", Path::new("x"), "x", Path::new("v"), 1).unwrap();

        let mut keys = list_voli_keys(&base).unwrap();
        keys.sort();
        assert_eq!(keys, vec!["aaa", "bbb"]);

        delete_base(&base).unwrap();
    }
}
