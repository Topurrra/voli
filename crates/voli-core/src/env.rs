//! User-level environment variables (spec §6, §8).
//!
//! Every mutation returns the **prior** state so callers can ledger it for the
//! uninstall guarantee.
//!
//! * **Windows**: the backing store is `HKCU\Environment` (registry). The
//!   registry subkey is injectable (`subkey` parameter): production passes
//!   [`ENVIRONMENT`]; tests pass a throwaway subkey under `Software\` so they
//!   never touch the real user environment.
//! * **Linux/macOS (shim-injected env)**: there is no global registry to write.
//!   Per-package env vars are embedded into each shim file at install time (see
//!   `install::shim_body` / `voli-shim`), so they apply to the shimmed process
//!   only and vanish with the shims on uninstall. The functions below persist
//!   the *recorded* global view to a JSON file instead — `<voli-root>/env.json`
//!   for the production subkey, temp files for scratch subkeys — so `voli env`,
//!   `doctor`, and the ledger-replay tests keep working without touching shell
//!   rc files. Voli never edits `~/.profile`, `~/.zshrc`, or fish config; the
//!   shims directory itself gets on PATH once via `install.sh`.
//!
//! PATH is handled specially: prepend semantics and exact-segment matching.
//! On Windows the value's registry type (`REG_EXPAND_SZ` vs `REG_SZ`) is
//! preserved on write — clobbering `REG_EXPAND_SZ` to `REG_SZ` would stop
//! `%VAR%` references in PATH from expanding. On unix PATH is `:`-separated
//! and case-sensitive.

use std::io;

/// The real user-environment subkey (Windows) / store name (unix).
/// Tests substitute their own.
pub const ENVIRONMENT: &str = "Environment";

/// The registry subkey (Windows) or store name (unix) env mutations target:
/// `VOLI_ENV_SUBKEY` if set (the test hook — points at a throwaway subkey so
/// tests never touch the real user Environment), else [`ENVIRONMENT`]. Lives
/// here so both the CLI and the core install/uninstall flows resolve the same
/// subkey (spec §8).
pub fn env_subkey() -> String {
    std::env::var("VOLI_ENV_SUBKEY").unwrap_or_else(|_| ENVIRONMENT.to_string())
}

/// Case-insensitive segment comparison on Windows (tolerant of a trailing
/// separator); case-sensitive on unix (where `:` separates and `/` trails).
#[cfg(windows)]
fn seg_eq(a: &str, b: &str) -> bool {
    // Plain fn (not a closure): elided lifetimes tie the return to the
    // argument, which a `|s: &str|` closure does not do. Compared with
    // `eq_ignore_ascii_case` (not two `to_ascii_lowercase()`s) per clippy.
    fn norm(s: &str) -> &str {
        s.trim().trim_end_matches(['\\', '/'])
    }
    norm(a).eq_ignore_ascii_case(norm(b))
}

#[cfg(not(windows))]
fn seg_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('/').to_string();
    norm(a) == norm(b)
}

/// Whether `path` (a PATH string) already contains `segment` as an exact
/// segment. Public so [`crate::selfinstall`] and `doctor` can reuse it.
#[cfg(windows)]
pub fn path_has_segment(path: &str, segment: &str) -> bool {
    path.split(';').any(|s| seg_eq(s, segment))
}

/// Whether `path` (a `:`-joined PATH string) already contains `segment` as an
/// exact segment. Public so [`crate::selfinstall`] and `doctor` can reuse it.
#[cfg(not(windows))]
pub fn path_has_segment(path: &str, segment: &str) -> bool {
    path.split(':').any(|s| seg_eq(s, segment))
}

// ---------------------------------------------------------------------------
// Windows backend (registry)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod backend {
    use super::*;
    use winreg::RegKey;
    use winreg::RegValue;
    use winreg::enums::{HKEY_CURRENT_USER, RegType};
    use winreg::types::FromRegValue;

    /// Open (creating if absent) an `HKCU\<subkey>` with read+write access.
    /// `pub(super)` so the unit tests in the parent module can probe raw
    /// values (e.g. the PATH registry type) without going through `get`.
    pub(super) fn open(subkey: &str) -> io::Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(subkey)
            .map(|(key, _)| key)
    }

    fn read_value(key: &RegKey, name: &str) -> io::Result<Option<String>> {
        match key.get_value::<String, _>(name) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Current value of `name`, or `None` if unset.
    pub fn get(subkey: &str, name: &str) -> io::Result<Option<String>> {
        read_value(&open(subkey)?, name)
    }

    /// Set `name` to `value` (REG_SZ). Returns the prior value.
    pub fn set(subkey: &str, name: &str, value: &str) -> io::Result<Option<String>> {
        let key = open(subkey)?;
        let prior = read_value(&key, name)?;
        key.set_value(name, &value.to_string())?;
        Ok(prior)
    }

    /// Delete `name`. Returns the prior value (`None` if it did not exist).
    pub fn delete(subkey: &str, name: &str) -> io::Result<Option<String>> {
        let key = open(subkey)?;
        let prior = read_value(&key, name)?;
        if prior.is_some() {
            key.delete_value(name)?;
        }
        Ok(prior)
    }

    /// Read PATH along with its registry type (defaulting to `REG_EXPAND_SZ`
    /// when PATH does not yet exist — that is the conventional type for it).
    fn read_path(key: &RegKey) -> io::Result<(Option<String>, RegType)> {
        match key.get_raw_value("Path") {
            Ok(rv) => {
                let vtype = rv.vtype.clone();
                let s = String::from_reg_value(&rv)?;
                Ok((Some(s), vtype))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((None, RegType::REG_EXPAND_SZ)),
            Err(e) => Err(e),
        }
    }

    fn write_path(key: &RegKey, value: &str, vtype: RegType) -> io::Result<()> {
        if vtype == RegType::REG_EXPAND_SZ {
            let bytes: Vec<u8> = value
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            key.set_raw_value(
                "Path",
                &RegValue {
                    bytes,
                    vtype: RegType::REG_EXPAND_SZ,
                },
            )
        } else {
            key.set_value("Path", &value.to_string())
        }
    }

    /// Prepend `segment` to PATH if not already present. Idempotent. Returns
    /// the prior PATH value.
    pub fn add_to_path(subkey: &str, segment: &str) -> io::Result<Option<String>> {
        let key = open(subkey)?;
        let (prior, vtype) = read_path(&key)?;
        let current = prior.clone().unwrap_or_default();
        if super::path_has_segment(&current, segment) {
            return Ok(prior);
        }
        let next = if current.is_empty() {
            segment.to_string()
        } else {
            format!("{segment};{current}")
        };
        write_path(&key, &next, vtype)?;
        Ok(prior)
    }

    /// Remove every exact occurrence of `segment` from PATH. Returns the prior
    /// PATH.
    pub fn remove_from_path(subkey: &str, segment: &str) -> io::Result<Option<String>> {
        let key = open(subkey)?;
        let (prior, vtype) = read_path(&key)?;
        let Some(current) = prior.clone() else {
            return Ok(None);
        };
        let kept: Vec<&str> = current
            .split(';')
            .filter(|s| !super::seg_eq(s, segment))
            .collect();
        let next = kept.join(";");
        if next != current {
            write_path(&key, &next, vtype)?;
        }
        Ok(prior)
    }

    /// Delete a whole subkey and its values. Intended for test cleanup — never
    /// call it on [`super::ENVIRONMENT`].
    pub fn delete_subkey(subkey: &str) -> io::Result<()> {
        match RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(subkey) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Unix backend (file-backed store; execution-time env lives in shims)
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod backend {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// File holding the store for `subkey`.
    ///
    /// Production (`Environment`) lives at `<voli-root>/env.json` so it moves
    /// with the install and `VOLI_ROOT` test isolation keeps working. Scratch
    /// subkeys map to sanitized files under `VOLI_ENV_DIR` (test hook) or the
    /// system temp dir, so parallel tests never share state.
    fn store_path(subkey: &str) -> PathBuf {
        if subkey == super::ENVIRONMENT {
            if let Ok(root) = crate::config::resolve_root() {
                return root.join("env.json");
            }
            if let Some(home) = crate::paths::user_home() {
                return home.join(".config").join("voli").join("env.json");
            }
            return std::env::temp_dir().join("voli-env.json");
        }
        let mut name: String = subkey
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if name.is_empty() {
            name = "default".to_string();
        }
        // Bound the file name length; collisions across over-long distinct
        // subkeys are acceptable for a test hook.
        if name.len() > 64 {
            name.truncate(64);
        }
        let base = std::env::var_os("VOLI_ENV_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        base.join(format!("voli-env-{name}.json"))
    }

    fn path_var_name(name: &str) -> Option<&'static str> {
        if name.eq_ignore_ascii_case("path") {
            Some("PATH")
        } else {
            None
        }
    }

    fn load(path: &std::path::Path) -> BTreeMap<String, String> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn save(path: &std::path::Path, map: &BTreeMap<String, String>) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(map)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // Atomic write: stage + rename so a crash cannot leave half a file.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Current value of `name`, or `None` if unset.
    pub fn get(subkey: &str, name: &str) -> io::Result<Option<String>> {
        let map = load(&store_path(subkey));
        if let Some(path_name) = path_var_name(name) {
            if let Some(v) = map.get(path_name) {
                return Ok(Some(v.clone()));
            }
            // Fall back to the legacy `Path` spelling if present.
            return Ok(map.get("Path").cloned());
        }
        Ok(map.get(name).cloned())
    }

    /// Set `name` to `value`. Returns the prior value.
    pub fn set(subkey: &str, name: &str, value: &str) -> io::Result<Option<String>> {
        let path = store_path(subkey);
        let mut map = load(&path);
        let key = path_var_name(name).unwrap_or(name).to_string();
        // Collapse legacy spellings onto `PATH`.
        let prior = map.insert(key.clone(), value.to_string());
        let prior = prior.or_else(|| {
            if key == "PATH" {
                map.remove("Path")
            } else {
                None
            }
        });
        save(&path, &map)?;
        Ok(prior)
    }

    /// Delete `name`. Returns the prior value (`None` if it did not exist).
    pub fn delete(subkey: &str, name: &str) -> io::Result<Option<String>> {
        let path = store_path(subkey);
        let mut map = load(&path);
        let mut prior = map.remove(name);
        if path_var_name(name).is_some() {
            // `PATH`/`Path` are one variable on unix; clear both spellings.
            let other = if name == "PATH" { "Path" } else { "PATH" };
            if let Some(v) = map.remove(other) {
                prior = prior.or(Some(v));
            }
        }
        save(&path, &map)?;
        Ok(prior)
    }

    /// Prepend `segment` to PATH if not already present. Idempotent. Returns
    /// the prior PATH value.
    pub fn add_to_path(subkey: &str, segment: &str) -> io::Result<Option<String>> {
        let path = store_path(subkey);
        let mut map = load(&path);
        // Prefer the canonical `PATH` entry; migrate a legacy `Path` one.
        let current = map
            .remove("PATH")
            .or_else(|| map.remove("Path"))
            .unwrap_or_default();
        let prior = if current.is_empty() {
            None
        } else {
            Some(current.clone())
        };
        if !current.is_empty() && super::path_has_segment(&current, segment) {
            map.insert("PATH".to_string(), current);
            save(&path, &map)?;
            return Ok(prior);
        }
        let next = if current.is_empty() {
            segment.to_string()
        } else {
            format!("{segment}:{current}")
        };
        map.insert("PATH".to_string(), next);
        save(&path, &map)?;
        Ok(prior)
    }

    /// Remove every exact occurrence of `segment` from PATH. Returns the prior
    /// PATH.
    pub fn remove_from_path(subkey: &str, segment: &str) -> io::Result<Option<String>> {
        let path = store_path(subkey);
        let mut map = load(&path);
        let current = map.remove("PATH").or_else(|| map.remove("Path"));
        let Some(current) = current else {
            save(&path, &map)?;
            return Ok(None);
        };
        let prior = Some(current.clone());
        let kept: Vec<&str> = current
            .split(':')
            .filter(|s| !super::seg_eq(s, segment))
            .collect();
        let next = kept.join(":");
        if next.is_empty() {
            // Drop the key entirely so `get` reports unset (matches the
            // Windows behaviour of writing back an empty PATH only when it
            // changed; an empty PATH is useless on unix).
            if next != current {
                // changed → key already removed
            } else {
                map.insert("PATH".to_string(), current);
            }
        } else {
            map.insert("PATH".to_string(), next);
        }
        save(&path, &map)?;
        Ok(prior)
    }

    /// Delete a whole store file. Intended for test cleanup — never call it on
    /// [`super::ENVIRONMENT`] in production code.
    pub fn delete_subkey(subkey: &str) -> io::Result<()> {
        let path = store_path(subkey);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub use backend::{add_to_path, delete, delete_subkey, get, remove_from_path, set};

/// Broadcast an environment change so already-open shells notice (spec §6).
/// Windows posts `WM_SETTINGCHANGE`; on unix there is nothing to notify
/// (shims read their env at exec time), so this is a no-op. Best-effort —
/// failure to notify is not fatal.
#[cfg(windows)]
pub fn broadcast_change() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };
    let param: Vec<u16> = "Environment\0".encode_utf16().collect();
    // SAFETY: a well-formed broadcast message; the wide string outlives the call.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            param.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            std::ptr::null_mut(),
        );
    }
}

#[cfg(not(windows))]
pub fn broadcast_change() {}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    // Each test uses its own subkey so they can run in parallel and never touch
    // the real user Environment.
    fn scratch(name: &str) -> String {
        format!("Software\\voli-test-env\\{name}")
    }

    #[test]
    fn set_get_delete_returns_prior() {
        let sk = scratch("setget");
        let _ = delete_subkey(&sk);

        assert_eq!(get(&sk, "FOO").unwrap(), None);
        // first set: no prior
        assert_eq!(set(&sk, "FOO", "one").unwrap(), None);
        assert_eq!(get(&sk, "FOO").unwrap().as_deref(), Some("one"));
        // second set: prior returned
        assert_eq!(set(&sk, "FOO", "two").unwrap().as_deref(), Some("one"));
        // delete: prior returned
        assert_eq!(delete(&sk, "FOO").unwrap().as_deref(), Some("two"));
        assert_eq!(delete(&sk, "FOO").unwrap(), None);

        delete_subkey(&sk).unwrap();
    }

    #[test]
    fn path_add_is_idempotent_and_prepends() {
        let sk = scratch("pathadd");
        let _ = delete_subkey(&sk);

        // seed an existing PATH
        set(&sk, "Path", "C:\\existing").unwrap();

        let prior = add_to_path(&sk, "C:\\voli\\shims").unwrap();
        assert_eq!(prior.as_deref(), Some("C:\\existing"));
        assert_eq!(
            get(&sk, "Path").unwrap().as_deref(),
            Some("C:\\voli\\shims;C:\\existing")
        );

        // adding again is a no-op and does not duplicate
        let prior2 = add_to_path(&sk, "C:\\voli\\shims").unwrap();
        assert_eq!(prior2.as_deref(), Some("C:\\voli\\shims;C:\\existing"));
        assert_eq!(
            get(&sk, "Path").unwrap().as_deref(),
            Some("C:\\voli\\shims;C:\\existing")
        );

        delete_subkey(&sk).unwrap();
    }

    #[test]
    fn path_remove_exact_segment() {
        let sk = scratch("pathremove");
        let _ = delete_subkey(&sk);

        set(&sk, "Path", "A;C:\\voli\\shims;B").unwrap();
        let prior = remove_from_path(&sk, "C:\\voli\\shims").unwrap();
        assert_eq!(prior.as_deref(), Some("A;C:\\voli\\shims;B"));
        assert_eq!(get(&sk, "Path").unwrap().as_deref(), Some("A;B"));

        // trailing-slash tolerance
        set(&sk, "Path", "A;C:\\voli\\shims\\;B").unwrap();
        remove_from_path(&sk, "C:\\voli\\shims").unwrap();
        assert_eq!(get(&sk, "Path").unwrap().as_deref(), Some("A;B"));

        delete_subkey(&sk).unwrap();
    }

    #[test]
    fn path_type_preserved_as_expand_sz() {
        let sk = scratch("pathtype");
        let _ = delete_subkey(&sk);

        // add to a nonexistent PATH -> created as REG_EXPAND_SZ
        add_to_path(&sk, "%USERPROFILE%\\bin").unwrap();
        let key = super::backend::open(&sk).unwrap();
        let raw = key.get_raw_value("Path").unwrap();
        assert_eq!(raw.vtype, winreg::enums::RegType::REG_EXPAND_SZ);

        delete_subkey(&sk).unwrap();
    }
}

#[cfg(all(test, not(windows)))]
mod unix_tests {
    use super::*;

    fn scratch(name: &str) -> String {
        format!("voli-test-env-{name}-{}", std::process::id())
    }

    #[test]
    fn set_get_delete_returns_prior() {
        let sk = scratch("setget");
        let _ = delete_subkey(&sk);

        assert_eq!(get(&sk, "FOO").unwrap(), None);
        assert_eq!(set(&sk, "FOO", "one").unwrap(), None);
        assert_eq!(get(&sk, "FOO").unwrap().as_deref(), Some("one"));
        assert_eq!(set(&sk, "FOO", "two").unwrap().as_deref(), Some("one"));
        assert_eq!(delete(&sk, "FOO").unwrap().as_deref(), Some("two"));
        assert_eq!(delete(&sk, "FOO").unwrap(), None);

        delete_subkey(&sk).unwrap();
    }

    #[test]
    fn path_add_is_idempotent_and_prepends_with_colon() {
        let sk = scratch("pathadd");
        let _ = delete_subkey(&sk);

        set(&sk, "PATH", "/existing").unwrap();

        let prior = add_to_path(&sk, "/voli/shims").unwrap();
        assert_eq!(prior.as_deref(), Some("/existing"));
        assert_eq!(
            get(&sk, "PATH").unwrap().as_deref(),
            Some("/voli/shims:/existing")
        );

        let prior2 = add_to_path(&sk, "/voli/shims").unwrap();
        assert_eq!(prior2.as_deref(), Some("/voli/shims:/existing"));
        assert_eq!(
            get(&sk, "PATH").unwrap().as_deref(),
            Some("/voli/shims:/existing")
        );

        delete_subkey(&sk).unwrap();
    }

    #[test]
    fn path_remove_exact_segment_colon_separated() {
        let sk = scratch("pathremove");
        let _ = delete_subkey(&sk);

        set(&sk, "PATH", "A:/voli/shims:B").unwrap();
        let prior = remove_from_path(&sk, "/voli/shims").unwrap();
        assert_eq!(prior.as_deref(), Some("A:/voli/shims:B"));
        assert_eq!(get(&sk, "PATH").unwrap().as_deref(), Some("A:B"));

        // trailing-slash tolerance
        set(&sk, "PATH", "A:/voli/shims/:B").unwrap();
        remove_from_path(&sk, "/voli/shims").unwrap();
        assert_eq!(get(&sk, "PATH").unwrap().as_deref(), Some("A:B"));

        // `Path` spelling aliases `PATH` on unix
        set(&sk, "Path", "X").unwrap();
        assert_eq!(get(&sk, "PATH").unwrap().as_deref(), Some("X"));

        delete_subkey(&sk).unwrap();
    }

    #[test]
    fn path_matching_is_case_sensitive_on_unix() {
        assert!(path_has_segment("/A:/b", "/A"));
        assert!(!path_has_segment("/A:/b", "/a"));
        // `;` is data on unix, not a separator
        assert!(!path_has_segment("A;B", "A"));
    }
}
