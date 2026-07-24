//! User-level environment variables via `HKCU\Environment` (spec §6, §8).
//!
//! Every mutation returns the **prior** state so callers can ledger it for the
//! uninstall guarantee. The registry subkey is injectable (`subkey` parameter):
//! production passes [`ENVIRONMENT`]; tests pass a throwaway subkey under
//! `Software\` so they never touch the real user environment.
//!
//! PATH is handled specially: prepend semantics, exact-segment matching, and the
//! value's registry type (`REG_EXPAND_SZ` vs `REG_SZ`) is preserved on write —
//! clobbering `REG_EXPAND_SZ` to `REG_SZ` would stop `%VAR%` references in PATH
//! from expanding.

use std::io;

use winreg::RegKey;
use winreg::RegValue;
use winreg::enums::{HKEY_CURRENT_USER, RegType};
use winreg::types::FromRegValue;

/// The real user-environment subkey. Tests substitute their own.
pub const ENVIRONMENT: &str = "Environment";

/// The registry subkey env mutations target: `VOLI_ENV_SUBKEY` if set (the test
/// hook — points at a throwaway subkey so tests never touch the real user
/// Environment), else [`ENVIRONMENT`]. Lives here so both the CLI and the core
/// install/uninstall flows resolve the same subkey (spec §8).
pub fn env_subkey() -> String {
    std::env::var("VOLI_ENV_SUBKEY").unwrap_or_else(|_| ENVIRONMENT.to_string())
}

/// Open (creating if absent) an `HKCU\<subkey>` with read+write access.
fn open(subkey: &str) -> io::Result<RegKey> {
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

/// Read PATH along with its registry type (defaulting to `REG_EXPAND_SZ` when
/// PATH does not yet exist — that is the conventional type for it).
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

/// Case-insensitive segment comparison, tolerant of a trailing separator.
fn seg_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches(['\\', '/']).to_ascii_lowercase();
    norm(a) == norm(b)
}

/// Whether `path` (a `;`-joined PATH string) already contains `segment` as an
/// exact segment. Public so [`crate::selfinstall`] and `doctor` can reuse it.
pub fn path_has_segment(path: &str, segment: &str) -> bool {
    path.split(';').any(|s| seg_eq(s, segment))
}

/// Prepend `segment` to PATH if not already present. Idempotent. Returns the
/// prior PATH value.
pub fn add_to_path(subkey: &str, segment: &str) -> io::Result<Option<String>> {
    let key = open(subkey)?;
    let (prior, vtype) = read_path(&key)?;
    let current = prior.clone().unwrap_or_default();
    if path_has_segment(&current, segment) {
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

/// Remove every exact occurrence of `segment` from PATH. Returns the prior PATH.
pub fn remove_from_path(subkey: &str, segment: &str) -> io::Result<Option<String>> {
    let key = open(subkey)?;
    let (prior, vtype) = read_path(&key)?;
    let Some(current) = prior.clone() else {
        return Ok(None);
    };
    let kept: Vec<&str> = current.split(';').filter(|s| !seg_eq(s, segment)).collect();
    let next = kept.join(";");
    if next != current {
        write_path(&key, &next, vtype)?;
    }
    Ok(prior)
}

/// Broadcast `WM_SETTINGCHANGE` so already-open shells notice the env change
/// (spec §6). Best-effort — failure to notify is not fatal.
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

/// Delete a whole subkey and its values. Intended for test cleanup — never call
/// it on [`ENVIRONMENT`].
pub fn delete_subkey(subkey: &str) -> io::Result<()> {
    match RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(subkey) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
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
        let key = open(&sk).unwrap();
        let raw = key.get_raw_value("Path").unwrap();
        assert_eq!(raw.vtype, RegType::REG_EXPAND_SZ);

        delete_subkey(&sk).unwrap();
    }
}
