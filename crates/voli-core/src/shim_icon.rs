//! Copy a target executable's own icon into a freshly-created shim (spec §6 /
//! install step 7). Windows-only; every entry point is best-effort.
//!
//! Each `shims\<app>.exe` starts life as a byte copy of a shim stub, so out of
//! the box it shows voli's bear icon in Explorer and on taskbar pins. Here we
//! read the primary icon group (`RT_GROUP_ICON` plus the `RT_ICON` images it
//! references) out of the real target exe — which already carries the app's own
//! icon from the app's own build — and overwrite the stub's icon (group id 1)
//! with it. The shim's code, entry point and every other resource are left
//! untouched, so it still launches the target and forwards args/stdio/exit codes
//! exactly as before; only the picture Explorer paints changes.
//!
//! An install must never fail over cosmetics, so the public entry point returns
//! `Ok(false)` (and leaves the working stub-icon shim in place) whenever the
//! target has no readable icon, and only surfaces an error when the in-place
//! resource update itself fails — which the caller also treats as non-fatal.

use core::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{BOOL, FreeLibrary, HANDLE, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    BeginUpdateResourceW, EndUpdateResourceW, EnumResourceLanguagesW, EnumResourceNamesW,
    FindResourceW, LOAD_LIBRARY_AS_DATAFILE, LoadLibraryExW, LoadResource, LockResource,
    SizeofResource, UpdateResourceW,
};
use windows_sys::core::PCWSTR;

// MAKEINTRESOURCEW ordinals for the two resource types we touch: an integer
// resource id is simply the value in the low word of the "pointer".
const RT_ICON: PCWSTR = 3 as PCWSTR;
const RT_GROUP_ICON: PCWSTR = 14 as PCWSTR;

/// The primary icon read out of a target exe, ready to write into a shim: the
/// `RT_GROUP_ICON` directory bytes plus each `(resource id, RT_ICON bytes)` it
/// references. Icon ids are kept exactly as the source uses them (the group's
/// entries point at them by id); only the group itself is re-homed to id 1 on
/// write, so it overrides the stub's own icon and wins the shell's lowest-id
/// selection.
struct PrimaryIcon {
    group: Vec<u8>,
    images: Vec<(u16, Vec<u8>)>,
}

/// Give `shim` the icon that `target` carries. Returns `Ok(true)` if an icon was
/// copied, `Ok(false)` if `target` has no readable icon (a clean no-op that
/// keeps the stub icon), or an error only if the in-place resource update fails
/// — in which case `shim` is left byte-identical to the working stub copy.
pub fn copy_exe_icon(target: &Path, shim: &Path) -> io::Result<bool> {
    let Some(icon) = read_primary_icon(target) else {
        return Ok(false);
    };
    // Overwrite in the stub's own resource language so we replace its icon
    // rather than add a second-language variant. winresource embeds at neutral
    // (0); discover it anyway so this stays correct if the stub ever changes.
    let lang = stub_icon_lang(shim).unwrap_or(0);
    write_icon(shim, &icon, lang)?;
    Ok(true)
}

/// Read the primary `RT_GROUP_ICON` directory bytes from a PE, if any. Public so
/// the install engine's tests can prove the shim's icon actually changed.
pub fn primary_group_icon(exe: &Path) -> Option<Vec<u8>> {
    read_primary_icon(exe).map(|icon| icon.group)
}

fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn read_primary_icon(exe: &Path) -> Option<PrimaryIcon> {
    let wide = to_wide(exe);
    // LOAD_LIBRARY_AS_DATAFILE maps the file for resource reads only — no code
    // runs, and a non-PE / unreadable file just yields a null handle.
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_AS_DATAFILE,
        )
    };
    if module.is_null() {
        return None;
    }
    let icon = read_loaded(module);
    unsafe { FreeLibrary(module) };
    icon
}

fn read_loaded(module: HMODULE) -> Option<PrimaryIcon> {
    // The first enumerated RT_GROUP_ICON is the one the shell shows (the resource
    // directory is sorted, so lowest id / first name comes first).
    let mut first = FirstName {
        name: std::ptr::null(),
        found: false,
    };
    unsafe {
        EnumResourceNamesW(
            module,
            RT_GROUP_ICON,
            Some(on_first_name),
            &mut first as *mut FirstName as isize,
        );
    }
    if !first.found {
        return None;
    }

    let group = load_bytes(module, first.name, RT_GROUP_ICON)?;
    // GRPICONDIR: 6-byte header (reserved u16, type u16, count u16) then
    // count * 14-byte GRPICONDIRENTRY. The entry's trailing u16 (offset +12) is
    // the id of the RT_ICON resource holding that image.
    if group.len() < 6 {
        return None;
    }
    let count = u16::from_le_bytes([group[4], group[5]]) as usize;
    if count == 0 || group.len() < 6 + count * 14 {
        return None;
    }
    let mut images = Vec::with_capacity(count);
    for i in 0..count {
        let off = 6 + i * 14 + 12;
        let id = u16::from_le_bytes([group[off], group[off + 1]]);
        images.push((id, load_bytes(module, id as usize as PCWSTR, RT_ICON)?));
    }
    Some(PrimaryIcon { group, images })
}

/// Copy the raw bytes of one resource out of a datafile-loaded module.
fn load_bytes(module: HMODULE, name: PCWSTR, typ: PCWSTR) -> Option<Vec<u8>> {
    unsafe {
        let info = FindResourceW(module, name, typ);
        if info.is_null() {
            return None;
        }
        let size = SizeofResource(module, info) as usize;
        let data = LoadResource(module, info);
        if data.is_null() || size == 0 {
            return None;
        }
        let ptr = LockResource(data) as *const u8;
        if ptr.is_null() {
            return None;
        }
        Some(std::slice::from_raw_parts(ptr, size).to_vec())
    }
}

/// Language of the stub's own primary group icon (winres writes it at id 1), so
/// we overwrite exactly that variant. `None` if it can't be determined.
fn stub_icon_lang(exe: &Path) -> Option<u16> {
    let wide = to_wide(exe);
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_AS_DATAFILE,
        )
    };
    if module.is_null() {
        return None;
    }
    let mut first = FirstLang {
        lang: 0,
        found: false,
    };
    unsafe {
        EnumResourceLanguagesW(
            module,
            RT_GROUP_ICON,
            1_usize as PCWSTR,
            Some(on_first_lang),
            &mut first as *mut FirstLang as isize,
        );
        FreeLibrary(module);
    }
    first.found.then_some(first.lang)
}

fn write_icon(shim: &Path, icon: &PrimaryIcon, lang: u16) -> io::Result<()> {
    let wide = to_wide(shim);
    // FALSE: keep the stub's other resources (version info, any manifest) — we
    // only swap the icon, so the PE is otherwise byte-for-byte the same stub.
    let update = unsafe { BeginUpdateResourceW(wide.as_ptr(), 0) };
    if update.is_null() {
        return Err(io::Error::last_os_error());
    }
    let queued = queue_icon(update, icon, lang);
    // Commit only a fully-queued icon; on any queue failure discard so the shim
    // stays the working stub copy rather than a half-updated file.
    let ended = unsafe { EndUpdateResourceW(update, i32::from(queued.is_err())) };
    queued?;
    if ended == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Queue every RT_ICON at its source id, then the group at id 1 (overwriting the
/// stub's icon so the shell paints the app's).
fn queue_icon(update: HANDLE, icon: &PrimaryIcon, lang: u16) -> io::Result<()> {
    for (id, bytes) in &icon.images {
        put(update, RT_ICON, *id as usize as PCWSTR, lang, bytes)?;
    }
    put(update, RT_GROUP_ICON, 1_usize as PCWSTR, lang, &icon.group)
}

fn put(update: HANDLE, typ: PCWSTR, name: PCWSTR, lang: u16, bytes: &[u8]) -> io::Result<()> {
    let ok = unsafe {
        UpdateResourceW(
            update,
            typ,
            name,
            lang,
            bytes.as_ptr() as *const c_void,
            bytes.len() as u32,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct FirstName {
    name: PCWSTR,
    found: bool,
}

/// Capture the first enumerated resource name, then stop. The name pointer stays
/// valid while the module is loaded (it's either an ordinal or points into the
/// module image), which it is for the rest of the read.
unsafe extern "system" fn on_first_name(
    _module: HMODULE,
    _typ: PCWSTR,
    name: PCWSTR,
    param: isize,
) -> BOOL {
    let out = unsafe { &mut *(param as *mut FirstName) };
    out.name = name;
    out.found = true;
    0 // FALSE: stop after the first (lowest-id) group
}

struct FirstLang {
    lang: u16,
    found: bool,
}

unsafe extern "system" fn on_first_lang(
    _module: HMODULE,
    _typ: PCWSTR,
    _name: PCWSTR,
    wlang: u16,
    param: isize,
) -> BOOL {
    let out = unsafe { &mut *(param as *mut FirstLang) };
    out.lang = wlang;
    out.found = true;
    0 // FALSE: stop after the first language
}
