//! Utility functions and constants for the underlying system API.

use crate::bititer::BitIter;
use crate::failx::*;
use crate::flag::Flag;
use crate::perm::Perm;
use crate::qualifier::Qualifier;
use crate::sys::*;

use nix::unistd::{Gid, Uid};
use scopeguard::defer;
use std::ffi::{c_void, CStr, CString};
use std::io;
use std::path::Path;
use std::ptr;
#[cfg(target_os = "macos")]
use uuid::Uuid;

// Re-export acl_entry_t and acl_t from crate::sys.
pub use crate::sys::{acl_entry_t, acl_t};

/// Free memory allocated by native acl_* routines.
pub(crate) fn xacl_free<T>(ptr: *mut T) {
    assert!(!ptr.is_null());
    let ret = unsafe { acl_free(ptr as *mut c_void) };
    assert_eq!(ret, 0);
}

/// Return true if path exists, even if it's a symlink to nowhere.
#[cfg(target_os = "macos")]
fn path_exists(path: &Path, symlink_only: bool) -> bool {
    if symlink_only {
        path.symlink_metadata().is_ok()
    } else {
        path.exists()
    }
}

/// Get the native ACL for a specific file or directory.
///
/// If the file is a symlink, the `symlink_acl` argument determines whether to
/// get the ACL from the symlink itself (true) or the file it points to (false).
#[cfg(target_os = "macos")]
pub(crate) fn xacl_get_file(
    path: &Path,
    symlink_acl: bool,
    default_acl: bool,
) -> io::Result<acl_t> {
    use std::os::unix::ffi::OsStrExt;

    if default_acl {
        return fail_custom("macOS does not support default ACL");
    }

    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let acl = if symlink_acl {
        unsafe { acl_get_link_np(c_path.as_ptr(), acl_type_t_ACL_TYPE_EXTENDED) }
    } else {
        unsafe { acl_get_file(c_path.as_ptr(), acl_type_t_ACL_TYPE_EXTENDED) }
    };

    if acl.is_null() {
        let func = if symlink_acl {
            "acl_get_link_np"
        } else {
            "acl_get_file"
        };
        let err = log_err("null", func, &c_path);

        // acl_get_file et al. can return NULL (ENOENT) if the file exists, but
        // there is no ACL. If the path exists, return an *empty* ACL.
        if let Some(sg::ENOENT) = err.raw_os_error() {
            if path_exists(&path, symlink_acl) {
                return xacl_init(1);
            }
        }

        return Err(err);
    }

    Ok(acl)
}

#[cfg(target_os = "linux")]
pub(crate) fn xacl_get_file(
    path: &Path,
    symlink_acl: bool,
    default_acl: bool,
) -> io::Result<acl_t> {
    use std::os::unix::ffi::OsStrExt;

    if symlink_acl {
        return fail_custom("Linux does not support symlinks with ACL's.");
    }

    let acl_type = if default_acl {
        ACL_TYPE_DEFAULT
    } else {
        ACL_TYPE_ACCESS
    };

    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let acl = unsafe { acl_get_file(c_path.as_ptr(), acl_type) };

    if acl.is_null() {
        let func = if default_acl {
            "acl_get_file/default"
        } else {
            "acl_get_file/access"
        };
        return fail_err("null", func, &c_path);
    }

    Ok(acl)
}

/// Set the acl for a symlink using `acl_set_fd`.
#[cfg(target_os = "macos")]
fn xacl_set_file_symlink(c_path: &CString, acl: acl_t) -> io::Result<()> {
    let fd = unsafe { open(c_path.as_ptr(), sg::O_SYMLINK) };
    if fd < 0 {
        return fail_err(fd, "open", &c_path);
    }
    defer! { unsafe{ close(fd) }; }

    let ret = unsafe { acl_set_fd(fd, acl) };
    if ret != 0 {
        return fail_err(ret, "acl_set_fd", fd);
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn xacl_set_file(
    path: &Path,
    acl: acl_t,
    symlink_acl: bool,
    default_acl: bool,
) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    if default_acl {
        return fail_custom("macOS does not support default ACL");
    }

    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let ret = if symlink_acl {
        unsafe { acl_set_link_np(c_path.as_ptr(), acl_type_t_ACL_TYPE_EXTENDED, acl) }
    } else {
        unsafe { acl_set_file(c_path.as_ptr(), acl_type_t_ACL_TYPE_EXTENDED, acl) }
    };

    if ret != 0 {
        let err = log_err(ret, "acl_set_link_np", &c_path);

        // acl_set_link_np() returns ENOTSUP for symlinks. Work-around this
        // by using acl_set_fd().
        if let Some(sg::ENOTSUP) = err.raw_os_error() {
            if symlink_acl {
                return xacl_set_file_symlink(&c_path, acl);
            }
        }

        return Err(err);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn xacl_set_file(
    path: &Path,
    acl: acl_t,
    symlink_acl: bool,
    default_acl: bool,
) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    if symlink_acl {
        return fail_custom("Linux does not support symlinks with ACL's");
    }

    let acl_type = if default_acl {
        ACL_TYPE_DEFAULT
    } else {
        ACL_TYPE_ACCESS
    };

    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let ret = unsafe { acl_set_file(c_path.as_ptr(), acl_type, acl) };
    if ret != 0 {
        let func = if default_acl {
            "acl_set_file/default"
        } else {
            "acl_set_file/access"
        };
        return fail_err(ret, func, &c_path);
    }

    Ok(())
}

/// Return number of entries in the ACL.
pub(crate) fn xacl_entry_count(acl: acl_t) -> usize {
    let mut count = 0;

    xacl_foreach(acl, |_| {
        count += 1;
        Ok(())
    })
    .unwrap();

    count
}

/// Return next entry in ACL.
fn xacl_get_entry(acl: acl_t, entry_id: i32, entry_p: *mut acl_entry_t) -> bool {
    let ret = unsafe { acl_get_entry(acl, entry_id, entry_p) };

    // MacOS: Zero means there is more.
    #[cfg(target_os = "macos")]
    return ret == 0;

    // Linux: One means there is more.
    #[cfg(target_os = "linux")]
    return ret == 1;
}

/// Iterate over entries in a native ACL.
pub(crate) fn xacl_foreach<F: FnMut(acl_entry_t) -> io::Result<()>>(
    acl: acl_t,
    mut func: F,
) -> io::Result<()> {
    let mut entry: acl_entry_t = ptr::null_mut();
    let mut entry_id = sg::ACL_FIRST_ENTRY;

    assert!(!acl.is_null());
    loop {
        if !xacl_get_entry(acl, entry_id, &mut entry) {
            break;
        }
        assert!(!entry.is_null());
        func(entry)?;
        entry_id = sg::ACL_NEXT_ENTRY;
    }

    Ok(())
}

/// Create a new empty ACL with the given capacity.
///
/// Client must call `xacl_free` when done with result.
pub(crate) fn xacl_init(capacity: usize) -> io::Result<acl_t> {
    use std::convert::TryFrom;

    let size = match i32::try_from(capacity) {
        Ok(size) if size <= sg::ACL_MAX_ENTRIES => size,
        _ => return fail_custom("Too many ACL entries"),
    };

    let acl = unsafe { acl_init(size) };
    if acl.is_null() {
        return fail_err("null", "acl_init", capacity);
    }

    Ok(acl)
}

/// Create a new entry in the specified ACL.
///
/// N.B. Memory reallocation may cause `acl` ptr to change.
pub(crate) fn xacl_create_entry(acl: &mut acl_t) -> io::Result<acl_entry_t> {
    let mut entry: acl_entry_t = ptr::null_mut();

    let ret = unsafe { acl_create_entry(&mut *acl, &mut entry) };
    if ret != 0 {
        return fail_err(ret, "acl_create_entry", ());
    }

    Ok(entry)
}

fn xacl_get_tag_type(entry: acl_entry_t) -> io::Result<acl_tag_t> {
    let mut tag: acl_tag_t = 0;

    let ret = unsafe { acl_get_tag_type(entry, &mut tag) };
    if ret != 0 {
        return fail_err(ret, "acl_get_tag_type", ());
    }

    Ok(tag)
}

/// Get the GUID qualifier and resolve it to a User/Group if possible.
///
/// Only call this function for `ACL_EXTENDED_ALLOW` or `ACL_EXTENDED_DENY`.
#[cfg(target_os = "macos")]
fn xacl_get_qualifier(entry: acl_entry_t) -> io::Result<Qualifier> {
    let uuid_ptr = unsafe { acl_get_qualifier(entry) as *mut Uuid };
    if uuid_ptr.is_null() {
        return fail_err("null", "acl_get_qualifier", ());
    }
    defer! { xacl_free(uuid_ptr) }

    let guid = unsafe { *uuid_ptr };
    Qualifier::from_guid(guid)
}

/// Get tag and qualifier from the entry.
#[cfg(target_os = "macos")]
pub(crate) fn xacl_get_tag_qualifier(entry: acl_entry_t) -> io::Result<(bool, Qualifier)> {
    let tag = xacl_get_tag_type(entry)?;

    #[allow(non_upper_case_globals)]
    let result = match tag {
        acl_tag_t_ACL_EXTENDED_ALLOW => (true, xacl_get_qualifier(entry)?),
        acl_tag_t_ACL_EXTENDED_DENY => (false, xacl_get_qualifier(entry)?),
        _ => (false, Qualifier::Unknown(format!("@tag:{}", tag))),
    };

    Ok(result)
}

#[cfg(target_os = "linux")]
fn xacl_get_qualifier(entry: acl_entry_t) -> io::Result<Qualifier> {
    let tag = xacl_get_tag_type(entry)?;

    let id = if tag == sg::ACL_USER || tag == sg::ACL_GROUP {
        let id_ptr = unsafe { acl_get_qualifier(entry) as *mut uid_t };
        if id_ptr.is_null() {
            return fail_err("null", "acl_get_qualifier", ());
        }
        defer! { xacl_free(id_ptr) };
        Some(unsafe { *id_ptr })
    } else {
        None
    };

    let result = match tag {
        sg::ACL_USER => Qualifier::User(Uid::from_raw(id.unwrap())),
        sg::ACL_GROUP => Qualifier::Group(Gid::from_raw(id.unwrap())),
        sg::ACL_USER_OBJ => Qualifier::UserObj,
        sg::ACL_GROUP_OBJ => Qualifier::GroupObj,
        sg::ACL_OTHER => Qualifier::Other,
        sg::ACL_MASK => Qualifier::Mask,
        tag => Qualifier::Unknown(format!("@tag:{}", tag)),
    };

    Ok(result)
}

#[cfg(target_os = "linux")]
pub(crate) fn xacl_get_tag_qualifier(entry: acl_entry_t) -> io::Result<(bool, Qualifier)> {
    let qualifier = xacl_get_qualifier(entry)?;
    Ok((true, qualifier))
}

// Get permissions from the entry.
pub(crate) fn xacl_get_perm(entry: acl_entry_t) -> io::Result<Perm> {
    let mut permset: acl_permset_t = std::ptr::null_mut();

    let ret = unsafe { acl_get_permset(entry, &mut permset) };
    if ret != 0 {
        return fail_err(ret, "acl_get_permset", ());
    }

    assert!(!permset.is_null());

    let mut perms = Perm::empty();
    for perm in BitIter(Perm::all()) {
        let res = unsafe { acl_get_perm(permset, perm.bits()) };
        debug_assert!(res >= 0 && res <= 1);
        if res == 1 {
            perms |= perm;
        }
    }

    Ok(perms)
}

/// Get flags from the entry.
#[cfg(target_os = "macos")]
pub(crate) fn xacl_get_flags(entry: acl_entry_t) -> io::Result<Flag> {
    let mut flagset: acl_flagset_t = std::ptr::null_mut();

    let ret = unsafe { acl_get_flagset_np(entry as *mut c_void, &mut flagset) };
    if ret != 0 {
        return fail_err(ret, "acl_get_flagset_np", ());
    }

    assert!(!flagset.is_null());

    let mut flags = Flag::empty();
    for flag in BitIter(Flag::all()) {
        let res = unsafe { acl_get_flag_np(flagset, flag.bits()) };
        debug_assert!(res >= 0 && res <= 1);
        if res == 1 {
            flags |= flag;
        }
    }

    Ok(flags)
}

#[cfg(target_os = "linux")]
pub(crate) fn xacl_get_flags(_entry: acl_entry_t) -> io::Result<Flag> {
    Ok(Flag::empty()) // noop
}

/// Set tag for ACL entry.
fn xacl_set_tag_type(entry: acl_entry_t, tag: acl_tag_t) -> io::Result<()> {
    let ret = unsafe { acl_set_tag_type(entry, tag) };
    if ret != 0 {
        return fail_err(ret, "acl_set_tag_type", ());
    }

    Ok(())
}

/// Set qualifier for entry.
#[cfg(target_os = "macos")]
fn xacl_set_qualifier(entry: acl_entry_t, qualifier: &Qualifier) -> io::Result<()> {
    // Translate qualifier User/Group to guid.
    let guid = qualifier.guid()?;

    let ret = unsafe { acl_set_qualifier(entry, guid.as_bytes().as_ptr() as *mut c_void) };
    if ret != 0 {
        return fail_err(ret, "acl_set_qualifier", ());
    }

    Ok(())
}

/// Set tag and qualifier for ACL entry.
#[cfg(target_os = "macos")]
pub(crate) fn xacl_set_tag_qualifier(
    entry: acl_entry_t,
    allow: bool,
    qualifier: &Qualifier,
) -> io::Result<()> {
    let tag = if let Qualifier::Unknown(_) = qualifier {
        debug_assert!(!allow);
        acl_tag_t_ACL_EXTENDED_DENY
    } else if allow {
        acl_tag_t_ACL_EXTENDED_ALLOW
    } else {
        acl_tag_t_ACL_EXTENDED_DENY
    };

    xacl_set_tag_type(entry, tag)?;
    xacl_set_qualifier(entry, &qualifier)?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn xacl_set_qualifier(entry: acl_entry_t, mut id: uid_t) -> io::Result<()> {
    let id_ptr = &mut id as *mut uid_t;

    let ret = unsafe { acl_set_qualifier(entry, id_ptr as *mut c_void) };
    if ret != 0 {
        return fail_err(ret, "acl_set_qualifier", ());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn xacl_set_tag_qualifier(
    entry: acl_entry_t,
    allow: bool,
    qualifier: &Qualifier,
) -> io::Result<()> {
    if !allow {
        return fail_custom("allow=false is not supported on Linux");
    }

    match qualifier {
        Qualifier::User(uid) => {
            xacl_set_tag_type(entry, sg::ACL_USER)?;
            xacl_set_qualifier(entry, uid.as_raw())?;
        }
        Qualifier::Group(gid) => {
            xacl_set_tag_type(entry, sg::ACL_GROUP)?;
            xacl_set_qualifier(entry, gid.as_raw())?;
        }
        Qualifier::UserObj => {
            xacl_set_tag_type(entry, sg::ACL_USER_OBJ)?;
        }
        Qualifier::GroupObj => {
            xacl_set_tag_type(entry, sg::ACL_GROUP_OBJ)?;
        }
        Qualifier::Other => {
            xacl_set_tag_type(entry, sg::ACL_OTHER)?;
        }
        Qualifier::Mask => {
            xacl_set_tag_type(entry, sg::ACL_MASK)?;
        }
        Qualifier::Unknown(tag) => {
            return fail_custom(&format!("unknown tag: {}", tag));
        }
    }

    Ok(())
}

/// Set permissions for the entry.
pub(crate) fn xacl_set_perm(entry: acl_entry_t, perms: Perm) -> io::Result<()> {
    let mut permset: acl_permset_t = std::ptr::null_mut();

    let ret_get = unsafe { acl_get_permset(entry, &mut permset) };
    if ret_get != 0 {
        return fail_err(ret_get, "acl_get_permset", ());
    }

    assert!(!permset.is_null());

    let ret_clear = unsafe { acl_clear_perms(permset) };
    if ret_clear != 0 {
        return fail_err(ret_clear, "acl_clear_perms", ());
    }

    for perm in BitIter(perms) {
        let ret = unsafe { acl_add_perm(permset, perm.bits()) };
        debug_assert!(ret == 0);
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn xacl_set_flags(entry: acl_entry_t, flags: Flag) -> io::Result<()> {
    let mut flagset: acl_flagset_t = std::ptr::null_mut();

    let ret_get = unsafe { acl_get_flagset_np(entry as *mut c_void, &mut flagset) };
    if ret_get != 0 {
        return fail_err(ret_get, "acl_get_flagset_np", ());
    }

    assert!(!flagset.is_null());

    let ret_clear = unsafe { acl_clear_flags_np(flagset) };
    if ret_clear != 0 {
        return fail_err(ret_clear, "acl_clear_flags_np", ());
    }

    for flag in BitIter(flags) {
        let ret = unsafe { acl_add_flag_np(flagset, flag.bits()) };
        debug_assert!(ret == 0);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn xacl_set_flags(_entry: acl_entry_t, _flags: Flag) -> io::Result<()> {
    Ok(()) // noop
}

pub(crate) fn xacl_from_text(text: &str) -> io::Result<acl_t> {
    let cstr = CString::new(text.as_bytes())?;

    let acl = unsafe { acl_from_text(cstr.as_ptr()) };
    if acl.is_null() {
        return fail_err("null", "acl_from_text", cstr);
    }

    Ok(acl)
}

pub(crate) fn xacl_to_text(acl: acl_t) -> io::Result<String> {
    let mut size: ssize_t = 0;
    let ptr = unsafe { acl_to_text(acl, &mut size) };
    if ptr.is_null() {
        return fail_err("null", "acl_to_text", ());
    }

    let result = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    xacl_free(ptr);

    Ok(result)
}

#[cfg(target_os = "macos")]
pub(crate) fn xacl_check(_acl: acl_t) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn xacl_check(acl: acl_t) -> io::Result<()> {
    use std::convert::TryInto;

    let mut last: i32 = 0;
    let ret = unsafe { acl_check(acl, &mut last) };
    if ret < 0 {
        return fail_err(ret, "acl_check", ());
    }

    if ret == 0 {
        return Ok(());
    }

    let msg = match ret.try_into().unwrap() {
        ACL_MULTI_ERROR => "Multiple ACL entries with a tag that may occur at most once",
        ACL_DUPLICATE_ERROR => "Multiple ACL entries with the same user/group ID",
        ACL_MISS_ERROR => "Required ACL entry is missing",
        ACL_ENTRY_ERROR => "Invalid ACL entry tag type",
        _ => "Unknown acl_check error message",
    };

    fail_custom(msg)
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
#[cfg(target_os = "macos")]
mod util_tests_mac {
    use super::*;
    use ctor::ctor;

    #[ctor]
    fn init() {
        env_logger::init();
    }

    #[test]
    fn test_acl_init() {
        use std::convert::TryInto;
        let max_entries: usize = ACL_MAX_ENTRIES.try_into().unwrap();

        let acl = xacl_init(max_entries).ok().unwrap();
        assert!(!acl.is_null());
        xacl_free(acl);

        // Custom error if we try to allocate MAX_ENTRIES + 1.
        let err = xacl_init(max_entries + 1).err().unwrap();
        assert_eq!(err.to_string(), "Too many ACL entries");
    }

    #[test]
    fn test_acl_too_big() {
        let mut acl = xacl_init(3).ok().unwrap();
        assert!(!acl.is_null());

        for _ in 0..ACL_MAX_ENTRIES {
            xacl_create_entry(&mut acl).unwrap();
        }

        // Memory error if we try to allocate MAX_ENTRIES + 1.
        let err = xacl_create_entry(&mut acl).err().unwrap();
        assert_eq!(err.raw_os_error(), Some(sg::ENOMEM));

        xacl_free(acl);
    }

    #[test]
    fn test_acl_api_misuse() {
        let mut acl = xacl_init(1).unwrap();
        let entry = xacl_create_entry(&mut acl).unwrap();

        // Setting tag other than 1 or 2 results in EINVAL error.
        let err = xacl_set_tag_type(entry, 0).err().unwrap();
        assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

        // Setting qualifier without first setting tag to a valid value results in EINVAL.
        let err = xacl_set_qualifier(entry, &Qualifier::Guid(Uuid::nil()))
            .err()
            .unwrap();
        assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

        assert_eq!(xacl_to_text(acl), "!#acl 1\n");

        let entry2 = xacl_create_entry(&mut acl).unwrap();
        xacl_set_tag_type(entry2, 1).unwrap();

        assert_eq!(
            xacl_to_text(acl),
            "!#acl 1\nuser:00000000-0000-0000-0000-000000000000:::allow\n"
        );

        // There are still two entries... one is corrupt.
        assert_eq!(xacl_entry_count(acl), 2);
        xacl_free(acl);
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod util_tests_linux {
    use super::*;

    #[test]
    fn test_acl_api_misuse() {
        // Create empty list and add an entry.
        let mut acl = xacl_init(1).unwrap();
        let entry = xacl_create_entry(&mut acl).unwrap();

        // Setting tag other than 1 or 2 results in EINVAL error.
        let err = xacl_set_tag_type(entry, 0).err().unwrap();
        assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

        // Setting qualifier without first setting tag to a valid value results in EINVAL.
        let err = xacl_set_qualifier(entry, 500).err().unwrap();
        assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

        // Try to set entry using unknown qualifier -- this should fail.
        let err = xacl_set_tag_qualifier(entry, true, &Qualifier::Unknown("x".to_string()))
            .err()
            .unwrap();
        assert!(err.to_string().contains("unknown tag: x"));

        // Even though ACL contains 1 invalid entry, the platform text still
        // results in empty string.
        assert_eq!(xacl_to_text(acl).unwrap(), "");

        // Add another entry and set it to a valid value.
        let entry2 = xacl_create_entry(&mut acl).unwrap();
        xacl_set_tag_type(entry2, sg::ACL_USER_OBJ).unwrap();

        // ACL only prints the one valid entry; no sign of other entry.
        assert_eq!(xacl_to_text(acl).unwrap(), "\nuser::---\n");

        // There are still two entries... one is corrupt.
        assert_eq!(xacl_entry_count(acl), 2);
        let err = xacl_check(acl).err().unwrap();
        assert!(err.to_string().contains("Invalid ACL entry tag type"));

        xacl_free(acl);
    }
}
