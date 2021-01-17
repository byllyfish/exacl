use crate::bititer::BitIter;
use crate::failx::*;
use crate::flag::Flag;
use crate::qualifier::Qualifier;
use crate::sys::*;
use crate::util::util_common::*;

use scopeguard::defer;
use std::ffi::{c_void, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use uuid::Uuid;

/// Return true if path exists, even if it's a symlink to nowhere.
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
pub fn xacl_get_file(path: &Path, symlink_acl: bool, default_acl: bool) -> io::Result<acl_t> {
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
            if path_exists(path, symlink_acl) {
                return xacl_init(1);
            }
        }

        return Err(err);
    }

    Ok(acl)
}

/// Set the acl for a symlink using `acl_set_fd`.
fn xacl_set_file_symlink_alt(c_path: &CString, acl: acl_t) -> io::Result<()> {
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

pub fn xacl_set_file(
    path: &Path,
    acl: acl_t,
    symlink_acl: bool,
    default_acl: bool,
) -> io::Result<()> {
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
                return xacl_set_file_symlink_alt(&c_path, acl);
            }
        }

        return Err(err);
    }

    Ok(())
}

/// Get the GUID qualifier and resolve it to a User/Group if possible.
///
/// Only call this function for `ACL_EXTENDED_ALLOW` or `ACL_EXTENDED_DENY`.
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
pub fn xacl_get_tag_qualifier(entry: acl_entry_t) -> io::Result<(bool, Qualifier)> {
    let tag = xacl_get_tag_type(entry)?;

    #[allow(non_upper_case_globals)]
    let result = match tag {
        sg::ACL_EXTENDED_ALLOW => (true, xacl_get_qualifier(entry)?),
        sg::ACL_EXTENDED_DENY => (false, xacl_get_qualifier(entry)?),
        _ => (false, Qualifier::Unknown(format!("@tag {}", tag))),
    };

    Ok(result)
}

/// Get flags from the entry.
fn xacl_get_flags_np(obj: *mut c_void) -> io::Result<Flag> {
    assert!(!obj.is_null());

    let mut flagset: acl_flagset_t = std::ptr::null_mut();
    let ret = unsafe { acl_get_flagset_np(obj, &mut flagset) };
    if ret != 0 {
        return fail_err(ret, "acl_get_flagset_np", ());
    }

    assert!(!flagset.is_null());

    let mut flags = Flag::empty();
    for flag in BitIter(Flag::all()) {
        let res = unsafe { acl_get_flag_np(flagset, flag.bits()) };
        debug_assert!((0..=1).contains(&res));
        if res == 1 {
            flags |= flag;
        }
    }

    Ok(flags)
}

pub fn xacl_get_flags(entry: acl_entry_t) -> io::Result<Flag> {
    xacl_get_flags_np(entry as *mut c_void)
}

pub fn xacl_get_acl_flags(acl: acl_t) -> io::Result<Flag> {
    xacl_get_flags_np(acl as *mut c_void)
}

/// Set qualifier for entry.
pub fn xacl_set_qualifier(entry: acl_entry_t, qualifier: &Qualifier) -> io::Result<()> {
    // Translate qualifier User/Group to guid.
    let guid = qualifier.guid()?;

    let ret = unsafe { acl_set_qualifier(entry, guid.as_bytes().as_ptr() as *mut c_void) };
    if ret != 0 {
        return fail_err(ret, "acl_set_qualifier", ());
    }

    Ok(())
}

/// Set tag and qualifier for ACL entry.
pub fn xacl_set_tag_qualifier(
    entry: acl_entry_t,
    allow: bool,
    qualifier: &Qualifier,
) -> io::Result<()> {
    let tag = if let Qualifier::Unknown(_) = qualifier {
        debug_assert!(!allow);
        sg::ACL_EXTENDED_DENY
    } else if allow {
        sg::ACL_EXTENDED_ALLOW
    } else {
        sg::ACL_EXTENDED_DENY
    };

    xacl_set_tag_type(entry, tag)?;
    xacl_set_qualifier(entry, qualifier)?;

    Ok(())
}

fn xacl_set_flags_np(obj: *mut c_void, flags: Flag) -> io::Result<()> {
    assert!(!obj.is_null());

    let mut flagset: acl_flagset_t = std::ptr::null_mut();
    let ret_get = unsafe { acl_get_flagset_np(obj, &mut flagset) };
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

pub fn xacl_set_flags(entry: acl_entry_t, flags: Flag) -> io::Result<()> {
    xacl_set_flags_np(entry as *mut c_void, flags)
}

pub fn xacl_set_acl_flags(acl: acl_t, flags: Flag) -> io::Result<()> {
    xacl_set_flags_np(acl as *mut c_void, flags)
}

pub const fn xacl_is_posix(_acl: acl_t) -> bool {
    false
}