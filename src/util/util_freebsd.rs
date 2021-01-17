use crate::failx::*;
use crate::flag::Flag;
use crate::qualifier::Qualifier;
use crate::sys::*;
use crate::util::util_common::*;

use nix::unistd::{Gid, Uid};
use scopeguard::defer;
use std::ffi::{c_void, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const fn get_acl_type(default_acl: bool) -> acl_type_t {
    if default_acl {
        sg::ACL_TYPE_DEFAULT
    } else {
        sg::ACL_TYPE_ACCESS
    }
}

/// Get ACL from file path, don't follow symbolic links.
fn xacl_get_link(path: &Path, default_acl: bool) -> io::Result<acl_t> {
    let acl_type = get_acl_type(default_acl);
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let acl = unsafe { acl_get_link_np(c_path.as_ptr(), acl_type) };

    if acl.is_null() {
        let func = if default_acl {
            "acl_get_link_np/default"
        } else {
            "acl_get_link_np/access"
        };
        return fail_err("null", func, &c_path);
    }

    Ok(acl)
}

/// Get ACL from file path.
///
/// This code first tries to obtain the Posix.1e ACL. If that's not appropriate
/// for the file system object, we try to access the NFS4 ACL.
pub fn xacl_get_file(path: &Path, symlink_acl: bool, default_acl: bool) -> io::Result<acl_t> {
    // Symlinks will use `acl_get_link_np` instead of `acl_get_file`.
    if symlink_acl {
        return xacl_get_link(path, default_acl);
    }

    let mut acl_type = get_acl_type(default_acl);
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let acl = unsafe { acl_get_file(c_path.as_ptr(), acl_type) };

    if !acl.is_null() {
        return Ok(acl);
    }

    // `acl_get_file` returns EINVAL when the ACL type is not appropriate for
    // the file system object. Retry with NFSv4 type.
    // FIXME: `default_acl` setting is currently ignored!
    if let Some(sg::EINVAL) = io::Error::last_os_error().raw_os_error() {
        acl_type = sg::ACL_TYPE_NFS4;
        let nfs_acl = unsafe { acl_get_file(c_path.as_ptr(), acl_type) };
        if !nfs_acl.is_null() {
            return Ok(nfs_acl);
        }
    }

    // Report acl_type and path to file that failed.
    let func = match acl_type {
        sg::ACL_TYPE_ACCESS => "acl_get_file/access",
        sg::ACL_TYPE_DEFAULT => "acl_get_file/default",
        sg::ACL_TYPE_NFS4 => "acl_get_file/nfs4",
        _ => "acl_get_file/?",
    };

    return fail_err("null", func, &c_path);
}

fn xacl_set_file_symlink(path: &Path, acl: acl_t, default_acl: bool) -> io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;

    if default_acl && xacl_is_empty(acl) {
        // Special case to delete the ACL. The FreeBSD version of
        // acl_set_link_np does not handle this case.
        let ret = unsafe { acl_delete_def_link_np(c_path.as_ptr()) };
        if ret != 0 {
            return fail_err(ret, "acl_delete_def_link_np", &c_path);
        }
        return Ok(());
    }

    let acl_type = get_acl_type(default_acl);
    let ret = unsafe { acl_set_link_np(c_path.as_ptr(), acl_type, acl) };
    if ret != 0 {
        let func = if default_acl {
            "acl_set_link_np/default"
        } else {
            "acl_set_link_np/access"
        };
        return fail_err(ret, func, &c_path);
    }

    Ok(())
}

pub fn xacl_set_file(
    path: &Path,
    acl: acl_t,
    symlink_acl: bool,
    default_acl: bool,
) -> io::Result<()> {
    if symlink_acl {
        return xacl_set_file_symlink(path, acl, default_acl);
    }

    let c_path = CString::new(path.as_os_str().as_bytes())?;

    if default_acl && xacl_is_empty(acl) {
        // Special case to delete the ACL. The FreeBSD version of
        // acl_set_file does not handle this case.
        let ret = unsafe { acl_delete_def_file(c_path.as_ptr()) };
        if ret != 0 {
            return fail_err(ret, "acl_delete_def_file", &c_path);
        }
        return Ok(());
    }

    let acl_type = get_acl_type(default_acl);
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
        tag => Qualifier::Unknown(format!("@tag {}", tag)),
    };

    Ok(result)
}

pub fn xacl_get_tag_qualifier(entry: acl_entry_t) -> io::Result<(bool, Qualifier)> {
    let qualifier = xacl_get_qualifier(entry)?;
    Ok((true, qualifier))
}

#[allow(clippy::clippy::missing_const_for_fn)]
pub fn xacl_get_flags(_entry: acl_entry_t) -> io::Result<Flag> {
    Ok(Flag::empty()) // noop
}

pub fn xacl_set_qualifier(entry: acl_entry_t, mut id: uid_t) -> io::Result<()> {
    let id_ptr = &mut id as *mut uid_t;

    let ret = unsafe { acl_set_qualifier(entry, id_ptr as *mut c_void) };
    if ret != 0 {
        return fail_err(ret, "acl_set_qualifier", ());
    }

    Ok(())
}

pub fn xacl_set_tag_qualifier(
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

#[allow(clippy::clippy::missing_const_for_fn)]
pub fn xacl_set_flags(_entry: acl_entry_t, _flags: Flag) -> io::Result<()> {
    Ok(()) // noop
}

pub fn xacl_is_posix(acl: acl_t) -> bool {
    let mut brand: std::os::raw::c_int = 0;
    let ret = unsafe { acl_get_brand_np(acl, &mut brand) }; 
    assert_eq!(ret, 0);
    brand == sg::ACL_BRAND_POSIX
}
