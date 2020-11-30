//! Utility functions and constants for the underlying system API.
//!
//! This module wraps all unsafe code from the native API.

use crate::bititer::BitIter;
use crate::failx::*;
use crate::flag::Flag;
use crate::perm::Perm;
use crate::sys::*;

use nix::unistd::{self, Gid, Uid};
use scopeguard::defer;
use std::ffi::{c_void, CStr, CString};
use std::io;
use std::path::Path;
use std::ptr;
#[cfg(target_os = "macos")]
use uuid::Uuid;

// Re-export acl_entry_t and acl_t from crate::sys.
pub use crate::sys::{acl_entry_t, acl_t};

#[cfg(target_os = "linux")]
pub const OWNER_NAME: &str = "";
#[cfg(target_os = "linux")]
pub const OTHER_NAME: &str = "";
#[cfg(target_os = "linux")]
pub const MASK_NAME: &str = "";

/// A Qualifier specifies the principal that is allowed/denied access to a
/// resource.
#[derive(Debug, PartialEq)]
pub enum Qualifier {
    User(Uid),
    Group(Gid),

    #[cfg(target_os = "macos")]
    Guid(Uuid),

    #[cfg(target_os = "linux")]
    UserObj,
    #[cfg(target_os = "linux")]
    GroupObj,
    #[cfg(target_os = "linux")]
    Other,
    #[cfg(target_os = "linux")]
    Mask,

    Unknown(String),
}

impl Qualifier {
    /// Create qualifier object from a GUID.
    #[cfg(target_os = "macos")]
    fn from_guid(guid: Uuid) -> io::Result<Qualifier> {
        let (id_c, idtype) = match xguid_to_id(guid) {
            Ok(info) => info,
            Err(err) => {
                if let Some(sg::ENOENT) = err.raw_os_error() {
                    return Ok(Qualifier::Guid(guid));
                } else {
                    return Err(err);
                }
            }
        };

        let qualifier = match idtype {
            sg::ID_TYPE_UID => Qualifier::User(Uid::from_raw(id_c)),
            sg::ID_TYPE_GID => Qualifier::Group(Gid::from_raw(id_c)),
            _ => Qualifier::Unknown(guid.to_string()),
        };

        Ok(qualifier)
    }

    /// Create qualifier object from a user name.
    #[cfg(target_os = "macos")]
    pub fn user_named(name: &str) -> io::Result<Qualifier> {
        match str_to_uid(name) {
            Ok(uid) => Ok(Qualifier::User(uid)),
            Err(err) => {
                // Try to parse name as a GUID.
                if let Ok(uuid) = Uuid::parse_str(name) {
                    Qualifier::from_guid(uuid)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Create qualifier object from a user name.
    #[cfg(target_os = "linux")]
    pub fn user_named(name: &str) -> io::Result<Qualifier> {
        match name {
            OWNER_NAME => Ok(Qualifier::UserObj),
            s => match str_to_uid(s) {
                Ok(uid) => Ok(Qualifier::User(uid)),
                Err(err) => Err(err),
            },
        }
    }

    /// Create qualifier object from a group name.
    #[cfg(target_os = "macos")]
    pub fn group_named(name: &str) -> io::Result<Qualifier> {
        match str_to_gid(name) {
            Ok(gid) => Ok(Qualifier::Group(gid)),
            Err(err) => {
                if let Ok(uuid) = Uuid::parse_str(name) {
                    Qualifier::from_guid(uuid)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Create qualifier object from a group name.
    #[cfg(target_os = "linux")]
    pub fn group_named(name: &str) -> io::Result<Qualifier> {
        match name {
            OWNER_NAME => Ok(Qualifier::GroupObj),
            s => match str_to_gid(s) {
                Ok(gid) => Ok(Qualifier::Group(gid)),
                Err(err) => Err(err),
            },
        }
    }

    /// Create qualifier from mask.
    #[cfg(target_os = "linux")]
    pub fn mask_named(name: &str) -> io::Result<Qualifier> {
        match name {
            MASK_NAME => Ok(Qualifier::Mask),
            s => fail_custom(&format!("unknown mask name: {:?}", s)),
        }
    }

    /// Create qualifier from other.
    #[cfg(target_os = "linux")]
    pub fn other_named(name: &str) -> io::Result<Qualifier> {
        match name {
            OTHER_NAME => Ok(Qualifier::Other),
            s => fail_custom(&format!("unknown other name: {:?}", s)),
        }
    }

    /// Return the GUID for the user/group.
    #[cfg(target_os = "macos")]
    fn guid(&self) -> io::Result<Uuid> {
        match self {
            Qualifier::User(uid) => xuid_to_guid(*uid),
            Qualifier::Group(gid) => xgid_to_guid(*gid),
            Qualifier::Guid(guid) => Ok(*guid),
            Qualifier::Unknown(tag) => fail_custom(&format!("unknown tag: {:?}", tag)),
        }
    }

    /// Return the name of the user/group.
    pub fn name(&self) -> String {
        match self {
            Qualifier::User(uid) => uid_to_str(*uid),
            Qualifier::Group(gid) => gid_to_str(*gid),
            #[cfg(target_os = "macos")]
            Qualifier::Guid(guid) => guid.to_string(),
            #[cfg(target_os = "linux")]
            Qualifier::UserObj | Qualifier::GroupObj => OWNER_NAME.to_string(),
            #[cfg(target_os = "linux")]
            Qualifier::Other => OTHER_NAME.to_string(),
            #[cfg(target_os = "linux")]
            Qualifier::Mask => MASK_NAME.to_string(),

            Qualifier::Unknown(s) => s.clone(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Convert user name to uid.
fn str_to_uid(name: &str) -> io::Result<Uid> {
    // Lookup user by user name.
    if let Ok(Some(user)) = unistd::User::from_name(name) {
        return Ok(user.uid);
    }

    // Try to parse name as a decimal user ID.
    if let Ok(num) = name.parse::<u32>() {
        return Ok(Uid::from_raw(num));
    }

    fail_custom(&format!("unknown user name: {:?}", name))
}

/// Convert group name to gid.
fn str_to_gid(name: &str) -> io::Result<Gid> {
    // Lookup group by group name.
    if let Ok(Some(group)) = unistd::Group::from_name(name) {
        return Ok(group.gid);
    }

    // Try to parse name as a decimal group ID.
    if let Ok(num) = name.parse::<u32>() {
        return Ok(Gid::from_raw(num));
    }

    fail_custom(&format!("unknown group name: {:?}", name))
}

/// Convert uid to user name.
fn uid_to_str(uid: Uid) -> String {
    if let Ok(Some(user)) = unistd::User::from_uid(uid) {
        user.name
    } else {
        uid.to_string()
    }
}

/// Convert gid to group name.
fn gid_to_str(gid: Gid) -> String {
    if let Ok(Some(group)) = unistd::Group::from_gid(gid) {
        group.name
    } else {
        gid.to_string()
    }
}

/// Convert uid to GUID.
#[cfg(target_os = "macos")]
fn xuid_to_guid(uid: Uid) -> io::Result<Uuid> {
    let guid = Uuid::nil();

    // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
    let ret = unsafe { mbr_uid_to_uuid(uid.as_raw(), guid.as_bytes().as_ptr() as *mut u8) };
    if ret != 0 {
        return fail_from_err(ret, "mbr_uid_to_uuid", uid);
    }

    Ok(guid)
}

/// Convert gid to GUID.
#[cfg(target_os = "macos")]
fn xgid_to_guid(gid: Gid) -> io::Result<Uuid> {
    let guid = Uuid::nil();

    // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
    let ret = unsafe { mbr_gid_to_uuid(gid.as_raw(), guid.as_bytes().as_ptr() as *mut u8) };
    if ret != 0 {
        return fail_from_err(ret, "mbr_gid_to_uuid", gid);
    }

    Ok(guid)
}

/// Convert GUID to uid/gid.
#[cfg(target_os = "macos")]
fn xguid_to_id(guid: Uuid) -> io::Result<(uid_t, i32)> {
    let mut id_c: uid_t = 0;
    let mut idtype: i32 = 0;
    let guid_ptr = guid.as_bytes().as_ptr() as *mut u8;

    // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
    let ret = unsafe { mbr_uuid_to_id(guid_ptr, &mut id_c, &mut idtype) };
    if ret != 0 {
        return fail_from_err(ret, "mbr_uuid_to_id", guid);
    }

    Ok((id_c, idtype))
}

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

pub(crate) fn xacl_to_text(acl: acl_t) -> String {
    let mut size: ssize_t = 0;
    let ptr = unsafe { acl_to_text(acl, &mut size) };
    if ptr.is_null() {
        return format!("<error: {}>", io::Error::last_os_error());
    }

    let result = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    xacl_free(ptr);

    result
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
mod qualifier_tests {
    use super::*;

    #[test]
    fn test_str_to_uid() {
        let msg = str_to_uid("").unwrap_err().to_string();
        assert_eq!(msg, "unknown user name: \"\"");

        let msg = str_to_uid("non_existant").unwrap_err().to_string();
        assert_eq!(msg, "unknown user name: \"non_existant\"");

        assert_eq!(str_to_uid("500").ok(), Some(Uid::from_raw(500)));

        #[cfg(target_os = "macos")]
        assert_eq!(str_to_uid("_spotlight").ok(), Some(Uid::from_raw(89)));

        #[cfg(target_os = "linux")]
        assert_eq!(str_to_uid("bin").ok(), Some(Uid::from_raw(2)));
    }

    #[test]
    fn test_str_to_gid() {
        let msg = str_to_gid("").unwrap_err().to_string();
        assert_eq!(msg, "unknown group name: \"\"");

        let msg = str_to_gid("non_existant").unwrap_err().to_string();
        assert_eq!(msg, "unknown group name: \"non_existant\"");

        assert_eq!(str_to_gid("500").ok(), Some(Gid::from_raw(500)));

        #[cfg(target_os = "macos")]
        assert_eq!(str_to_gid("_spotlight").ok(), Some(Gid::from_raw(89)));

        #[cfg(target_os = "linux")]
        assert_eq!(str_to_gid("bin").ok(), Some(Gid::from_raw(2)));
    }

    #[test]
    fn test_uid_to_str() {
        assert_eq!(uid_to_str(Uid::from_raw(1500)), "1500");

        #[cfg(target_os = "macos")]
        assert_eq!(uid_to_str(Uid::from_raw(89)), "_spotlight");

        #[cfg(target_os = "linux")]
        assert_eq!(uid_to_str(Uid::from_raw(2)), "bin");
    }

    #[test]
    fn test_gid_to_str() {
        assert_eq!(gid_to_str(Gid::from_raw(1500)), "1500");

        #[cfg(target_os = "macos")]
        assert_eq!(gid_to_str(Gid::from_raw(89)), "_spotlight");

        #[cfg(target_os = "linux")]
        assert_eq!(gid_to_str(Gid::from_raw(2)), "bin");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_uid_to_guid() {
        assert_eq!(
            xuid_to_guid(Uid::from_raw(89)).ok(),
            Some(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap())
        );

        assert_eq!(
            xuid_to_guid(Uid::from_raw(1500)).ok(),
            Some(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa000005dc").unwrap())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_gid_to_guid() {
        assert_eq!(
            xgid_to_guid(Gid::from_raw(89)).ok(),
            Some(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap())
        );

        assert_eq!(
            xgid_to_guid(Gid::from_raw(1500)).ok(),
            Some(Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffff000005dc").unwrap())
        );

        assert_eq!(
            xgid_to_guid(Gid::from_raw(20)).ok(),
            Some(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000014").unwrap())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_guid_to_id() {
        assert_eq!(
            xguid_to_id(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap()).ok(),
            Some((89, sg::ID_TYPE_UID))
        );

        assert_eq!(
            xguid_to_id(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa000005dc").unwrap()).ok(),
            Some((1500, sg::ID_TYPE_UID))
        );

        assert_eq!(
            xguid_to_id(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap()).ok(),
            Some((89, sg::ID_TYPE_GID))
        );

        assert_eq!(
            xguid_to_id(Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffff000005dc").unwrap()).ok(),
            Some((1500, sg::ID_TYPE_GID))
        );

        assert_eq!(
            xguid_to_id(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000014").unwrap()).ok(),
            Some((20, sg::ID_TYPE_GID))
        );

        let err = xguid_to_id(Uuid::nil()).err().unwrap();
        assert_eq!(err.raw_os_error().unwrap(), sg::ENOENT);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_from_guid() {
        let user =
            Qualifier::from_guid(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap())
                .ok();
        assert_eq!(user, Some(Qualifier::User(Uid::from_raw(89))));

        let group =
            Qualifier::from_guid(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap())
                .ok();
        assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(89))));

        let user = Qualifier::from_guid(Uuid::nil()).ok();
        assert_eq!(user, Some(Qualifier::Guid(Uuid::nil())));
    }

    #[test]
    fn test_user_named() {
        let user = Qualifier::user_named("89").ok();
        assert_eq!(user, Some(Qualifier::User(Uid::from_raw(89))));

        #[cfg(target_os = "macos")]
        {
            let user = Qualifier::user_named("_spotlight").ok();
            assert_eq!(user, Some(Qualifier::User(Uid::from_raw(89))));

            let user = Qualifier::user_named("ffffeeee-dddd-cccc-bbbb-aaaa00000059").ok();
            assert_eq!(user, Some(Qualifier::User(Uid::from_raw(89))));
        }

        #[cfg(target_os = "linux")]
        {
            let user = Qualifier::user_named("bin").ok();
            assert_eq!(user, Some(Qualifier::User(Uid::from_raw(2))));
        }
    }

    #[test]
    fn test_group_named() {
        let group = Qualifier::group_named("89").ok();
        assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(89))));

        #[cfg(target_os = "macos")]
        {
            let group = Qualifier::group_named("_spotlight").ok();
            assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(89))));

            let group = Qualifier::group_named("abcdefab-cdef-abcd-efab-cdef00000059").ok();
            assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(89))));
        }

        #[cfg(target_os = "linux")]
        {
            let group = Qualifier::group_named("bin").ok();
            assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(2))));
        }
    }
}

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

        assert_eq!(xacl_to_text(acl), "");

        let entry2 = xacl_create_entry(&mut acl).unwrap();
        xacl_set_tag_type(entry2, sg::ACL_USER_OBJ).unwrap();

        assert_eq!(xacl_to_text(acl), "\nuser::---\n");

        // There are still two entries... one is corrupt.
        assert_eq!(xacl_entry_count(acl), 2);
        xacl_free(acl);
    }
}
