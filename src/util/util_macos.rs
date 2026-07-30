use crate::ExtendedAclPresence;
use crate::bititer::BitIter;
use crate::failx::*;
use crate::flag::Flag;
use crate::perm::Perm;
use crate::qualifier::Qualifier;
use crate::sys::*;
use crate::util::util_common;

use scopeguard::defer;
use std::ffi::{CString, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use uuid::Uuid;

pub use util_common::{xacl_create_entry, xacl_foreach, xacl_free, xacl_init, xacl_is_empty};

use util_common::*;

/// Return true if path exists, even if it's a symlink to nowhere.
fn path_exists(path: &Path, symlink_only: bool) -> bool {
    if symlink_only {
        path.symlink_metadata().is_ok()
    } else {
        path.exists()
    }
}

pub(crate) fn xacl_extended_acl_presence(fd: BorrowedFd<'_>) -> io::Result<ExtendedAclPresence> {
    xacl_extended_acl_presence_with(
        fd.as_raw_fd(),
        |raw_fd, acl_type| {
            // SAFETY: `BorrowedFd` keeps `raw_fd` open for this call, Darwin's
            // getter does not retain it, and `acl_type` is the platform's valid
            // extended-ACL constant.
            unsafe { acl_get_fd_np(raw_fd, acl_type) }
        },
        |acl| {
            // SAFETY: `acl` is the non-null allocation returned by the getter.
            // It has not been freed or otherwise used, this closure is invoked
            // exactly once, and the pointer is never used after this call.
            unsafe { crate::sys::acl_free(acl.cast::<c_void>()) }
        },
        io::Error::last_os_error,
    )
}

fn xacl_extended_acl_presence_with<GetAcl, FreeAcl, LastOsError>(
    fd: RawFd,
    get_acl: GetAcl,
    free_acl: FreeAcl,
    mut last_os_error: LastOsError,
) -> io::Result<ExtendedAclPresence>
where
    GetAcl: FnOnce(RawFd, acl_type_t) -> acl_t,
    FreeAcl: FnOnce(acl_t) -> c_int,
    LastOsError: FnMut() -> io::Error,
{
    let acl = get_acl(fd, sg::ACL_TYPE_EXTENDED);
    if acl.is_null() {
        let error = last_os_error();
        log::debug!("acl_get_fd_np({fd}, ACL_TYPE_EXTENDED) returned null: {error}");
        return if error.raw_os_error() == Some(sg::ENOENT) {
            Ok(ExtendedAclPresence::Absent)
        } else {
            Err(error)
        };
    }

    let free_result = free_acl(acl);
    if free_result != 0 {
        let error = last_os_error();
        log::debug!("acl_free returned {free_result}: {error}");
        return Err(error);
    }

    Ok(ExtendedAclPresence::Present)
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
        if err.raw_os_error() == Some(sg::ENOENT) && path_exists(path, symlink_acl) {
            return xacl_init(1);
        }

        return Err(err);
    }

    Ok(acl)
}

/// Set the acl for a symlink using `acl_set_fd`.
fn xacl_set_file_symlink_alt(c_path: &CString, acl: acl_t) -> io::Result<()> {
    let fd = unsafe { open(c_path.as_ptr(), sg::O_SYMLINK) };
    if fd < 0 {
        return fail_err(fd, "open", c_path);
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
        if err.raw_os_error() == Some(sg::ENOTSUP) && symlink_acl {
            return xacl_set_file_symlink_alt(&c_path, acl);
        }

        return Err(err);
    }

    Ok(())
}

/// Get the GUID qualifier and resolve it to a User/Group if possible.
///
/// Only call this function for `ACL_EXTENDED_ALLOW` or `ACL_EXTENDED_DENY`.
fn xacl_get_qualifier(entry: acl_entry_t) -> io::Result<Qualifier> {
    let uuid_ptr = unsafe { acl_get_qualifier(entry).cast::<Uuid>() };
    if uuid_ptr.is_null() {
        return fail_err("null", "acl_get_qualifier", ());
    }
    defer! { xacl_free(uuid_ptr) }

    let guid = unsafe { *uuid_ptr };
    Qualifier::from_guid(guid)
}

/// Get tag and qualifier from the entry.
fn xacl_get_tag_qualifier(_acl: acl_t, entry: acl_entry_t) -> io::Result<(bool, Qualifier)> {
    let tag = xacl_get_tag_type(entry)?;

    let result = match tag {
        sg::ACL_EXTENDED_ALLOW => (true, xacl_get_qualifier(entry)?),
        sg::ACL_EXTENDED_DENY => (false, xacl_get_qualifier(entry)?),
        _ => (false, Qualifier::Unknown(format!("@tag {tag}"))),
    };

    Ok(result)
}

/// Get flags from the entry.
fn xacl_get_flags_np(obj: *mut c_void) -> io::Result<Flag> {
    assert!(!obj.is_null());

    let mut flagset: acl_flagset_t = std::ptr::null_mut();
    let ret = unsafe { acl_get_flagset_np(obj, &raw mut flagset) };
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

fn xacl_get_flags(_acl: acl_t, entry: acl_entry_t) -> io::Result<Flag> {
    xacl_get_flags_np(entry.cast::<c_void>())
}

pub fn xacl_get_entry(acl: acl_t, entry: acl_entry_t) -> io::Result<(bool, Qualifier, Perm, Flag)> {
    let (allow, qualifier) = xacl_get_tag_qualifier(acl, entry)?;
    let perms = xacl_get_perm(entry)?;
    let flags = xacl_get_flags(acl, entry)?;

    Ok((allow, qualifier, perms, flags))
}

/// Set qualifier for entry.
///
/// Used in test.
pub fn xacl_set_qualifier(entry: acl_entry_t, qualifier: &Qualifier) -> io::Result<()> {
    // Translate qualifier User/Group to guid.
    let mut bytes = qualifier.guid()?.into_bytes();

    let ret = unsafe { acl_set_qualifier(entry, bytes.as_mut_ptr().cast::<c_void>()) };
    if ret != 0 {
        return fail_err(ret, "acl_set_qualifier", ());
    }

    Ok(())
}

/// Set tag and qualifier for ACL entry.
fn xacl_set_tag_qualifier(
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
    let ret_get = unsafe { acl_get_flagset_np(obj, &raw mut flagset) };
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

fn xacl_set_flags(entry: acl_entry_t, flags: Flag) -> io::Result<()> {
    xacl_set_flags_np(entry.cast::<c_void>(), flags)
}

pub fn xacl_add_entry(
    acl: &mut acl_t,
    allow: bool,
    qualifier: &Qualifier,
    perms: Perm,
    flags: Flag,
) -> io::Result<acl_entry_t> {
    let entry = xacl_create_entry(acl)?;
    xacl_set_tag_qualifier(entry, allow, qualifier)?;
    xacl_set_perm(entry, perms)?;
    xacl_set_flags(entry, flags)?;

    Ok(entry)
}

pub const fn xacl_is_posix(_acl: acl_t) -> bool {
    false
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod util_macos_test {
    use super::*;
    use std::cell::Cell;

    fn fake_acl() -> acl_t {
        std::ptr::NonNull::<_acl>::dangling().as_ptr()
    }

    #[test]
    fn fd_acl_presence_maps_null_enoent_to_absent_without_freeing() {
        let free_calls = Cell::new(0);
        let errno_calls = Cell::new(0);

        let presence = xacl_extended_acl_presence_with(
            41,
            |fd, acl_type| {
                assert_eq!(fd, 41);
                assert_eq!(acl_type, sg::ACL_TYPE_EXTENDED);
                std::ptr::null_mut()
            },
            |_| {
                free_calls.set(free_calls.get() + 1);
                0
            },
            || {
                errno_calls.set(errno_calls.get() + 1);
                io::Error::from_raw_os_error(sg::ENOENT)
            },
        )
        .unwrap();

        assert_eq!(presence, ExtendedAclPresence::Absent);
        assert_eq!(free_calls.get(), 0);
        assert_eq!(errno_calls.get(), 1);
    }

    #[test]
    fn fd_acl_presence_preserves_null_error_without_freeing() {
        let free_calls = Cell::new(0);
        let errno_calls = Cell::new(0);

        let error = xacl_extended_acl_presence_with(
            42,
            |fd, acl_type| {
                assert_eq!(fd, 42);
                assert_eq!(acl_type, sg::ACL_TYPE_EXTENDED);
                std::ptr::null_mut()
            },
            |_| {
                free_calls.set(free_calls.get() + 1);
                0
            },
            || {
                errno_calls.set(errno_calls.get() + 1);
                io::Error::from_raw_os_error(sg::ENOTSUP)
            },
        )
        .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(sg::ENOTSUP));
        assert_eq!(free_calls.get(), 0);
        assert_eq!(errno_calls.get(), 1);
    }

    #[test]
    fn fd_acl_presence_rejects_every_other_null_errno() {
        const DARWIN_EBADF: i32 = 9;
        const DARWIN_EOPNOTSUPP: i32 = 102;

        for raw_errno in [
            DARWIN_EBADF,
            sg::EINVAL,
            sg::ENOMEM,
            DARWIN_EOPNOTSUPP,
            sg::ENOTSUP,
            0,
        ] {
            let free_calls = Cell::new(0);
            let errno_calls = Cell::new(0);
            let error = xacl_extended_acl_presence_with(
                45,
                |_, _| std::ptr::null_mut(),
                |_| {
                    free_calls.set(free_calls.get() + 1);
                    0
                },
                || {
                    errno_calls.set(errno_calls.get() + 1);
                    io::Error::from_raw_os_error(raw_errno)
                },
            )
            .unwrap_err();

            assert_eq!(error.raw_os_error(), Some(raw_errno));
            assert_eq!(free_calls.get(), 0);
            assert_eq!(errno_calls.get(), 1);
        }
    }

    #[test]
    fn fd_acl_presence_reports_present_and_frees_exactly_once() {
        let expected_acl = fake_acl();
        let free_calls = Cell::new(0);
        let errno_calls = Cell::new(0);

        let presence = xacl_extended_acl_presence_with(
            43,
            |fd, acl_type| {
                assert_eq!(fd, 43);
                assert_eq!(acl_type, sg::ACL_TYPE_EXTENDED);
                expected_acl
            },
            |acl| {
                assert_eq!(acl, expected_acl);
                free_calls.set(free_calls.get() + 1);
                0
            },
            || {
                errno_calls.set(errno_calls.get() + 1);
                io::Error::from_raw_os_error(sg::EINVAL)
            },
        )
        .unwrap();

        assert_eq!(presence, ExtendedAclPresence::Present);
        assert_eq!(free_calls.get(), 1);
        assert_eq!(errno_calls.get(), 0);
    }

    #[test]
    fn fd_acl_presence_preserves_free_error_without_retrying() {
        let expected_acl = fake_acl();
        let free_calls = Cell::new(0);
        let errno_calls = Cell::new(0);

        let error = xacl_extended_acl_presence_with(
            44,
            |fd, acl_type| {
                assert_eq!(fd, 44);
                assert_eq!(acl_type, sg::ACL_TYPE_EXTENDED);
                expected_acl
            },
            |acl| {
                assert_eq!(acl, expected_acl);
                free_calls.set(free_calls.get() + 1);
                -1
            },
            || {
                errno_calls.set(errno_calls.get() + 1);
                io::Error::from_raw_os_error(sg::EINVAL)
            },
        )
        .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(sg::EINVAL));
        assert_eq!(free_calls.get(), 1);
        assert_eq!(errno_calls.get(), 1);
    }

    #[test]
    fn test_acl_init() {
        use std::convert::TryInto;
        let max_entries: usize = ACL_MAX_ENTRIES.try_into().unwrap();

        let acl = xacl_init(max_entries).ok().unwrap();
        assert!(!acl.is_null());
        xacl_free(acl);

        // Custom error if we try to allocate MAX_ENTRIES + 1.
        let err = xacl_init(max_entries + 1).unwrap_err();
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
        let err = xacl_create_entry(&mut acl).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(sg::ENOMEM));

        xacl_free(acl);
    }

    #[test]
    fn test_acl_api_misuse() {
        let mut acl = xacl_init(1).unwrap();
        let entry = xacl_create_entry(&mut acl).unwrap();

        // Setting tag other than 1 or 2 results in EINVAL error.
        let err = xacl_set_tag_type(entry, 0).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

        // Setting qualifier without first setting tag to a valid value results in EINVAL.
        let err = xacl_set_qualifier(entry, &Qualifier::Guid(Uuid::nil())).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

        let entry2 = xacl_create_entry(&mut acl).unwrap();
        xacl_set_tag_type(entry2, 1).unwrap();

        xacl_free(acl);
    }

    #[test]
    fn test_uninitialized_entry() {
        let mut acl = xacl_init(1).unwrap();
        let entry_p = xacl_create_entry(&mut acl).unwrap();

        let (allow, qualifier) = xacl_get_tag_qualifier(acl, entry_p).unwrap();
        assert_eq!(qualifier.name().unwrap(), "@tag 0");
        assert!(!allow);

        xacl_free(acl);
    }
}
