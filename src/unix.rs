//! Implements utilities for converting user/group names to uid/gid.

use crate::failx::*;
use crate::sys::{getgrgid_r, getgrnam_r, getpwnam_r, getpwuid_r, group, passwd, sg};
#[cfg(target_os = "macos")]
use crate::sys::{id_t, mbr_gid_to_uuid, mbr_uid_to_uuid, mbr_uuid_to_id};

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::os::raw::c_char;
use std::ptr;
#[cfg(target_os = "macos")]
use uuid::Uuid;

// Export uid_t and gid_t.
pub use crate::sys::{gid_t, uid_t};

// Max buffer sizes for getpwnam_r, getgrnam_r, et al. are usually determined
// by calling sysconf with SC_GETPW_R_SIZE_MAX or SC_GETGR_R_SIZE_MAX. Rather
// than calling sysconf, this code hard-wires the default value and quadruples
// the buffer size as needed, up to a maximum of 1MB.

// SC_GETPW_R_SIZE_MAX/SC_GETGR_R_SIZE_MAX default to 1024 on vanilla Ubuntu
// and 4096 on macOS/FreeBSD. We start the initial buffer size at 4096 bytes.

const INITIAL_BUFSIZE: usize = 4096; // 4KB
const MAX_BUFSIZE: usize = 1_048_576; // 1MB

/// Convert user name to uid.
pub fn name_to_uid(name: &str) -> io::Result<uid_t> {
    let mut pwd = mem::MaybeUninit::<passwd>::uninit();
    let mut buf = Vec::<c_char>::with_capacity(INITIAL_BUFSIZE);
    let mut result = ptr::null_mut();
    let cstr = CString::new(name)?;

    let mut ret;
    loop {
        ret = unsafe {
            getpwnam_r(
                cstr.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.capacity(),
                &mut result,
            )
        };

        if ret == 0 || ret != sg::ERANGE || buf.capacity() >= MAX_BUFSIZE {
            break;
        }

        // Quadruple buffer size and try again.
        buf.reserve(4 * buf.capacity());
    }

    if ret != 0 {
        return fail_err(ret, "getpwnam_r", name);
    }

    if !result.is_null() {
        let uid = unsafe { pwd.assume_init().pw_uid };
        return Ok(uid);
    }

    // Try to parse name as a decimal user ID.
    if let Ok(num) = name.parse::<u32>() {
        return Ok(num);
    }

    fail_custom(&format!("unknown user name: {name:?}"))
}

/// Convert group name to gid.
pub fn name_to_gid(name: &str) -> io::Result<gid_t> {
    let mut grp = mem::MaybeUninit::<group>::uninit();
    let mut buf = Vec::<c_char>::with_capacity(INITIAL_BUFSIZE);
    let mut result = ptr::null_mut();
    let cstr = CString::new(name)?;

    let mut ret;
    loop {
        ret = unsafe {
            getgrnam_r(
                cstr.as_ptr(),
                grp.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.capacity(),
                &mut result,
            )
        };

        if ret == 0 || ret != sg::ERANGE || buf.capacity() >= MAX_BUFSIZE {
            break;
        }

        // Quadruple buffer size and try again.
        buf.reserve(4 * buf.capacity());
    }

    if ret != 0 {
        return fail_err(ret, "getgrnam_r", name);
    }

    if !result.is_null() {
        let gid = unsafe { grp.assume_init().gr_gid };
        return Ok(gid);
    }

    // Try to parse name as a decimal group ID.
    if let Ok(num) = name.parse::<u32>() {
        return Ok(num);
    }

    fail_custom(&format!("unknown group name: {name:?}"))
}

/// Convert uid to user name.
pub fn uid_to_name(uid: uid_t) -> io::Result<String> {
    let mut pwd = mem::MaybeUninit::<passwd>::uninit();
    let mut buf = Vec::<c_char>::with_capacity(INITIAL_BUFSIZE);
    let mut result = ptr::null_mut();

    let mut ret;
    loop {
        ret = unsafe {
            getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.capacity(),
                &mut result,
            )
        };

        if ret == 0 || ret != sg::ERANGE || buf.capacity() >= MAX_BUFSIZE {
            break;
        }

        // Quadruple buffer size and try again.
        buf.reserve(4 * buf.capacity());
    }

    if ret != 0 {
        return fail_err(ret, "getpwuid_r", uid);
    }

    if !result.is_null() {
        let cstr = unsafe { CStr::from_ptr(pwd.assume_init().pw_name) };
        return Ok(cstr.to_string_lossy().into_owned());
    }

    Ok(uid.to_string())
}

/// Convert gid to group name.
pub fn gid_to_name(gid: gid_t) -> io::Result<String> {
    let mut grp = mem::MaybeUninit::<group>::uninit();
    let mut buf = Vec::<c_char>::with_capacity(INITIAL_BUFSIZE);
    let mut result = ptr::null_mut();

    let mut ret;
    loop {
        ret = unsafe {
            getgrgid_r(
                gid,
                grp.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.capacity(),
                &mut result,
            )
        };

        if ret == 0 || ret != sg::ERANGE || buf.capacity() >= MAX_BUFSIZE {
            break;
        }

        // Quadruple buffer size and try again.
        buf.reserve(4 * buf.capacity());
    }

    if ret != 0 {
        return fail_err(ret, "getgrgid_r", gid);
    }

    if !result.is_null() {
        let cstr = unsafe { CStr::from_ptr(grp.assume_init().gr_name) };
        return Ok(cstr.to_string_lossy().into_owned());
    }

    Ok(gid.to_string())
}

/// Convert uid to GUID.
#[cfg(target_os = "macos")]
pub fn uid_to_guid(uid: uid_t) -> io::Result<Uuid> {
    let mut bytes = [0u8; 16];

    // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
    let ret = unsafe { mbr_uid_to_uuid(uid, bytes.as_mut_ptr()) };
    if ret != 0 {
        return fail_from_err(ret, "mbr_uid_to_uuid", uid);
    }

    Ok(Uuid::from_bytes(bytes))
}

/// Convert gid to GUID.
#[cfg(target_os = "macos")]
pub fn gid_to_guid(gid: gid_t) -> io::Result<Uuid> {
    let mut bytes = [0u8; 16];

    // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
    let ret = unsafe { mbr_gid_to_uuid(gid, bytes.as_mut_ptr()) };
    if ret != 0 {
        return fail_from_err(ret, "mbr_gid_to_uuid", gid);
    }

    Ok(Uuid::from_bytes(bytes))
}

/// Convert GUID to uid/gid.
///
/// Returns a pair of options (Option[uid], Option[gid]). Either one option must
/// be set or neither is set. If neither is set, the GUID was not found.
#[cfg(target_os = "macos")]
pub fn guid_to_id(guid: Uuid) -> io::Result<(Option<uid_t>, Option<gid_t>)> {
    let mut id_c: id_t = 0;
    let mut idtype: i32 = 0;
    let mut bytes = guid.into_bytes();

    // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
    let ret = unsafe { mbr_uuid_to_id(bytes.as_mut_ptr(), &mut id_c, &mut idtype) };
    if ret == sg::ENOENT {
        // GUID was not found.
        return Ok((None, None));
    }

    if ret != 0 {
        return fail_from_err(ret, "mbr_uuid_to_id", guid);
    }

    let result = match idtype {
        sg::ID_TYPE_UID => (Some(id_c), None),
        sg::ID_TYPE_GID => (None, Some(id_c)),
        _ => {
            return fail_custom(&format!(
                "mbr_uuid_to_id: Unknown idtype {:?} for guid {:?}",
                idtype, guid
            ))
        }
    };

    Ok(result)
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod unix_tests {
    use super::*;

    #[test]
    fn test_name_to_uid() {
        let msg = name_to_uid("").unwrap_err().to_string();
        assert_eq!(msg, "unknown user name: \"\"");

        let msg = name_to_uid("non_existant").unwrap_err().to_string();
        assert_eq!(msg, "unknown user name: \"non_existant\"");

        assert_eq!(name_to_uid("500").ok(), Some(500));

        #[cfg(target_os = "macos")]
        assert_eq!(name_to_uid("_spotlight").ok(), Some(89));

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        assert_eq!(name_to_uid("daemon").ok(), Some(1));
    }

    #[test]
    fn test_name_to_gid() {
        let msg = name_to_gid("").unwrap_err().to_string();
        assert_eq!(msg, "unknown group name: \"\"");

        let msg = name_to_gid("non_existant").unwrap_err().to_string();
        assert_eq!(msg, "unknown group name: \"non_existant\"");

        assert_eq!(name_to_gid("500").ok(), Some(500));

        #[cfg(target_os = "macos")]
        assert_eq!(name_to_gid("_spotlight").ok(), Some(89));

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        assert_eq!(name_to_gid("daemon").ok(), Some(1));
    }

    #[test]
    fn test_uid_to_name() {
        assert_eq!(uid_to_name(1500).unwrap(), "1500");

        #[cfg(target_os = "macos")]
        assert_eq!(uid_to_name(89).unwrap(), "_spotlight");

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        assert_eq!(uid_to_name(1).unwrap(), "daemon");
    }

    #[test]
    fn test_gid_to_name() {
        assert_eq!(gid_to_name(1500).unwrap(), "1500");

        #[cfg(target_os = "macos")]
        assert_eq!(gid_to_name(89).unwrap(), "_spotlight");

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        assert_eq!(gid_to_name(1).unwrap(), "daemon");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_uid_to_guid() {
        assert_eq!(
            uid_to_guid(89).ok(),
            Some(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap())
        );

        assert_eq!(
            uid_to_guid(1500).ok(),
            Some(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa000005dc").unwrap())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_gid_to_guid() {
        assert_eq!(
            gid_to_guid(89).ok(),
            Some(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap())
        );

        assert_eq!(
            gid_to_guid(1500).ok(),
            Some(Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffff000005dc").unwrap())
        );

        assert_eq!(
            gid_to_guid(20).ok(),
            Some(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000014").unwrap())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_guid_to_id() {
        assert_eq!(
            guid_to_id(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap()).unwrap(),
            (Some(89), None)
        );

        assert_eq!(
            guid_to_id(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa000005dc").unwrap()).unwrap(),
            (Some(1500), None)
        );

        assert_eq!(
            guid_to_id(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap()).unwrap(),
            (None, Some(89))
        );

        assert_eq!(
            guid_to_id(Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffff000005dc").unwrap()).unwrap(),
            (None, Some(1500))
        );

        assert_eq!(
            guid_to_id(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000014").unwrap()).unwrap(),
            (None, Some(20))
        );

        assert_eq!(guid_to_id(Uuid::nil()).unwrap(), (None, None));
    }
}
