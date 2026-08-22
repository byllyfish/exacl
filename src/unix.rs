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
    // Lookup user name using `getpwnam_r`.
    if let Some(uid) = getpwnam(name)? {
        return Ok(uid);
    }

    // Try to parse name as a decimal user ID.
    if let Ok(num) = name.parse::<u32>() {
        return Ok(num);
    }

    fail_custom(&format!("unknown user name: {name:?}"))
}

/// Convert user name to uid using `getpwnam_r` library call.
fn getpwnam(name: &str) -> io::Result<Option<uid_t>> {
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
                &raw mut result,
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

    if result.is_null() {
        Ok(None)
    } else {
        let uid = unsafe { pwd.assume_init().pw_uid };
        Ok(Some(uid))
    }
}

/// Convert group name to gid.
pub fn name_to_gid(name: &str) -> io::Result<gid_t> {
    // Lookup group name using `getgrnam_r`.
    if let Some(gid) = getgrnam(name)? {
        return Ok(gid);
    }

    // Try to parse name as a decimal group ID.
    if let Ok(num) = name.parse::<u32>() {
        return Ok(num);
    }

    fail_custom(&format!("unknown group name: {name:?}"))
}

/// Convert group name to gid using `getgrnam_r` library call.
fn getgrnam(name: &str) -> io::Result<Option<gid_t>> {
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
                &raw mut result,
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

    if result.is_null() {
        Ok(None)
    } else {
        let gid = unsafe { grp.assume_init().gr_gid };
        Ok(Some(gid))
    }
}

/// Convert uid to user name.
pub fn uid_to_name(uid: uid_t) -> io::Result<String> {
    if let Some(name) = getpwuid(uid)? {
        return Ok(name);
    }

    Ok(uid.to_string())
}

/// Convert uid to name using `getpwuid_r` library call.
fn getpwuid(uid: uid_t) -> io::Result<Option<String>> {
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
                &raw mut result,
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

    if result.is_null() {
        Ok(None)
    } else {
        let cstr = unsafe { CStr::from_ptr(pwd.assume_init().pw_name) };
        Ok(Some(cstr.to_string_lossy().into_owned()))
    }
}

/// Convert gid to group name.
pub fn gid_to_name(gid: gid_t) -> io::Result<String> {
    if let Some(name) = getgrgid(gid)? {
        return Ok(name);
    }

    Ok(gid.to_string())
}

/// Convert gid to name using `getgruid_r` library call.
fn getgrgid(gid: gid_t) -> io::Result<Option<String>> {
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
                &raw mut result,
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

    if result.is_null() {
        Ok(None)
    } else {
        let cstr = unsafe { CStr::from_ptr(grp.assume_init().gr_name) };
        Ok(Some(cstr.to_string_lossy().into_owned()))
    }
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
    let ret = unsafe { mbr_uuid_to_id(bytes.as_mut_ptr(), &raw mut id_c, &raw mut idtype) };
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
                "mbr_uuid_to_id: Unknown idtype {idtype:?} for guid {guid:?}"
            ));
        }
    };

    Ok(result)
}

////////////////////////////////////////////////////////////////////////////////

/// The `unix::helper` module contains a `getent` function that looks up a
/// uid/gid for a specific user name. This module is provided for test code
/// only.
#[cfg(test)]
pub mod helper {
    /// Retrieve `user_id` and `group_id` of unix user with specified name.
    /// Equivalent to running `getent passwd NAME`.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn getent(name: &str) -> (u32, u32) {
        use std::str::FromStr;

        let cmd = std::process::Command::new("getent")
            .args(["passwd", name])
            .output()
            .expect("failed to execute getent");

        if !cmd.status.success() {
            let error = String::from_utf8(cmd.stderr).expect("invalid utf8");
            panic!("getent failed ({name}): {error:?}")
        }

        // Expected output:
        // ```
        // NAME:x:UID:GID:...
        // ```

        let out = String::from_utf8(cmd.stdout).expect("invalid utf8");
        let tokens = out.split(':').collect::<Vec<_>>();
        assert_eq!(tokens[0], name);
        let user_id = u32::from_str(tokens[2]).expect("invalid uid");
        let group_id = u32::from_str(tokens[3]).expect("invalid gid");

        (user_id, group_id)
    }

    /// Retrieve `user_id` and `group_id` of unix entity with specified name.
    ///  `dscl . -read /Users/NAME UniqueID PrimaryGroupID`
    #[cfg(target_os = "macos")]
    pub fn getent(name: &str) -> (u32, u32) {
        use std::str::FromStr;

        let cmd = std::process::Command::new("dscl")
            .args([
                ".",
                "-read",
                &format!("/Users/{name}"),
                "UniqueID",
                "PrimaryGroupID",
            ])
            .output()
            .expect("failed to execute dscl");

        if !cmd.status.success() {
            let error = String::from_utf8(cmd.stderr).expect("invalid utf8");
            panic!("dscl failed ({name}): {error:?}")
        }

        // Expected output:
        // ```
        // PrimaryGroupID: GID
        // UniqueID: UID
        // ```

        let out = String::from_utf8(cmd.stdout).expect("invalid utf8");
        let mut group_id = None;
        let mut user_id = None;

        for line in out.lines() {
            // Split token pair on space character.
            let tokens = line.split_once(' ').unwrap();
            match tokens.0 {
                "PrimaryGroupID:" => group_id = Some(u32::from_str(tokens.1).expect("invalid gid")),
                "UniqueID:" => user_id = Some(u32::from_str(tokens.1).expect("invalid uid")),
                _ => (),
            }
        }

        (user_id.expect("no uid"), group_id.expect("no gid"))
    }

    /// Test the `getent` test function using $USER and "daemon".
    #[test]
    fn test_getent() {
        let user = std::env::var("USER").unwrap();
        let result = getent(&user);
        eprintln!("getent: {user} = {result:?}");

        let user = "daemon";
        let result = getent(user);
        eprintln!("getent: {user} = {result:?}");

        #[cfg(target_os = "macos")]
        {
            let user = "_spotlight";
            let result = getent(user);
            eprintln!("getent: {user} = {result:?}");
        }
    }
}

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
        {
            let (user_id, _) = getent("daemon");
            assert_eq!(name_to_uid("daemon").ok(), Some(user_id));
        }
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
        {
            let (_, group_id) = getent("daemon");
            assert_eq!(name_to_gid("daemon").ok(), Some(group_id));
        }
    }

    #[test]
    fn test_uid_to_name() {
        assert_eq!(uid_to_name(1500).unwrap(), "1500");

        #[cfg(target_os = "macos")]
        assert_eq!(uid_to_name(89).unwrap(), "_spotlight");

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            let (user_id, _) = getent("daemon");
            assert_eq!(uid_to_name(user_id).unwrap(), "daemon");
        }
    }

    #[test]
    fn test_gid_to_name() {
        assert_eq!(gid_to_name(1500).unwrap(), "1500");

        #[cfg(target_os = "macos")]
        assert_eq!(gid_to_name(89).unwrap(), "_spotlight");

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            let (_, group_id) = getent("daemon");
            assert_eq!(gid_to_name(group_id).unwrap(), "daemon");
        }
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
