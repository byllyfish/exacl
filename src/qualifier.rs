//! Implements the `Qualifier` type for internal use

use crate::failx::*;
#[cfg(target_os = "macos")]
use crate::sys::{id_t, mbr_gid_to_uuid, mbr_uid_to_uuid, mbr_uuid_to_id, sg};

use nix::unistd::{self, Gid, Uid};
use std::io;
#[cfg(target_os = "macos")]
use uuid::Uuid;

#[cfg(target_os = "linux")]
const OWNER_NAME: &str = "";
#[cfg(target_os = "linux")]
const OTHER_NAME: &str = "";
#[cfg(target_os = "linux")]
const MASK_NAME: &str = "";

/// A Qualifier specifies the principal that is allowed/denied access to a
/// resource.
#[derive(Debug, PartialEq)]
pub(crate) enum Qualifier {
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
    pub fn from_guid(guid: Uuid) -> io::Result<Qualifier> {
        let (id_c, idtype) = match guid_to_id(guid) {
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
    pub fn guid(&self) -> io::Result<Uuid> {
        match self {
            Qualifier::User(uid) => uid_to_guid(*uid),
            Qualifier::Group(gid) => gid_to_guid(*gid),
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
fn uid_to_guid(uid: Uid) -> io::Result<Uuid> {
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
fn gid_to_guid(gid: Gid) -> io::Result<Uuid> {
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
fn guid_to_id(guid: Uuid) -> io::Result<(id_t, i32)> {
    let mut id_c: id_t = 0;
    let mut idtype: i32 = 0;
    let guid_ptr = guid.as_bytes().as_ptr() as *mut u8;

    // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
    let ret = unsafe { mbr_uuid_to_id(guid_ptr, &mut id_c, &mut idtype) };
    if ret != 0 {
        return fail_from_err(ret, "mbr_uuid_to_id", guid);
    }

    Ok((id_c, idtype))
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
            uid_to_guid(Uid::from_raw(89)).ok(),
            Some(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap())
        );

        assert_eq!(
            uid_to_guid(Uid::from_raw(1500)).ok(),
            Some(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa000005dc").unwrap())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_gid_to_guid() {
        assert_eq!(
            gid_to_guid(Gid::from_raw(89)).ok(),
            Some(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap())
        );

        assert_eq!(
            gid_to_guid(Gid::from_raw(1500)).ok(),
            Some(Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffff000005dc").unwrap())
        );

        assert_eq!(
            gid_to_guid(Gid::from_raw(20)).ok(),
            Some(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000014").unwrap())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_guid_to_id() {
        assert_eq!(
            guid_to_id(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap()).ok(),
            Some((89, sg::ID_TYPE_UID))
        );

        assert_eq!(
            guid_to_id(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa000005dc").unwrap()).ok(),
            Some((1500, sg::ID_TYPE_UID))
        );

        assert_eq!(
            guid_to_id(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap()).ok(),
            Some((89, sg::ID_TYPE_GID))
        );

        assert_eq!(
            guid_to_id(Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffff000005dc").unwrap()).ok(),
            Some((1500, sg::ID_TYPE_GID))
        );

        assert_eq!(
            guid_to_id(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000014").unwrap()).ok(),
            Some((20, sg::ID_TYPE_GID))
        );

        let err = guid_to_id(Uuid::nil()).err().unwrap();
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
