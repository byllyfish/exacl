//! Implements the Qualifier data type.

use crate::sys::*;
use crate::util::custom_error;

use log::debug;
use nix::unistd::{self, Gid, Uid};
use std::io;
use uuid::Uuid;

/// Specifies the principal that is allowed/denied access to a resource.
#[derive(Debug, PartialEq)]
pub enum Qualifier {
    User(Uid),
    Group(Gid),
    Guid(Uuid),
    Unknown(String),
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

    Err(custom_error(&format!("unknown user name: {:?}", name)))
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

    Err(custom_error(&format!("unknown group name: {:?}", name)))
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
fn xuid_to_guid(uid: Uid) -> io::Result<Uuid> {
    let guid = Uuid::nil();

    let ret = unsafe { mbr_uid_to_uuid(uid.as_raw(), guid.as_bytes().as_ptr() as *mut u8) };
    if ret != 0 {
        // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
        let err = io::Error::from_raw_os_error(ret);
        debug!("mbr_uid_to_uuid({}) returned err={}", uid, err);
        return Err(err);
    }

    Ok(guid)
}

/// Convert gid to GUID.
fn xgid_to_guid(gid: Gid) -> io::Result<Uuid> {
    let guid = Uuid::nil();

    let ret = unsafe { mbr_gid_to_uuid(gid.as_raw(), guid.as_bytes().as_ptr() as *mut u8) };
    if ret != 0 {
        // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
        let err = io::Error::from_raw_os_error(ret);
        debug!("mbr_gid_to_uuid({}) returned err={}", gid, err);
        return Err(err);
    }

    Ok(guid)
}

/// Convert GUID to uid/gid.
fn xguid_to_id(guid: Uuid) -> io::Result<(uid_t, u32)> {
    let mut id_c: uid_t = 0;
    let mut idtype: i32 = 0;
    let guid_ptr = guid.as_bytes().as_ptr() as *mut u8;

    let ret = unsafe { mbr_uuid_to_id(guid_ptr, &mut id_c, &mut idtype) };
    if ret != 0 {
        // On error, returns one of {EIO, ENOENT, EAUTH, EINVAL, ENOMEM}.
        let err = io::Error::from_raw_os_error(ret);
        debug!("mbr_uuid_to_id({}) returned err={}", guid, err);
        return Err(err);
    }
    assert!(idtype >= 0);

    Ok((id_c, idtype as u32))
}

impl Qualifier {
    /// Create qualifier object from a GUID.
    pub fn from_guid(guid: Uuid) -> io::Result<Qualifier> {
        let (id_c, idtype) = match xguid_to_id(guid) {
            Ok(info) => info,
            Err(err) => {
                const ERR_NOT_FOUND: i32 = ENOENT as i32;
                if let Some(ERR_NOT_FOUND) = err.raw_os_error() {
                    return Ok(Qualifier::Guid(guid));
                } else {
                    return Err(err);
                }
            }
        };

        let qualifier = match idtype {
            ID_TYPE_UID => Qualifier::User(Uid::from_raw(id_c)),
            ID_TYPE_GID => Qualifier::Group(Gid::from_raw(id_c)),
            other => {
                debug!("Unknown idtype {}", other);
                Qualifier::Unknown(guid.to_string())
            }
        };

        Ok(qualifier)
    }

    /// Create qualifier object from a user name.
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

    /// Create qualifier object from a group name.
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

    /// Return the GUID for the user/group.
    pub fn guid(&self) -> io::Result<Uuid> {
        match self {
            Qualifier::User(uid) => xuid_to_guid(*uid),
            Qualifier::Group(gid) => xgid_to_guid(*gid),
            Qualifier::Guid(guid) => Ok(*guid),
            Qualifier::Unknown(tag) => Err(custom_error(&format!("unknown tag: {:?}", tag))),
        }
    }

    /// Return the name of the user/group.
    pub fn name(&self) -> String {
        match self {
            Qualifier::User(uid) => uid_to_str(*uid),
            Qualifier::Group(gid) => gid_to_str(*gid),
            Qualifier::Guid(guid) => guid.to_string(),
            Qualifier::Unknown(s) => s.clone(),
        }
    }
}

#[test]
fn test_str_to_uid() {
    let msg = str_to_uid("").unwrap_err().to_string();
    assert_eq!(msg, "unknown user name: \"\"");

    let msg = str_to_uid("non_existant").unwrap_err().to_string();
    assert_eq!(msg, "unknown user name: \"non_existant\"");

    assert_eq!(str_to_uid("500").ok(), Some(Uid::from_raw(500)));
    assert_eq!(str_to_uid("_spotlight").ok(), Some(Uid::from_raw(89)));
}

#[test]
fn test_str_to_gid() {
    let msg = str_to_gid("").unwrap_err().to_string();
    assert_eq!(msg, "unknown group name: \"\"");

    let msg = str_to_gid("non_existant").unwrap_err().to_string();
    assert_eq!(msg, "unknown group name: \"non_existant\"");

    assert_eq!(str_to_gid("500").ok(), Some(Gid::from_raw(500)));
    assert_eq!(str_to_gid("_spotlight").ok(), Some(Gid::from_raw(89)));
    assert_eq!(str_to_gid("staff").ok(), Some(Gid::from_raw(20)));
}

#[test]
fn test_uid_to_str() {
    assert_eq!(uid_to_str(Uid::from_raw(1500)), "1500");
    assert_eq!(uid_to_str(Uid::from_raw(89)), "_spotlight");
}

#[test]
fn test_gid_to_str() {
    assert_eq!(gid_to_str(Gid::from_raw(1500)), "1500");
    assert_eq!(gid_to_str(Gid::from_raw(89)), "_spotlight");
    assert_eq!(gid_to_str(Gid::from_raw(20)), "staff");
}

#[test]
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
fn test_guid_to_id() {
    assert_eq!(
        xguid_to_id(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap()).ok(),
        Some((89, ID_TYPE_UID))
    );

    assert_eq!(
        xguid_to_id(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa000005dc").unwrap()).ok(),
        Some((1500, ID_TYPE_UID))
    );

    assert_eq!(
        xguid_to_id(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap()).ok(),
        Some((89, ID_TYPE_GID))
    );

    assert_eq!(
        xguid_to_id(Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffff000005dc").unwrap()).ok(),
        Some((1500, ID_TYPE_GID))
    );

    assert_eq!(
        xguid_to_id(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000014").unwrap()).ok(),
        Some((20, ID_TYPE_GID))
    );

    let err = xguid_to_id(Uuid::nil()).err().unwrap();
    assert_eq!(err.raw_os_error().unwrap(), ENOENT as i32);
}

#[test]
fn test_qualifier_ctor() {
    let user =
        Qualifier::from_guid(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap()).ok();
    assert_eq!(user, Some(Qualifier::User(Uid::from_raw(89))));

    let group =
        Qualifier::from_guid(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap()).ok();
    assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(89))));

    let user = Qualifier::from_guid(Uuid::nil()).ok();
    assert_eq!(user, Some(Qualifier::Guid(Uuid::nil())));

    let user = Qualifier::user_named("89").ok();
    assert_eq!(user, Some(Qualifier::User(Uid::from_raw(89))));

    let user = Qualifier::user_named("_spotlight").ok();
    assert_eq!(user, Some(Qualifier::User(Uid::from_raw(89))));

    let user = Qualifier::user_named("ffffeeee-dddd-cccc-bbbb-aaaa00000059").ok();
    assert_eq!(user, Some(Qualifier::User(Uid::from_raw(89))));

    let group = Qualifier::group_named("89").ok();
    assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(89))));

    let group = Qualifier::group_named("_spotlight").ok();
    assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(89))));

    let group = Qualifier::group_named("abcdefab-cdef-abcd-efab-cdef00000059").ok();
    assert_eq!(group, Some(Qualifier::Group(Gid::from_raw(89))));
}
