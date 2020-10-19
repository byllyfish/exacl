//! Implements the Qualifier data type.

use crate::sys::*;

use nix::unistd::{self, Gid, Uid};
use std::io;
use uuid::Uuid;

/// Specifies the principal that is allowed/denied access to a resource.
#[derive(Debug)]
pub enum Qualifier {
    User(Uid),
    Group(Gid),
    Unknown(String),
}

/// Convert user name to uid.
fn str_to_uid(name: &str) -> io::Result<Uid> {
    // Try to parse name as a decimal user ID.
    if let Ok(num) = name.parse::<u32>() {
        return Ok(Uid::from_raw(num));
    }

    if let Ok(Some(user)) = unistd::User::from_name(name) {
        Ok(user.uid)
    } else {
        // FIXME report error from_name...
        Err(io::Error::new(io::ErrorKind::NotFound, "Unknown user name"))
    }
}

/// Convert group name to gid.
fn str_to_gid(name: &str) -> io::Result<Gid> {
    // Try to parse name as a decimal group ID.
    if let Ok(num) = name.parse::<u32>() {
        return Ok(Gid::from_raw(num));
    }

    if let Ok(Some(group)) = unistd::Group::from_name(name) {
        Ok(group.gid)
    } else {
        // FIXME report error from_name.
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Unknown group name",
        ))
    }
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
fn uid_to_guid(uid: Uid) -> io::Result<Uuid> {
    let guid = Uuid::nil();
    let ret = unsafe { mbr_uid_to_uuid(uid.as_raw(), guid.as_bytes().as_ptr() as *mut u8) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(guid)
}

/// Convert gid to GUID.
fn gid_to_guid(gid: Gid) -> io::Result<Uuid> {
    let guid = Uuid::nil();
    let ret = unsafe { mbr_gid_to_uuid(gid.as_raw(), guid.as_bytes().as_ptr() as *mut u8) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(guid)
}

impl Qualifier {
    // Create qualifier object from a GUID.
    pub fn from_guid(guid: Uuid) -> io::Result<Qualifier> {
        let mut id_c: uid_t = 0;
        let mut idtype: ::std::os::raw::c_int = 0;
        let guid_ptr = guid.as_bytes().as_ptr() as *mut u8;
        let ret = unsafe { mbr_uuid_to_id(guid_ptr, &mut id_c, &mut idtype) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let qualifier = match idtype as u32 {
            ID_TYPE_UID => Qualifier::User(Uid::from_raw(id_c)),
            ID_TYPE_GID => Qualifier::Group(Gid::from_raw(id_c)),
            _ => Qualifier::Unknown(guid.to_string()),
        };

        Ok(qualifier)
    }

    pub fn user_named(name: &str) -> io::Result<Qualifier> {
        let uid = str_to_uid(name)?;
        Ok(Qualifier::User(uid))
    }

    pub fn group_named(name: &str) -> io::Result<Qualifier> {
        let gid = str_to_gid(name)?;
        Ok(Qualifier::Group(gid))
    }

    /// Return the GUID for the user/group.
    pub fn guid(&self) -> io::Result<Uuid> {
        match self {
            Qualifier::User(uid) => uid_to_guid(*uid),
            Qualifier::Group(gid) => gid_to_guid(*gid),
            Qualifier::Unknown(_) => {
                let err = io::Error::new(io::ErrorKind::InvalidInput, "Unknown ACL tag");
                Err(err)
            }
        }
    }

    /// Return the name of the user/group.
    pub fn name(&self) -> String {
        match self {
            Qualifier::User(uid) => uid_to_str(*uid),
            Qualifier::Group(gid) => gid_to_str(*gid),
            Qualifier::Unknown(s) => s.clone(),
        }
    }
}
