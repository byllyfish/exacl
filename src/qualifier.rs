//! Implements the `Qualifier` type for internal use

use crate::failx::*;
use crate::unix;
use std::fmt;
use std::io;
#[cfg(target_os = "macos")]
use uuid::Uuid;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const OWNER_NAME: &str = "";
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const OTHER_NAME: &str = "";
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const MASK_NAME: &str = "";
#[cfg(target_os = "freebsd")]
const EVERYONE_NAME: &str = "";

/// A Qualifier specifies the principal that is allowed/denied access to a
/// resource.
#[derive(Debug, PartialEq)]
pub enum Qualifier {
    User(unix::uid_t),
    Group(unix::gid_t),

    #[cfg(target_os = "macos")]
    Guid(Uuid),

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    UserObj,
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    GroupObj,
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    Other,
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    Mask,
    #[cfg(target_os = "freebsd")]
    Everyone,

    Unknown(String),
}

impl Qualifier {
    /// Create qualifier object from a GUID.
    #[cfg(target_os = "macos")]
    pub fn from_guid(guid: Uuid) -> io::Result<Qualifier> {
        let qualifier = match unix::guid_to_id(guid)? {
            (Some(uid), None) => Qualifier::User(uid),
            (None, Some(gid)) => Qualifier::Group(gid),
            (None, None) => Qualifier::Guid(guid),
            _ => unreachable!("guid_to_id bug"),
        };

        Ok(qualifier)
    }

    /// Create qualifier object from a user name.
    #[cfg(target_os = "macos")]
    pub fn user_named(name: &str) -> io::Result<Qualifier> {
        match unix::str_to_uid(name) {
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
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn user_named(name: &str) -> io::Result<Qualifier> {
        match name {
            OWNER_NAME => Ok(Qualifier::UserObj),
            s => match unix::str_to_uid(s) {
                Ok(uid) => Ok(Qualifier::User(uid)),
                Err(err) => Err(err),
            },
        }
    }

    /// Create qualifier object from a group name.
    #[cfg(target_os = "macos")]
    pub fn group_named(name: &str) -> io::Result<Qualifier> {
        match unix::str_to_gid(name) {
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
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn group_named(name: &str) -> io::Result<Qualifier> {
        match name {
            OWNER_NAME => Ok(Qualifier::GroupObj),
            s => match unix::str_to_gid(s) {
                Ok(gid) => Ok(Qualifier::Group(gid)),
                Err(err) => Err(err),
            },
        }
    }

    /// Create qualifier from mask.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn mask_named(name: &str) -> io::Result<Qualifier> {
        match name {
            MASK_NAME => Ok(Qualifier::Mask),
            s => fail_custom(&format!("unknown mask name: {:?}", s)),
        }
    }

    /// Create qualifier from other.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn other_named(name: &str) -> io::Result<Qualifier> {
        match name {
            OTHER_NAME => Ok(Qualifier::Other),
            s => fail_custom(&format!("unknown other name: {:?}", s)),
        }
    }

    /// Create qualifier from everyone.
    #[cfg(target_os = "freebsd")]
    pub fn everyone_named(name: &str) -> io::Result<Qualifier> {
        match name {
            EVERYONE_NAME => Ok(Qualifier::Everyone),
            s => fail_custom(&format!("unknown everyone name: {:?}", s)),
        }
    }

    /// Return the GUID for the user/group.
    #[cfg(target_os = "macos")]
    pub fn guid(&self) -> io::Result<Uuid> {
        match self {
            Qualifier::User(uid) => unix::uid_to_guid(*uid),
            Qualifier::Group(gid) => unix::gid_to_guid(*gid),
            Qualifier::Guid(guid) => Ok(*guid),
            Qualifier::Unknown(tag) => fail_custom(&format!("unknown tag: {:?}", tag)),
        }
    }

    /// Return the name of the user/group.
    pub fn name(&self) -> String {
        match self {
            Qualifier::User(uid) => unix::uid_to_str(*uid),
            Qualifier::Group(gid) => unix::gid_to_str(*gid),
            #[cfg(target_os = "macos")]
            Qualifier::Guid(guid) => guid.to_string(),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::UserObj | Qualifier::GroupObj => OWNER_NAME.to_string(),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::Other => OTHER_NAME.to_string(),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::Mask => MASK_NAME.to_string(),
            #[cfg(target_os = "freebsd")]
            Qualifier::Everyone => EVERYONE_NAME.to_string(),

            Qualifier::Unknown(s) => s.clone(),
        }
    }
}

impl fmt::Display for Qualifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Qualifier::User(uid) => write!(f, "user:{}", uid),
            Qualifier::Group(gid) => write!(f, "group:{}", gid),
            #[cfg(target_os = "macos")]
            Qualifier::Guid(guid) => write!(f, "guid:{}", guid),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::UserObj => write!(f, "user"),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::GroupObj => write!(f, "group"),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::Other => write!(f, "other"),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::Mask => write!(f, "mask"),
            #[cfg(target_os = "freebsd")]
            Qualifier::Everyone => write!(f, "everyone"),
            Qualifier::Unknown(s) => write!(f, "unknown:{}", s),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod qualifier_tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_from_guid() {
        let user =
            Qualifier::from_guid(Uuid::parse_str("ffffeeee-dddd-cccc-bbbb-aaaa00000059").unwrap())
                .ok();
        assert_eq!(user, Some(Qualifier::User(89)));

        let group =
            Qualifier::from_guid(Uuid::parse_str("abcdefab-cdef-abcd-efab-cdef00000059").unwrap())
                .ok();
        assert_eq!(group, Some(Qualifier::Group(89)));

        let user = Qualifier::from_guid(Uuid::nil()).ok();
        assert_eq!(user, Some(Qualifier::Guid(Uuid::nil())));
    }

    #[test]
    fn test_user_named() {
        let user = Qualifier::user_named("89").ok();
        assert_eq!(user, Some(Qualifier::User(89)));

        #[cfg(target_os = "macos")]
        {
            let user = Qualifier::user_named("_spotlight").ok();
            assert_eq!(user, Some(Qualifier::User(89)));

            let user = Qualifier::user_named("ffffeeee-dddd-cccc-bbbb-aaaa00000059").ok();
            assert_eq!(user, Some(Qualifier::User(89)));
        }

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            let user = Qualifier::user_named("daemon").ok();
            assert_eq!(user, Some(Qualifier::User(1)));
        }
    }

    #[test]
    fn test_group_named() {
        let group = Qualifier::group_named("89").ok();
        assert_eq!(group, Some(Qualifier::Group(89)));

        #[cfg(target_os = "macos")]
        {
            let group = Qualifier::group_named("_spotlight").ok();
            assert_eq!(group, Some(Qualifier::Group(89)));

            let group = Qualifier::group_named("abcdefab-cdef-abcd-efab-cdef00000059").ok();
            assert_eq!(group, Some(Qualifier::Group(89)));
        }

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            let group = Qualifier::group_named("daemon").ok();
            assert_eq!(group, Some(Qualifier::Group(1)));
        }
    }
}
