//! Provides `AclEntry` implementation.

use crate::failx::fail_custom;
use crate::flag::Flag;
use crate::perm::Perm;
use crate::util::*;

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::io;

/// Kind of ACL entry (e.g. user, group, or unknown).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AclEntryKind {
    User,
    Group,
    Unknown,
}

/// ACL entry with allow/deny semantics.
///
/// ACL entries are ordered so sorting will automatically put the ACL in
/// canonical order.
///
#[derive(Debug, PartialEq, Serialize, Deserialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct AclEntry {
    // API subject to change!
    pub kind: AclEntryKind,
    pub name: String,
    pub perms: Perm,
    pub flags: Flag,
    pub allow: bool,
}

impl Ord for AclEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        let ret = self.allow.cmp(&other.allow);
        if ret != Ordering::Equal {
            return ret;
        }

        let ret = self.kind.cmp(&other.kind);
        if ret != Ordering::Equal {
            return ret;
        }

        self.name.cmp(&other.name)
    }
}

impl PartialOrd for AclEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl AclEntry {
    /// Construct a new access control entry.
    #[must_use]
    pub fn new(kind: AclEntryKind, name: &str, perms: Perm, flags: Flag, allow: bool) -> AclEntry {
        AclEntry {
            kind,
            name: String::from(name),
            perms,
            flags,
            allow,
        }
    }

    /// Construct an ALLOW access control entry for a user.
    #[must_use]
    pub fn allow_user(name: &str, perms: Perm, flags: Flag) -> AclEntry {
        AclEntry::new(AclEntryKind::User, name, perms, flags, true)
    }

    /// Construct an ALLOW access control entry for a group.
    #[must_use]
    pub fn allow_group(name: &str, perms: Perm, flags: Flag) -> AclEntry {
        AclEntry::new(AclEntryKind::Group, name, perms, flags, true)
    }

    /// Construct a DENY access control entry for a user.
    #[must_use]
    pub fn deny_user(name: &str, perms: Perm, flags: Flag) -> AclEntry {
        AclEntry::new(AclEntryKind::User, name, perms, flags, false)
    }

    /// Construct a DENY access control entry for a group.
    #[must_use]
    pub fn deny_group(name: &str, perms: Perm, flags: Flag) -> AclEntry {
        AclEntry::new(AclEntryKind::Group, name, perms, flags, false)
    }

    /// Construct an ALLOW access control entry for a user/group.
    #[must_use]
    pub fn allow(kind: AclEntryKind, name: &str, perms: Perm) -> AclEntry {
        AclEntry::new(kind, name, perms, Flag::empty(), true)
    }

    /// Construct a DENY access control entry for a user/group.
    #[must_use]
    pub fn deny(kind: AclEntryKind, name: &str, perms: Perm) -> AclEntry {
        AclEntry::new(kind, name, perms, Flag::empty(), false)
    }

    pub(crate) fn from_raw(entry: acl_entry_t) -> io::Result<AclEntry> {
        let (allow, qualifier) = xacl_get_tag_qualifier(entry)?;
        let perms = xacl_get_perm(entry)?;
        let flags = xacl_get_flags(entry)?;

        let (kind, name) = match qualifier {
            Qualifier::Unknown(s) => (AclEntryKind::Unknown, s),

            #[cfg(target_os = "macos")]
            Qualifier::User(_) | Qualifier::Guid(_) => (AclEntryKind::User, qualifier.name()),

            #[cfg(target_os = "macos")]
            Qualifier::Group(_) => (AclEntryKind::Group, qualifier.name()),

            #[cfg(target_os = "linux")]
            Qualifier::User(_) | Qualifier::UserObj | Qualifier::Other => {
                (AclEntryKind::User, qualifier.name())
            }

            #[cfg(target_os = "linux")]
            Qualifier::Group(_) | Qualifier::GroupObj | Qualifier::Mask => {
                (AclEntryKind::Group, qualifier.name())
            }
        };

        Ok(AclEntry {
            kind,
            name,
            perms,
            flags,
            allow,
        })
    }

    pub(crate) fn to_raw(&self, entry: acl_entry_t) -> io::Result<()> {
        let qualifier = self.qualifier()?;

        xacl_set_tag_qualifier(entry, self.allow, &qualifier)?;
        xacl_set_perm(entry, self.perms)?;
        xacl_set_flags(entry, self.flags)?;

        Ok(())
    }

    fn qualifier(&self) -> io::Result<Qualifier> {
        let qualifier = match self.kind {
            AclEntryKind::User => Qualifier::user_named(&self.name)?,
            AclEntryKind::Group => Qualifier::group_named(&self.name)?,
            AclEntryKind::Unknown => {
                return fail_custom("unsupported kind: \"unknown\"");
            }
        };

        Ok(qualifier)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod aclentry_tests {
    use super::*;

    #[test]
    fn test_from_raw_on_corrupt_entry() {
        let mut acl = xacl_init(1).unwrap();
        let entry_p = xacl_create_entry(&mut acl).unwrap();

        let entry = AclEntry::from_raw(entry_p).unwrap();
        assert_eq!(entry.name, "@tag:0");

        #[cfg(target_os = "macos")]
        assert_eq!(entry.allow, false);

        #[cfg(target_os = "linux")]
        assert_eq!(entry.allow, true);

        xacl_free(acl);
    }

    #[test]
    fn test_ordering() {
        use AclEntryKind::{Group, User};

        let mut acl = vec![
            AclEntry::deny(User, "c", Perm::READ),
            AclEntry::allow(User, "f", Perm::WRITE),
            AclEntry::allow(Group, "b", Perm::EXECUTE),
            AclEntry::allow(Group, "d", Perm::EXECUTE),
            AclEntry::allow(User, "@z", Perm::READ),
            AclEntry::allow(Group, "@z", Perm::READ),
            AclEntry::deny(User, "a", Perm::READ),
        ];

        acl.sort();

        let acl_sorted = vec![
            AclEntry::deny(User, "a", Perm::READ),
            AclEntry::deny(User, "c", Perm::READ),
            AclEntry::allow(User, "@z", Perm::READ),
            AclEntry::allow(User, "f", Perm::WRITE),
            AclEntry::allow(Group, "@z", Perm::READ),
            AclEntry::allow(Group, "b", Perm::EXECUTE),
            AclEntry::allow(Group, "d", Perm::EXECUTE),
        ];

        assert_eq!(acl, acl_sorted);
    }
}
