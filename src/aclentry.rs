//! Provides `AclEntry` implementation.

use crate::failx::fail_custom;
use crate::flag::Flag;
use crate::perm::Perm;
use crate::util::*;

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::io;

/// Kind of ACL entry (User, Group, Mask, Other, or Unknown).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AclEntryKind {
    /// Entry represents a user.
    User,

    /// Entry represents a group.
    Group,

    /// Entry represents a Posix.1e mask entry.
    #[cfg(target_os = "linux")]
    Mask,

    /// Entry represents a Posix.1e other entry.
    #[cfg(target_os = "linux")]
    Other,

    /// Entry represents a possibly corrupt ACL entry. Caused by an unknown tag.
    /// The name contains more information.
    Unknown,
}

/// ACL entry with allow/deny semantics.
///
/// ACL entries are ordered so sorting will automatically put the ACL in
/// canonical order.
///
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct AclEntry {
    /// Kind of entry (User, Group, Other, Mask, or Unknown).
    pub kind: AclEntryKind,

    /// Name of the principal being given access. You can use a user/group name
    /// or decimal uid/gid. On macOS you can use a UUID.
    pub name: String,

    /// Permission bits for the entry.
    pub perms: Perm,

    /// Flags indicating whether an entry is inherited, etc.
    #[serde(default)]
    pub flags: Flag,

    /// True if entry is allowed; false means deny. Linux only supports
    /// allow=true.
    #[serde(default = "default_allow")]
    pub allow: bool,
}

// Default value of allow; used for serde.
fn default_allow() -> bool {
    true
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
    pub fn new(
        kind: AclEntryKind,
        name: &str,
        perms: Perm,
        flags: Option<Flag>,
        allow: bool,
    ) -> AclEntry {
        AclEntry {
            kind,
            name: String::from(name),
            perms,
            flags: flags.unwrap_or_default(),
            allow,
        }
    }

    /// Construct an ALLOW access control entry for a user.
    #[must_use]
    pub fn allow_user<F>(name: &str, perms: Perm, flags: F) -> AclEntry
    where
        F: Into<Option<Flag>>,
    {
        AclEntry::new(AclEntryKind::User, name, perms, flags.into(), true)
    }

    /// Construct an ALLOW access control entry for a group.
    #[must_use]
    pub fn allow_group<F>(name: &str, perms: Perm, flags: F) -> AclEntry
    where
        F: Into<Option<Flag>>,
    {
        AclEntry::new(AclEntryKind::Group, name, perms, flags.into(), true)
    }

    /// Construct an ALLOW access control entry for mask.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn allow_mask<F>(perms: Perm, flags: F) -> AclEntry
    where
        F: Into<Option<Flag>>,
    {
        AclEntry::new(AclEntryKind::Mask, "", perms, flags.into(), true)
    }

    /// Construct an ALLOW access control entry for other.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn allow_other<F>(perms: Perm, flags: F) -> AclEntry
    where
        F: Into<Option<Flag>>,
    {
        AclEntry::new(AclEntryKind::Other, "", perms, flags.into(), true)
    }

    /// Construct a DENY access control entry for a user.
    #[must_use]
    pub fn deny_user<F>(name: &str, perms: Perm, flags: F) -> AclEntry
    where
        F: Into<Option<Flag>>,
    {
        AclEntry::new(AclEntryKind::User, name, perms, flags.into(), false)
    }

    /// Construct a DENY access control entry for a group.
    #[must_use]
    pub fn deny_group<F>(name: &str, perms: Perm, flags: F) -> AclEntry
    where
        F: Into<Option<Flag>>,
    {
        AclEntry::new(AclEntryKind::Group, name, perms, flags.into(), false)
    }

    /// Return an `AclEntry` constructed from a native `acl_entry_t`.
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
            Qualifier::User(_) | Qualifier::UserObj => (AclEntryKind::User, qualifier.name()),

            #[cfg(target_os = "linux")]
            Qualifier::Group(_) | Qualifier::GroupObj => (AclEntryKind::Group, qualifier.name()),

            #[cfg(target_os = "linux")]
            Qualifier::Mask => (AclEntryKind::Mask, qualifier.name()),

            #[cfg(target_os = "linux")]
            Qualifier::Other => (AclEntryKind::Other, qualifier.name()),
        };

        Ok(AclEntry {
            kind,
            name,
            perms,
            flags,
            allow,
        })
    }

    fn to_raw(&self, entry: acl_entry_t) -> io::Result<()> {
        let qualifier = self.qualifier()?;

        xacl_set_tag_qualifier(entry, self.allow, &qualifier)?;
        xacl_set_perm(entry, self.perms)?;
        xacl_set_flags(entry, self.flags)?;

        Ok(())
    }

    pub(crate) fn add_to_acl(&self, acl: &mut acl_t) -> io::Result<()> {
        let entry_p = xacl_create_entry(acl)?;
        self.to_raw(entry_p)
    }

    fn qualifier(&self) -> io::Result<Qualifier> {
        let qualifier = match self.kind {
            AclEntryKind::User => Qualifier::user_named(&self.name)?,
            AclEntryKind::Group => Qualifier::group_named(&self.name)?,
            #[cfg(target_os = "linux")]
            AclEntryKind::Mask => Qualifier::mask_named(&self.name)?,
            #[cfg(target_os = "linux")]
            AclEntryKind::Other => Qualifier::other_named(&self.name)?,
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
        let mut acl = vec![
            AclEntry::deny_user("c", Perm::READ, None),
            AclEntry::allow_user("f", Perm::WRITE, None),
            AclEntry::allow_group("3", Perm::EXECUTE, None),
            AclEntry::allow_group("d", Perm::EXECUTE, None),
            AclEntry::allow_user("z", Perm::READ, None),
            AclEntry::allow_group("z", Perm::READ, None),
            AclEntry::deny_user("a", Perm::READ, None),
        ];

        acl.sort();

        let acl_sorted = vec![
            AclEntry::deny_user("a", Perm::READ, None),
            AclEntry::deny_user("c", Perm::READ, None),
            AclEntry::allow_user("f", Perm::WRITE, None),
            AclEntry::allow_user("z", Perm::READ, None),
            AclEntry::allow_group("3", Perm::EXECUTE, None),
            AclEntry::allow_group("d", Perm::EXECUTE, None),
            AclEntry::allow_group("z", Perm::READ, None),
        ];

        assert_eq!(acl, acl_sorted);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_ordering_linux() {
        let mut acl = vec![
            AclEntry::allow_user("f", Perm::WRITE, None),
            AclEntry::allow_mask(Perm::READ, None),
            AclEntry::allow_group("b", Perm::EXECUTE, None),
            AclEntry::allow_group("d", Perm::EXECUTE, None),
            AclEntry::allow_user("z", Perm::READ, None),
            AclEntry::allow_user("", Perm::READ, None),
            AclEntry::allow_other(Perm::EXECUTE, None),
            AclEntry::allow_group("z", Perm::READ, None),
            AclEntry::allow_group("", Perm::READ, None),
        ];

        acl.sort();

        let acl_sorted = vec![
            AclEntry::allow_user("", Perm::READ, None),
            AclEntry::allow_user("f", Perm::WRITE, None),
            AclEntry::allow_user("z", Perm::READ, None),
            AclEntry::allow_group("", Perm::READ, None),
            AclEntry::allow_group("b", Perm::EXECUTE, None),
            AclEntry::allow_group("d", Perm::EXECUTE, None),
            AclEntry::allow_group("z", Perm::READ, None),
            AclEntry::allow_mask(Perm::READ, None),
            AclEntry::allow_other(Perm::EXECUTE, None),
        ];

        assert_eq!(acl, acl_sorted);
    }
}
