//! Provides AclEntry implementation.

use crate::flag::Flag;
use crate::perm::Perm;
use crate::qualifier::Qualifier;
use crate::util::*;

use serde::{Deserialize, Serialize};
use std::io;

/// Kind of ACL entry (e.g. user, group, or unknown).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclEntryKind {
    User,
    Group,
    Unknown,
}

/// ACL entry with allow/deny semantics.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclEntry {
    // API subject to change!
    pub kind: AclEntryKind,
    pub name: String,
    pub perms: Perm,
    pub flags: Flag,
    pub allow: bool,
}

impl AclEntry {
    /// Construct an ALLOW access control entry.
    pub fn allow(kind: AclEntryKind, name: &str, perms: Perm) -> AclEntry {
        AclEntry {
            kind,
            name: String::from(name),
            perms,
            flags: Flag::empty(),
            allow: true,
        }
    }

    /// Construct a DENY access control entry.
    pub fn deny(kind: AclEntryKind, name: &str, perms: Perm) -> AclEntry {
        AclEntry {
            kind,
            name: String::from(name),
            perms,
            flags: Flag::empty(),
            allow: false,
        }
    }

    pub(crate) fn from_raw(entry: acl_entry_t) -> io::Result<AclEntry> {
        let (allow, qualifier) = xacl_get_tag_qualifier(entry)?;
        let perms = xacl_get_perm(entry)?;
        let flags = xacl_get_flags(entry)?;

        let (kind, name) = match qualifier {
            Qualifier::User(_) => (AclEntryKind::User, qualifier.name()),
            Qualifier::Group(_) => (AclEntryKind::Group, qualifier.name()),
            Qualifier::Unknown(s) => (AclEntryKind::Unknown, s),
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
                return Err(custom_error("unsupported kind", "unknown"));
            }
        };

        Ok(qualifier)
    }

    /// Validate the entry.
    pub(crate) fn validate(&self) -> Option<String> {
        if let Err(err) = self.qualifier() {
            return Some(err.to_string());
        }

        None
    }
}
