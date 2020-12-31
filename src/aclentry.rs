//! Provides `AclEntry` implementation.

use crate::failx::fail_custom;
use crate::flag::Flag;
use crate::format;
use crate::perm::Perm;
use crate::qualifier::Qualifier;
use crate::util::*;

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::io;

/// Kind of ACL entry (User, Group, Mask, Other, or Unknown).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AclEntryKind {
    /// Entry represents a user.
    User,

    /// Entry represents a group.
    Group,

    /// Entry represents a Posix.1e "mask" entry.
    #[cfg(any(docsrs, target_os = "linux", target_os = "freebsd"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "freebsd"))))]
    Mask,

    /// Entry represents a Posix.1e "other" entry.
    #[cfg(any(docsrs, target_os = "linux", target_os = "freebsd"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "freebsd"))))]
    Other,

    /// Entry represents a possibly corrupt ACL entry, caused by an unknown tag.
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
const fn default_allow() -> bool {
    true
}

impl Ord for AclEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Entries with flags last.
        match (self.flags.is_empty(), other.flags.is_empty()) {
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => (),
        }

        // Denied entries first.
        let ret = self.allow.cmp(&other.allow);
        if ret != Ordering::Equal {
            return ret;
        }

        // Order by kind.
        let ret = self.kind.cmp(&other.kind);
        if ret != Ordering::Equal {
            return ret;
        }

        // Lastly, order by name.
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for AclEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AclEntry {
    /// Construct a new access control entry.
    #[must_use]
    fn new(
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
    #[cfg(any(docsrs, target_os = "linux", target_os = "freebsd"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "freebsd"))))]
    #[must_use]
    pub fn allow_mask<F>(perms: Perm, flags: F) -> AclEntry
    where
        F: Into<Option<Flag>>,
    {
        AclEntry::new(AclEntryKind::Mask, "", perms, flags.into(), true)
    }

    /// Construct an ALLOW access control entry for other.
    #[cfg(any(docsrs, target_os = "linux", target_os = "freebsd"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "freebsd"))))]
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

            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::User(_) | Qualifier::UserObj => (AclEntryKind::User, qualifier.name()),

            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::Group(_) | Qualifier::GroupObj => (AclEntryKind::Group, qualifier.name()),

            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Qualifier::Mask => (AclEntryKind::Mask, qualifier.name()),

            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
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

    pub(crate) fn add_to_acl(&self, acl: &mut acl_t) -> io::Result<()> {
        let qualifier = self.qualifier()?;

        // Check for duplicates already in the list.
        xacl_foreach(*acl, |entry| {
            let (_, prev) = xacl_get_tag_qualifier(entry)?;
            if prev == qualifier {
                let default = if self.flags.contains(Flag::DEFAULT) {
                    "default "
                } else {
                    ""
                };
                fail_custom(&format!("duplicate {}entry for \"{}\"", default, qualifier))?;
            }
            Ok(())
        })?;

        // Adding an ACL entry may cause the acl's memory to be reallocated.
        let entry_p = xacl_create_entry(acl)?;
        xacl_set_tag_qualifier(entry_p, self.allow, &qualifier)?;
        xacl_set_perm(entry_p, self.perms)?;
        xacl_set_flags(entry_p, self.flags)?;

        Ok(())
    }

    fn qualifier(&self) -> io::Result<Qualifier> {
        let qualifier = match self.kind {
            AclEntryKind::User => Qualifier::user_named(&self.name)?,
            AclEntryKind::Group => Qualifier::group_named(&self.name)?,
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            AclEntryKind::Mask => Qualifier::mask_named(&self.name)?,
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            AclEntryKind::Other => Qualifier::other_named(&self.name)?,
            AclEntryKind::Unknown => {
                return fail_custom("unsupported kind: \"unknown\"");
            }
        };

        Ok(qualifier)
    }
}

impl fmt::Display for AclEntryKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        format::write_enum(f, self)
    }
}

impl std::str::FromStr for AclEntryKind {
    type Err = format::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "u" => Ok(AclEntryKind::User),
            "g" => Ok(AclEntryKind::Group),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            "o" => Ok(AclEntryKind::Other),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            "m" => Ok(AclEntryKind::Mask),
            _ => format::read_enum(s),
        }
    }
}

impl fmt::Display for AclEntry {
    /// Format an `AclEntry` 5-tuple:
    ///   <allow>:<flags>:<kind>:<name>:<perms>
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let allow = if self.allow { "allow" } else { "deny" };
        write!(
            f,
            "{}:{}:{}:{}:{}",
            allow, self.flags, self.kind, self.name, self.perms
        )
    }
}

fn parse_allow(value: &str) -> Result<bool, format::Error> {
    let result = match value {
        "allow" => true,
        "deny" => false,
        s => {
            return Err(format::Error::Message(format!(
                "Unknown variant `{}`, expected one of `allow`, `deny`",
                s
            )))
        }
    };
    Ok(result)
}

impl std::str::FromStr for AclEntry {
    type Err = format::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields = s.splitn(5, ':').map(str::trim).collect::<Vec<&str>>();

        let entry = match fields.len() {
            5 => {
                // <allow>:<flags>:<kind>:<name>:<perms>
                let allow = parse_allow(fields[0])?;
                let flags = fields[1].parse::<Flag>()?;
                let kind = fields[2].parse::<AclEntryKind>()?;
                let name = fields[3];
                let perms = fields[4].parse::<Perm>()?;
                AclEntry::new(kind, name, perms, Some(flags), allow)
            }
            4 => {
                // <flags>:<kind>:<name>:<perms>
                let allow = true;
                let flags = fields[0].parse::<Flag>()?;
                let kind = fields[1].parse::<AclEntryKind>()?;
                let name = fields[2];
                let perms = fields[3].parse::<Perm>()?;
                AclEntry::new(kind, name, perms, Some(flags), allow)
            }
            3 => {
                // <kind>:<name>:<perms>
                let allow = true;
                let flags = Flag::empty();
                let kind = fields[0].parse::<AclEntryKind>()?;
                let name = fields[1];
                let perms = fields[2].parse::<Perm>()?;
                AclEntry::new(kind, name, perms, Some(flags), allow)
            }
            _ => {
                return Err(format::Error::Message(format!(
                    "Unknown ACL format: `{}`",
                    s
                )))
            }
        };

        Ok(entry)
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
        assert_eq!(entry.name, "@tag 0");

        #[cfg(target_os = "macos")]
        assert_eq!(entry.allow, false);

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        assert_eq!(entry.allow, true);

        xacl_free(acl);
    }

    #[test]
    fn test_ordering() {
        let mut acl = vec![
            AclEntry::allow_user("f", Perm::WRITE, None),
            AclEntry::allow_group("3", Perm::EXECUTE, None),
            AclEntry::allow_group("d", Perm::EXECUTE, None),
            AclEntry::allow_user("z", Perm::READ, None),
            AclEntry::allow_group("z", Perm::READ, None),
            #[cfg(target_os = "macos")]
            AclEntry::deny_user("a", Perm::READ, Flag::FILE_INHERIT),
            AclEntry::deny_user("c", Perm::READ, None),
        ];

        acl.sort();

        let acl_sorted = vec![
            AclEntry::deny_user("c", Perm::READ, None),
            AclEntry::allow_user("f", Perm::WRITE, None),
            AclEntry::allow_user("z", Perm::READ, None),
            AclEntry::allow_group("3", Perm::EXECUTE, None),
            AclEntry::allow_group("d", Perm::EXECUTE, None),
            AclEntry::allow_group("z", Perm::READ, None),
            #[cfg(target_os = "macos")]
            AclEntry::deny_user("a", Perm::READ, Flag::FILE_INHERIT),
        ];

        assert_eq!(acl, acl_sorted);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
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
            AclEntry::allow_group("a", Perm::READ, Flag::DEFAULT),
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
            AclEntry::allow_group("a", Perm::READ, Flag::DEFAULT),
        ];

        assert_eq!(acl, acl_sorted);
    }

    #[test]
    fn test_display_kind() {
        assert_eq!(format!("{}", AclEntryKind::User), "user");
        assert_eq!(format!("{}", AclEntryKind::Group), "group");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_display_entry() {
        let perms = Perm::READ | Perm::EXECUTE;
        let flags = Flag::INHERITED | Flag::FILE_INHERIT;
        let entry = AclEntry::allow_user("x", perms, flags);

        assert_eq!(
            format!("{}", entry),
            "allow:inherited,file_inherit:user:x:read,execute"
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    fn test_display_entry() {
        let perms = Perm::READ | Perm::EXECUTE;
        let flags = Flag::DEFAULT;

        let entry = AclEntry::allow_user("x", perms, flags);
        assert_eq!(format!("{}", entry), "allow:default:user:x:read,execute");
    }

    #[test]
    fn test_display_entry_name() {
        let perms = Perm::READ;

        // FIXME: Need to have colons in user names escaped on output!
        let entry = AclEntry::allow_user("x:y", perms, None);
        assert_eq!(format!("{}", entry), "allow::user:x:y:read");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_entry_fromstr() {
        let entry = "allow:inherited:user:x:read".parse::<AclEntry>().unwrap();
        assert_eq!(entry.to_string(), "allow:inherited:user:x:read");

        let entry = "allow::user:x:read".parse::<AclEntry>().unwrap();
        assert_eq!(entry.to_string(), "allow::user:x:read");

        let entry = "user:x:read".parse::<AclEntry>().unwrap();
        assert_eq!(entry.to_string(), "allow::user:x:read");

        let entry = " deny : inherited : user : x : read "
            .parse::<AclEntry>()
            .unwrap();
        assert_eq!(entry.to_string(), "deny:inherited:user:x:read");

        let entry = "inherited:user:x:read".parse::<AclEntry>().unwrap();
        assert_eq!(entry.to_string(), "allow:inherited:user:x:read");
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    fn test_entry_fromstr() {
        let entry = "allow:default:user:x:read".parse::<AclEntry>().unwrap();
        assert_eq!(entry.to_string(), "allow:default:user:x:read");

        let entry = "allow::user:x:read".parse::<AclEntry>().unwrap();
        assert_eq!(entry.to_string(), "allow::user:x:read");

        let entry = "user:x:read".parse::<AclEntry>().unwrap();
        assert_eq!(entry.to_string(), "allow::user:x:read");

        let entry = " deny : default : user : x : read "
            .parse::<AclEntry>()
            .unwrap();
        assert_eq!(entry.to_string(), "deny:default:user:x:read");

        let entry = "default:user:x:read".parse::<AclEntry>().unwrap();
        assert_eq!(entry.to_string(), "allow:default:user:x:read");
    }

    #[test]
    fn test_entry_fromstr_err() {
        // Mispelled "allow".
        let err = "all::user:x:read".parse::<AclEntry>().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Unknown variant `all`, expected one of `allow`, `deny`"
        );

        // Invalid format.
        let err = "allow:foo".parse::<AclEntry>().unwrap_err();
        assert_eq!(err.to_string(), "Unknown ACL format: `allow:foo`");
    }

    #[test]
    fn test_entry_fromstr_roundtrip() {
        let values = [
            ("user:a:read", "allow::user:a:read"),
            ("group:b:write", "allow::group:b:write"),
            ("unknown:c:execute", "allow::unknown:c:execute"),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            ("other:d:execute", "allow::other:d:execute"),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            ("mask:e:write,read", "allow::mask:e:read,write"),
        ];

        for (input, expected) in &values {
            let entry = input.parse::<AclEntry>().unwrap();
            assert_eq!(*expected, entry.to_string());
        }
    }

    #[test]
    fn test_entry_fromstr_examples() {
        let values = [
            ("u:admin:rwx", "allow::user:admin:read,write,execute"),
            ("g::rw", "allow::group::read,write"),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            ("default:user:admin:r", "allow:default:user:admin:read"),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            ("d:group:admin:w", "allow:default:group:admin:write"),
            ("deny::u:self:x", "deny::user:self:execute"),
        ];

        for (input, expected) in &values {
            let entry = input.parse::<AclEntry>().unwrap();
            assert_eq!(*expected, entry.to_string());
        }
    }
}
