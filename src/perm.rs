//! Implements the permissions flags.

use crate::bititer::{BitIter, BitIterable};
use crate::sys::*;

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

bitflags! {
    /// Represents ACL entry file access permissions.
    #[derive(Default)]
    pub struct Perm : acl_perm_t {
        /// READ_DATA permission for a file.
        /// LIST_DIRECTORY permission for a directory.
        #[cfg(target_os = "macos")]
        const READ = acl_perm_t_ACL_READ_DATA;

        /// WRITE_DATA permission for a file.
        /// ADD_FILE permission for a directory.
        #[cfg(target_os = "macos")]
        const WRITE = acl_perm_t_ACL_WRITE_DATA;

        /// EXECUTE permission for a file.
        /// SEARCH permission for a directory.
        #[cfg(target_os = "macos")]
        const EXECUTE = acl_perm_t_ACL_EXECUTE;

        /// DELETE permission for a file.
        #[cfg(target_os = "macos")]
        const DELETE = acl_perm_t_ACL_DELETE;

        /// APPEND_DATA permission for a file.
        /// ADD_SUBDIRECTORY permission for a directory.
        #[cfg(target_os = "macos")]
        const APPEND = acl_perm_t_ACL_APPEND_DATA;

        /// DELETE_CHILD permission for a directory.
        #[cfg(target_os = "macos")]
        const DELETE_CHILD = acl_perm_t_ACL_DELETE_CHILD;

        /// READ_ATTRIBUTES permission for file or directory.
        #[cfg(target_os = "macos")]
        const READ_ATTRIBUTES = acl_perm_t_ACL_READ_ATTRIBUTES;

        /// WRITE_ATTRIBUTES permission for a file or directory.
        #[cfg(target_os = "macos")]
        const WRITE_ATTRIBUTES = acl_perm_t_ACL_WRITE_ATTRIBUTES;

        /// READ_EXTATTRIBUTES permission for a file or directory.
        #[cfg(target_os = "macos")]
        const READ_EXTATTRIBUTES = acl_perm_t_ACL_READ_EXTATTRIBUTES;

        /// WRITE_EXTATTRIBUTES permission for a file or directory.
        #[cfg(target_os = "macos")]
        const WRITE_EXTATTRIBUTES = acl_perm_t_ACL_WRITE_EXTATTRIBUTES;

        /// READ_SECURITY permission for a file or directory.
        #[cfg(target_os = "macos")]
        const READ_SECURITY = acl_perm_t_ACL_READ_SECURITY;

        /// WRITE_SECURITY permission for a file or directory.
        #[cfg(target_os = "macos")]
        const WRITE_SECURITY = acl_perm_t_ACL_WRITE_SECURITY;

        /// CHANGE_OWNER permission for a file or directory.
        #[cfg(target_os = "macos")]
        const CHANGE_OWNER = acl_perm_t_ACL_CHANGE_OWNER;

        /// SYNCHRONIZE permission (unsupported).
        #[cfg(target_os = "macos")]
        const SYNCHRONIZE = acl_perm_t_ACL_SYNCHRONIZE;
    }
}

impl BitIterable for Perm {
    #[inline]
    fn overflowing_neg(&self) -> (Self, bool) {
        let (bits, overflow) = <acl_perm_t>::overflowing_neg(self.bits);
        (Perm { bits }, overflow)
    }
}

#[derive(Deserialize, Serialize, TryFromPrimitive, Copy, Clone, Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
enum PermName {
    read = acl_perm_t_ACL_READ_DATA,
    write = acl_perm_t_ACL_WRITE_DATA,
    execute = acl_perm_t_ACL_EXECUTE,
    delete = acl_perm_t_ACL_DELETE,
    append = acl_perm_t_ACL_APPEND_DATA,
    delete_child = acl_perm_t_ACL_DELETE_CHILD,
    readattr = acl_perm_t_ACL_READ_ATTRIBUTES,
    writeattr = acl_perm_t_ACL_WRITE_ATTRIBUTES,
    readextattr = acl_perm_t_ACL_READ_EXTATTRIBUTES,
    writeextattr = acl_perm_t_ACL_WRITE_EXTATTRIBUTES,
    readsecurity = acl_perm_t_ACL_READ_SECURITY,
    writesecurity = acl_perm_t_ACL_WRITE_SECURITY,
    chown = acl_perm_t_ACL_CHANGE_OWNER,
    sync = acl_perm_t_ACL_SYNCHRONIZE,
}

impl PermName {
    fn from_perm(perm: Perm) -> Option<PermName> {
        use std::convert::TryFrom;
        PermName::try_from(perm.bits).ok()
    }

    fn to_perm(&self) -> Perm {
        Perm { bits: *self as u32 }
    }
}

impl ser::Serialize for Perm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;

        for perm in BitIter(*self) {
            seq.serialize_element(&PermName::from_perm(perm))?;
        }

        seq.end()
    }
}

impl<'de> de::Deserialize<'de> for Perm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct PermVisitor;

        impl<'de> de::Visitor<'de> for PermVisitor {
            type Value = Perm;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("list of permissions")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut perms: Perm = Default::default();

                while let Some(value) = seq.next_element()? {
                    let name: PermName = value;
                    perms |= name.to_perm();
                }

                Ok(perms)
            }
        }

        deserializer.deserialize_seq(PermVisitor)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod perm_tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_perm_equivalences() {
        assert_eq!(acl_perm_t_ACL_READ_DATA, acl_perm_t_ACL_LIST_DIRECTORY);
        assert_eq!(acl_perm_t_ACL_WRITE_DATA, acl_perm_t_ACL_ADD_FILE);
        assert_eq!(acl_perm_t_ACL_EXECUTE, acl_perm_t_ACL_SEARCH);
        assert_eq!(acl_perm_t_ACL_APPEND_DATA, acl_perm_t_ACL_ADD_SUBDIRECTORY);
    }
}
