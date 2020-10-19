//! Implements the permissions flags.

use crate::bititer::{BitIter, BitIterable};
use crate::sys::*;

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde;
use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use std::fmt;

bitflags! {
    /// Represents ACL entry file access permissions.
    #[derive(Default)]
    pub struct Perm : acl_perm_t {
        /// Read permission for a file (read).
        /// Same bit as LIST_DIRECTORY.
        const READ_DATA = acl_perm_t_ACL_READ_DATA;

        /// Read permission for a directory to list its contents (list).
        /// Same bit as READ_DATA.
        const LIST_DIRECTORY = acl_perm_t_ACL_LIST_DIRECTORY;

        /// Write permission for a file (write).
        /// Same bit as ADD_FILE.
        const WRITE_DATA = acl_perm_t_ACL_WRITE_DATA;

        /// Add file permission for a directory (add_file).
        /// Same bit as WRITE_DATA.
        const ADD_FILE = acl_perm_t_ACL_ADD_FILE;

        /// Execute permission for a file (execute).
        /// Same bit as SEARCH.
        const EXECUTE = acl_perm_t_ACL_EXECUTE;

        /// Search permission for a directory (search).
        /// Same bit as EXECUTE.
        const SEARCH = acl_perm_t_ACL_SEARCH;

        /// Delete permission for a file (delete).
        const DELETE = acl_perm_t_ACL_DELETE;

        /// Append permission for a file (append).
        /// Same bit as ADD_SUBDIRECTORY.
        const APPEND_DATA = acl_perm_t_ACL_APPEND_DATA;

        /// Add subdirectory permission for a directory.
        /// Same bit as APPEND_DATA.
        const ADD_SUBDIRECTORY = acl_perm_t_ACL_ADD_SUBDIRECTORY;

        const DELETE_CHILD = acl_perm_t_ACL_DELETE_CHILD;
        const READ_ATTRIBUTES = acl_perm_t_ACL_READ_ATTRIBUTES;
        const WRITE_ATTRIBUTES = acl_perm_t_ACL_WRITE_ATTRIBUTES;
        const READ_EXTATTRIBUTES = acl_perm_t_ACL_READ_EXTATTRIBUTES;
        const WRITE_EXTATTRIBUTES = acl_perm_t_ACL_WRITE_EXTATTRIBUTES;
        const READ_SECURITY = acl_perm_t_ACL_READ_SECURITY;
        const WRITE_SECURITY = acl_perm_t_ACL_WRITE_SECURITY;
        const CHANGE_OWNER = acl_perm_t_ACL_CHANGE_OWNER;
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

#[derive(serde::Deserialize, serde::Serialize, TryFromPrimitive, Copy, Clone, Debug)]
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

impl Serialize for Perm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;

        for perm in BitIter(*self) {
            seq.serialize_element(&PermName::from_perm(perm))?;
        }

        seq.end()
    }
}

impl<'de> Deserialize<'de> for Perm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PermVisitor;

        impl<'de> Visitor<'de> for PermVisitor {
            type Value = Perm;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("permission values")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
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

#[test]
fn test_perm_equivalences() {
    assert_eq!(Perm::READ_DATA, Perm::LIST_DIRECTORY);
    assert_eq!(Perm::WRITE_DATA, Perm::ADD_FILE);
    assert_eq!(Perm::EXECUTE, Perm::SEARCH);
    assert_eq!(Perm::APPEND_DATA, Perm::ADD_SUBDIRECTORY);
}
