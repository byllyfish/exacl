//! Implements the permissions flags.

use crate::bititer::{BitIter, BitIterable};
use crate::format;
use crate::sys::*;

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

bitflags! {
    /// Represents file access permissions.
    #[derive(Default)]
    pub struct Perm : acl_perm_t {
        /// READ_DATA permission for a file.
        /// Same as LIST_DIRECTORY permission for a directory.
        const READ = ACL_READ;

        /// WRITE_DATA permission for a file.
        /// Same as ADD_FILE permission for a directory.
        const WRITE = ACL_WRITE;

        /// EXECUTE permission for a file.
        /// Same as SEARCH permission for a directory.
        const EXECUTE = ACL_EXECUTE;

        /// DELETE permission for a file.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const DELETE = np::ACL_DELETE;

        /// APPEND_DATA permission for a file.
        /// Same as ADD_SUBDIRECTORY permission for a directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const APPEND = np::ACL_APPEND_DATA;

        /// DELETE_CHILD permission for a directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const DELETE_CHILD = np::ACL_DELETE_CHILD;

        /// READ_ATTRIBUTES permission for file or directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const READATTR = np::ACL_READ_ATTRIBUTES;

        /// WRITE_ATTRIBUTES permission for a file or directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const WRITEATTR = np::ACL_WRITE_ATTRIBUTES;

        /// READ_EXTATTRIBUTES permission for a file or directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const READEXTATTR = np::ACL_READ_EXTATTRIBUTES;

        /// WRITE_EXTATTRIBUTES permission for a file or directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const WRITEEXTATTR = np::ACL_WRITE_EXTATTRIBUTES;

        /// READ_SECURITY permission for a file or directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const READSECURITY = np::ACL_READ_SECURITY;

        /// WRITE_SECURITY permission for a file or directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const WRITESECURITY = np::ACL_WRITE_SECURITY;

        /// CHANGE_OWNER permission for a file or directory.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const CHOWN = np::ACL_CHANGE_OWNER;

        /// SYNCHRONIZE permission (unsupported).
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const SYNC = np::ACL_SYNCHRONIZE;
    }
}

impl BitIterable for Perm {
    fn lsb(self) -> Option<Self> {
        if self.is_empty() {
            return None;
        }
        Some(Perm {
            bits: 1 << self.bits.trailing_zeros(),
        })
    }

    fn msb(self) -> Option<Self> {
        #[allow(clippy::cast_possible_truncation)]
        const MAX_BITS: acl_perm_t = 8 * std::mem::size_of::<Perm>() as acl_perm_t - 1;

        if self.is_empty() {
            return None;
        }
        Some(Perm {
            bits: 1 << (MAX_BITS - self.bits.leading_zeros()),
        })
    }
}

#[derive(Deserialize, Serialize, TryFromPrimitive, Copy, Clone, Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
enum PermName {
    read = Perm::READ.bits,

    write = Perm::WRITE.bits,

    execute = Perm::EXECUTE.bits,

    #[cfg(target_os = "macos")]
    delete = Perm::DELETE.bits,

    #[cfg(target_os = "macos")]
    append = Perm::APPEND.bits,

    #[cfg(target_os = "macos")]
    delete_child = Perm::DELETE_CHILD.bits,

    #[cfg(target_os = "macos")]
    readattr = Perm::READATTR.bits,

    #[cfg(target_os = "macos")]
    writeattr = Perm::WRITEATTR.bits,

    #[cfg(target_os = "macos")]
    readextattr = Perm::READEXTATTR.bits,

    #[cfg(target_os = "macos")]
    writeextattr = Perm::WRITEEXTATTR.bits,

    #[cfg(target_os = "macos")]
    readsecurity = Perm::READSECURITY.bits,

    #[cfg(target_os = "macos")]
    writesecurity = Perm::WRITESECURITY.bits,

    #[cfg(target_os = "macos")]
    chown = Perm::CHOWN.bits,

    #[cfg(target_os = "macos")]
    sync = Perm::SYNC.bits,
}

impl PermName {
    fn from_perm(perm: Perm) -> Option<PermName> {
        use std::convert::TryFrom;
        PermName::try_from(perm.bits).ok()
    }

    const fn to_perm(self) -> Perm {
        Perm { bits: self as u32 }
    }
}

impl fmt::Display for PermName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format::to_string(self).unwrap())
    }
}

impl fmt::Display for Perm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Iterate forwards on macOS and backwards elsewhere. Only iterate over
        // valid bits.
        #[cfg(target_os = "macos")]
        let mut iter = BitIter(*self & Perm::all());
        #[cfg(not(target_os = "macos"))]
        let mut iter = BitIter(*self & Perm::all()).rev();

        if let Some(perm) = iter.next() {
            write!(f, "{}", PermName::from_perm(perm).unwrap())?;

            for perm in iter {
                write!(f, ",{}", PermName::from_perm(perm).unwrap())?;
            }
        }

        Ok(())
    }
}

impl ser::Serialize for Perm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;

        // Iterate forwards on macOS and backwards elsewhere.
        #[cfg(target_os = "macos")]
        let iter = BitIter(*self);
        #[cfg(not(target_os = "macos"))]
        let iter = BitIter(*self).rev();

        for perm in iter {
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
                let mut perms: Perm = Perm::empty();

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

    #[test]
    fn test_perm_display() {
        assert_eq!(Perm::empty().to_string(), "");

        let perms = Perm::READ | Perm::EXECUTE;
        assert_eq!(perms.to_string(), "read,execute");

        let bad_perm = Perm { bits: 0x0080_0000 } | Perm::READ;
        assert_eq!(bad_perm.to_string(), "read");

        #[cfg(target_os = "macos")]
        assert_eq!(Perm::all().to_string(), "read,write,execute,delete,append,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,writesecurity,chown,sync");

        #[cfg(target_os = "linux")]
        assert_eq!(Perm::all().to_string(), "read,write,execute");
    }
}
