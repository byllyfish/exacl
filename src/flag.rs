//! Implements the inheritance flags.

use crate::bititer::{BitIter, BitIterable};
use crate::sys::*;

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

bitflags! {
    /// Represents ACL inheritance flags.
    #[derive(Default)]
    pub struct Flag : acl_flag_t {
        /// ACL Flag.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const DEFER_INHERIT = np::ACL_FLAG_DEFER_INHERIT;

        /// ACL Flag.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const NO_INHERIT = np::ACL_FLAG_NO_INHERIT;

        /// ACL entry was inherited.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const INHERITED = np::ACL_ENTRY_INHERITED;

        /// Inherit to files.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const FILE_INHERIT = np::ACL_ENTRY_FILE_INHERIT;

        /// Inherit to directories.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const DIRECTORY_INHERIT = np::ACL_ENTRY_DIRECTORY_INHERIT;

        /// Clear the DIRECTORY_INHERIT flag in the ACL entry that is inherited.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const LIMIT_INHERIT = np::ACL_ENTRY_LIMIT_INHERIT;

        /// Don't consider this entry when processing the ACL. Just inherit it.
        #[cfg(any(docsrs, target_os = "macos"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
        const ONLY_INHERIT = np::ACL_ENTRY_ONLY_INHERIT;

        /// Linux ACL's don't use flags.
        #[cfg(any(docsrs, target_os = "linux"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
        const DEFAULT = 0;
    }
}

impl BitIterable for Flag {
    #[inline]
    fn overflowing_neg(&self) -> (Self, bool) {
        let (bits, overflow) = <acl_flag_t>::overflowing_neg(self.bits);
        (Flag { bits }, overflow)
    }
}

#[derive(Deserialize, Serialize, TryFromPrimitive, Copy, Clone, Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
enum FlagName {
    #[cfg(target_os = "macos")]
    defer_inherit = Flag::DEFER_INHERIT.bits,

    #[cfg(target_os = "macos")]
    no_inherit = Flag::NO_INHERIT.bits,

    #[cfg(target_os = "macos")]
    inherited = Flag::INHERITED.bits,

    #[cfg(target_os = "macos")]
    file_inherit = Flag::FILE_INHERIT.bits,

    #[cfg(target_os = "macos")]
    directory_inherit = Flag::DIRECTORY_INHERIT.bits,

    #[cfg(target_os = "macos")]
    limit_inherit = Flag::LIMIT_INHERIT.bits,

    #[cfg(target_os = "macos")]
    only_inherit = Flag::ONLY_INHERIT.bits,

    #[cfg(target_os = "linux")]
    default = Flag::DEFAULT.bits,
}

impl FlagName {
    fn from_flag(flag: Flag) -> Option<FlagName> {
        use std::convert::TryFrom;
        FlagName::try_from(flag.bits).ok()
    }

    fn to_flag(self) -> Flag {
        Flag { bits: self as u32 }
    }
}

impl ser::Serialize for Flag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;

        for flag in BitIter(*self) {
            seq.serialize_element(&FlagName::from_flag(flag))?;
        }

        seq.end()
    }
}

impl<'de> de::Deserialize<'de> for Flag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct FlagVisitor;

        impl<'de> de::Visitor<'de> for FlagVisitor {
            type Value = Flag;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("list of flags")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut flags: Flag = Default::default();

                while let Some(value) = seq.next_element()? {
                    let name: FlagName = value;
                    flags |= name.to_flag();
                }

                Ok(flags)
            }
        }

        deserializer.deserialize_seq(FlagVisitor)
    }
}
