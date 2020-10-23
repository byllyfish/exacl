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
        const FLAG_DEFER_INHERIT = acl_flag_t_ACL_FLAG_DEFER_INHERIT;
        const FLAG_NO_INHERIT = acl_flag_t_ACL_FLAG_NO_INHERIT;
        const ENTRY_INHERITED = acl_flag_t_ACL_ENTRY_INHERITED;
        const ENTRY_FILE_INHERIT = acl_flag_t_ACL_ENTRY_FILE_INHERIT;
        const ENTRY_DIRECTORY_INHERIT = acl_flag_t_ACL_ENTRY_DIRECTORY_INHERIT;
        const ENTRY_LIMIT_INHERIT = acl_flag_t_ACL_ENTRY_LIMIT_INHERIT;
        const ENTRY_ONLY_INHERIT = acl_flag_t_ACL_ENTRY_ONLY_INHERIT;
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
    defer_inherit = Flag::FLAG_DEFER_INHERIT.bits,
    no_inherit = Flag::FLAG_NO_INHERIT.bits,
    inherited = Flag::ENTRY_INHERITED.bits,
    file_inherit = Flag::ENTRY_FILE_INHERIT.bits,
    directory_inherit = Flag::ENTRY_DIRECTORY_INHERIT.bits,
    limit_inherit = Flag::ENTRY_LIMIT_INHERIT.bits,
    only_inherit = Flag::ENTRY_ONLY_INHERIT.bits,
}

impl FlagName {
    fn from_flag(flag: Flag) -> Option<FlagName> {
        use std::convert::TryFrom;
        FlagName::try_from(flag.bits).ok()
    }

    fn to_flag(&self) -> Flag {
        Flag { bits: *self as u32 }
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
