//! Implements the inheritance flags.

use crate::bititer::{BitIter, BitIterable};
use crate::format;
use crate::sys::*;

use bitflags::bitflags;
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

bitflags! {
    /// Represents ACL entry inheritance flags.
    #[derive(Default)]
    pub struct Flag : acl_flag_t {
        /// ACL entry was inherited.
        #[cfg(any(docsrs, target_os = "macos", target_os = "freebsd"))]
        #[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "freebsd"))))]
        const INHERITED = np::ACL_ENTRY_INHERITED;

        /// Inherit to files.
        #[cfg(any(docsrs, target_os = "macos", target_os = "freebsd"))]
        #[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "freebsd"))))]
        const FILE_INHERIT = np::ACL_ENTRY_FILE_INHERIT;

        /// Inherit to directories.
        #[cfg(any(docsrs, target_os = "macos", target_os = "freebsd"))]
        #[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "freebsd"))))]
        const DIRECTORY_INHERIT = np::ACL_ENTRY_DIRECTORY_INHERIT;

        /// Clear the DIRECTORY_INHERIT flag in the ACL entry that is inherited.
        #[cfg(any(docsrs, target_os = "macos", target_os = "freebsd"))]
        #[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "freebsd"))))]
        const LIMIT_INHERIT = np::ACL_ENTRY_LIMIT_INHERIT;

        /// Don't consider this entry when processing the ACL. Just inherit it.
        #[cfg(any(docsrs, target_os = "macos", target_os = "freebsd"))]
        #[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "freebsd"))))]
        const ONLY_INHERIT = np::ACL_ENTRY_ONLY_INHERIT;

        /// Specifies a default ACL entry on Linux.
        #[cfg(any(docsrs, target_os = "linux", target_os = "freebsd"))]
        #[cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "freebsd"))))]
        const DEFAULT = 1 << 13;

        #[cfg(any(docsrs, target_os = "freebsd"))]
        #[cfg_attr(docsrs, doc(cfg(target_os = "freebsd")))]
        /// NFSv4 Specific Flags on FreeBSD.
        const NFS4_SPECIFIC = Self::INHERITED.bits | Self::FILE_INHERIT.bits | Self::DIRECTORY_INHERIT.bits | Self::LIMIT_INHERIT.bits | Self::ONLY_INHERIT.bits;
    }
}

// N.B. On FreeBSD, acl_flag_t is a u16. On Linux and macOS, acl_flag_t is a u32.

impl BitIterable for Flag {
    fn lsb(self) -> Option<Self> {
        if self.is_empty() {
            return None;
        }
        Some(Flag {
            bits: 1 << self.bits.trailing_zeros(),
        })
    }

    fn msb(self) -> Option<Self> {
        // FIXME: Replace computation with `BITS` once it lands in stable.
        #[allow(clippy::cast_possible_truncation)]
        const MAX_BITS: acl_flag_t = 8 * std::mem::size_of::<Flag>() as acl_flag_t - 1;

        if self.is_empty() {
            return None;
        }
        Some(Flag {
            bits: 1 << (MAX_BITS - self.bits.leading_zeros() as acl_flag_t),
        })
    }
}

#[derive(Deserialize, Serialize, Copy, Clone, Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
enum FlagName {
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    inherited = Flag::INHERITED.bits as u32,

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    file_inherit = Flag::FILE_INHERIT.bits as u32,

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    directory_inherit = Flag::DIRECTORY_INHERIT.bits as u32,

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    limit_inherit = Flag::LIMIT_INHERIT.bits as u32,

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    only_inherit = Flag::ONLY_INHERIT.bits as u32,

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    default = Flag::DEFAULT.bits as u32,
}

impl FlagName {
    fn from_flag(flag: Flag) -> Option<FlagName> {
        match flag {
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            Flag::INHERITED => Some(FlagName::inherited),

            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            Flag::FILE_INHERIT => Some(FlagName::file_inherit),

            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            Flag::DIRECTORY_INHERIT => Some(FlagName::directory_inherit),

            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            Flag::LIMIT_INHERIT => Some(FlagName::limit_inherit),

            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            Flag::ONLY_INHERIT => Some(FlagName::only_inherit),

            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Flag::DEFAULT => Some(FlagName::default),

            _ => None,
        }
    }

    const fn to_flag(self) -> Flag {
        Flag {
            bits: self as acl_flag_t,
        }
    }
}

impl fmt::Display for FlagName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        format::write_enum(f, self)
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = BitIter(*self & Flag::all());

        if let Some(flag) = iter.next() {
            write!(f, "{}", FlagName::from_flag(flag).unwrap())?;

            for flag in iter {
                write!(f, ",{}", FlagName::from_flag(flag).unwrap())?;
            }
        }

        Ok(())
    }
}

/// Parse an abbreviated flag ("d").
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn parse_flag_abbreviation(s: &str) -> Option<Flag> {
    match s {
        "d" => Some(Flag::DEFAULT),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
const fn parse_flag_abbreviation(_s: &str) -> Option<Flag> {
    None
}

impl std::str::FromStr for FlagName {
    type Err = format::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        format::read_enum(s)
    }
}

impl std::str::FromStr for Flag {
    type Err = format::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = Flag::empty();

        for item in s.split(',') {
            let word = item.trim();
            if !word.is_empty() {
                if let Some(flag) = parse_flag_abbreviation(word) {
                    result |= flag;
                } else {
                    result |= word.parse::<FlagName>()?.to_flag();
                }
            }
        }

        Ok(result)
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
                let mut flags: Flag = Flag::empty();

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

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod flag_tests {
    use super::*;

    #[test]
    fn test_flag_display() {
        assert_eq!(Flag::empty().to_string(), "");

        #[cfg(target_os = "macos")]
        {
            let flags = Flag::INHERITED | Flag::FILE_INHERIT;
            assert_eq!(flags.to_string(), "inherited,file_inherit");

            let bad_flag = Flag { bits: 0x0080_0000 } | Flag::INHERITED;
            assert_eq!(bad_flag.to_string(), "inherited");

            assert_eq!(
                Flag::all().to_string(),
                "inherited,file_inherit,directory_inherit,limit_inherit,only_inherit"
            );
        }

        #[cfg(target_os = "linux")]
        {
            let flags = Flag::DEFAULT;
            assert_eq!(flags.to_string(), "default");

            let bad_flag = Flag { bits: 0x8000 } | Flag::DEFAULT;
            assert_eq!(bad_flag.to_string(), "default");

            assert_eq!(Flag::all().to_string(), "default");
        }

        #[cfg(target_os = "freebsd")]
        {
            let flags = Flag::DEFAULT;
            assert_eq!(flags.to_string(), "default");

            let bad_flag = Flag { bits: 0x8000 } | Flag::DEFAULT;
            assert_eq!(bad_flag.to_string(), "default");

            assert_eq!(
                Flag::all().to_string(),
                "file_inherit,directory_inherit,limit_inherit,only_inherit,inherited,default"
            );
        }
    }

    #[test]
    fn test_flag_fromstr() {
        #[cfg(target_os = "macos")]
        {
            assert_eq!(Flag::empty(), "".parse::<Flag>().unwrap());

            let flags = Flag::INHERITED | Flag::FILE_INHERIT;
            assert_eq!(flags, "inherited,file_inherit".parse().unwrap());

            assert_eq!(
                Flag::all(),
                "inherited,file_inherit,directory_inherit,limit_inherit,only_inherit"
                    .parse()
                    .unwrap()
            );

            assert_eq!("unknown variant `bad_flag`, expected one of `inherited`, `file_inherit`, `directory_inherit`, `limit_inherit`, `only_inherit`", "bad_flag".parse::<Flag>().unwrap_err().to_string());
        }

        #[cfg(target_os = "linux")]
        {
            assert_eq!(Flag::empty(), "".parse::<Flag>().unwrap());

            assert_eq!(Flag::DEFAULT, "d".parse().unwrap());
            assert_eq!(Flag::all(), "default".parse().unwrap());

            assert_eq!(
                "unknown variant `bad_flag`, expected `default`",
                "bad_flag".parse::<Flag>().unwrap_err().to_string()
            );
        }

        #[cfg(target_os = "freebsd")]
        {
            assert_eq!(Flag::empty(), "".parse::<Flag>().unwrap());

            assert_eq!(Flag::DEFAULT, "d".parse().unwrap());
            assert_eq!(
                Flag::all(),
                "default,inherited,file_inherit,directory_inherit,limit_inherit,only_inherit"
                    .parse()
                    .unwrap()
            );

            assert_eq!(
                "unknown variant `bad_flag`, expected one of `inherited`, `file_inherit`, `directory_inherit`, `limit_inherit`, `only_inherit`, `default`",
                "bad_flag".parse::<Flag>().unwrap_err().to_string()
            );
        }
    }
}
