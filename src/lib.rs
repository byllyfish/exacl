//! Rust library to manipulate access control lists.
//!
//! Supports `macOS` and `Linux`.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use exacl::{Acl, AclOption};
//!
//! let acl = Acl::read("./foo/bar.txt", AclOption::default())?;
//!
//! for entry in &acl.entries()? {
//!     println!("{:?}", entry);
//! }
//! # Ok(()) }
//! ```
//!

#![cfg_attr(docsrs, feature(doc_cfg))]

mod aclentry;
mod bititer;
mod flag;
mod perm;
mod sys;
mod util;

// Export AclEntry, AclEntryKind, Flag and Perm.
pub use aclentry::{AclEntry, AclEntryKind};
pub use flag::Flag;
pub use perm::Perm;

use bitflags::bitflags;
use scopeguard::{self, ScopeGuard};
use std::io;
use std::path::Path;
use util::*;

bitflags! {
    #[derive(Default)]
    pub struct AclOption : u32 {
        /// Get/set the ACL of the symlink itself.
        const SYMLINK_ONLY = 0x01;
    }
}

/// Access Control List native object wrapper.
pub struct Acl {
    acl: acl_t,
}

impl Acl {
    /// Specify the file owner (Linux).
    pub const OWNER: &'static str = OWNER_NAME;

    /// Specify other than file owner or group owner (Linux).
    pub const OTHER: &'static str = OTHER_NAME;

    /// Specify mask for user/group permissions (Linux).
    pub const MASK: &'static str = MASK_NAME;

    /// Read ACL for specified file.
    pub fn read<P: AsRef<Path>>(path: P, options: AclOption) -> io::Result<Acl> {
        let symlink_only = options.contains(AclOption::SYMLINK_ONLY);
        let acl_p = xacl_get_file(path.as_ref(), symlink_only)?;

        Ok(Acl { acl: acl_p })
    }

    /// Write ACL for specified file.
    pub fn write<P: AsRef<Path>>(&self, path: P, options: AclOption) -> io::Result<()> {
        let symlink_only = options.contains(AclOption::SYMLINK_ONLY);

        xacl_check(self.acl)?;
        xacl_set_file(path.as_ref(), self.acl, symlink_only)
    }

    /// Construct ACL from AclEntry's.
    pub fn from_entries(entries: &[AclEntry]) -> io::Result<Acl> {
        let new_acl = xacl_init(entries.len())?;

        // Use the smart pointer form of scopeguard; acl_p can change value.
        let mut acl_p = scopeguard::guard(new_acl, |a| {
            xacl_free(a);
        });

        for (i, entry) in entries.iter().enumerate() {
            let entry_p = xacl_create_entry(&mut acl_p)?;
            if let Err(err) = entry.to_raw(entry_p) {
                return Err(custom_error(&format!("entry {}: {}", i, err)));
            }
        }

        Ok(Acl {
            acl: ScopeGuard::into_inner(acl_p),
        })
    }

    /// Return ACL as a list of AclEntry's.
    pub fn entries(&self) -> io::Result<Vec<AclEntry>> {
        let mut entries = Vec::<AclEntry>::with_capacity(xacl_entry_count(self.acl));

        xacl_foreach(self.acl, |entry_p| {
            let entry = AclEntry::from_raw(entry_p)?;
            entries.push(entry);
            Ok(())
        })?;

        Ok(entries)
    }

    /// Construct ACL from platform-dependent textual description.
    pub fn from_platform_text(text: &str) -> io::Result<Acl> {
        let acl_p = xacl_from_text(text)?;
        Ok(Acl { acl: acl_p })
    }

    /// Return platform-dependent textual description.
    pub fn to_platform_text(&self) -> String {
        xacl_to_text(self.acl)
    }
}

impl Drop for Acl {
    fn drop(&mut self) {
        xacl_free(self.acl);
    }
}
