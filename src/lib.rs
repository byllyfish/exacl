//! Rust library to manipulate access control lists on MacOS.
//!
//! An Extended ACL specifies additional rules for file/directory access beyond
//! the file mode permission bits.
//!
//! You can read a file's ACL with the `read_acl` function. The ACL is
//! represented as Vec<AclEntry>. If the given path is a symlink, the symlink's
//! ACL is returned.
//!
//! ```no_run
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use exacl::Acl;
//! use std::path::Path;
//!
//! let path = Path::new("./foo/bar.txt");
//! let acl = Acl::read(&path)?;
//!
//! for entry in &acl.entries()? {
//!     println!("{:?}", entry);
//! }
//! #
//! #     Ok(())
//! # }
//! ```
//!

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

use scopeguard::{self, ScopeGuard};
use std::io;
use std::path::Path;
use util::*;

/// Access Control List native object wrapper.
pub struct Acl(acl_t);

impl Acl {
    /// Read ACL for specified file.
    pub fn read(path: &Path) -> io::Result<Acl> {
        let acl_p = xacl_get_file(path)?;
        Ok(Acl(acl_p))
    }

    /// Write ACL for specified file.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        xacl_set_file(path, self.0)
    }

    /// Construct ACL from AclEntry's.
    pub fn from_entries(entries: &[AclEntry]) -> io::Result<Acl> {
        // Use the smart pointer form of scopeguard; acl_p can change value.
        let new_acl = xacl_init(entries.len())?;
        let mut acl_p = scopeguard::guard(new_acl, |a| {
            xacl_free(a);
        });

        for (i, entry) in entries.iter().enumerate() {
            let entry_p = xacl_create_entry(&mut acl_p)?;
            if let Err(err) = entry.to_raw(entry_p) {
                return Err(custom_error(&format!("entry {}: {}", i, err)));
            }
        }

        Ok(Acl(ScopeGuard::into_inner(acl_p)))
    }

    /// Return ACL as a list of AclEntry's.
    pub fn entries(&self) -> io::Result<Vec<AclEntry>> {
        let mut entries = Vec::<AclEntry>::with_capacity(xacl_entry_count(self.0));

        xacl_foreach(self.0, |entry_p| {
            let entry = AclEntry::from_raw(entry_p)?;
            entries.push(entry);
            Ok(())
        })?;

        Ok(entries)
    }

    /// Construct ACL from platform-dependent textual description.
    pub fn from_platform_text(text: &str) -> io::Result<Acl> {
        let acl_p = xacl_from_text(text)?;
        Ok(Acl(acl_p))
    }

    /// Return platform-dependent textual description.
    pub fn to_platform_text(&self) -> String {
        xacl_to_text(self.0)
    }
}

impl Drop for Acl {
    fn drop(&mut self) {
        xacl_free(self.0);
    }
}
