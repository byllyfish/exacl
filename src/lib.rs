//! Supports extended access control lists (ACL's) on MacOS.
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
//! use std::path::Path;
//!
//! let path = Path::new("./foo/bar.txt");
//! let acl = exacl::read_acl(&path)?;
//! for entry in &acl {
//!     println!("{:?}", entry);
//! }
//! #
//! #     Ok(())
//! # }
//! ```
//!
//! Once you have the ACL vector, you can modify it as you please. There are
//! no changes until you write the file's ACL with the `write_acl` function.
//! If path is a symlink, the symlink's ACL is written.
//!
//! ```ignore
//! use exacl::AclEntryKind::*;
//! use exacl::Perm::*;
//! use exacl::Flag::*;
//! let acl = vec![
//!     AclEntry::allow(User, "bfish", READ_DATA),
//!     AclEntry::deny(User, "bfish", WRITE_DATA).with_flags(ENTRY_FILE_INHERIT),
//!     AclEntry::allow(Group, "staff", READ_DATA | WRITE_DATA)
//! ];
//! exacl::write_acl(&path, &acl)?;
//! ```
//!
//! This example shows how to clear the inherited flag:
//!
//! ```ignore
//! use exacl::Flag;
//! let mut acl = xacl::read_acl(path)?;
//! for entry in &acl {
//!     entry.flags.clear(Flag::ENTRY_INHERITED);
//! }
//! exacl::write_acl(path, &acl)?;
//! ```
//!
//! Known Issue: The current API doesn't support reading/writing flags for the
//! ACL itself, which is possible using the `acl_get_flagset_np()` function.

mod aclentry;
mod bititer;
mod flag;
mod perm;
mod qualifier;
mod sys;
mod util;

// Export AclEntry, AclEntryKind, Flag and Perm.
pub use aclentry::{AclEntry, AclEntryKind};
pub use flag::Flag;
pub use perm::Perm;

use log::debug;
use scopeguard::defer;
use std::io;
use std::path::Path;
use util::*;

/// Represents an access control list.
pub type Acl = Vec<AclEntry>;

/// Read ACL for a specific file.
pub fn read_acl(path: &Path) -> io::Result<Acl> {
    let mut acl = Acl::new();

    let acl_p = xacl_get_file(path)?;
    defer! { xacl_free(acl_p) }

    xacl_foreach(acl_p, |entry_p| {
        let entry = AclEntry::from_raw(entry_p)?;
        acl.push(entry);
        Ok(())
    })?;

    debug!("Reading ACL from {:?}: {:?}", path, acl);

    Ok(acl)
}

/// Write ACL for a specific file.
pub fn write_acl(path: &Path, acl: &Acl) -> io::Result<()> {
    debug!("Writing ACL to {:?}: {:?}", path, acl);

    let new_acl = xacl_init(acl.len())?;

    // Use the smart pointer form of scopeguard; acl_p can change value.
    let mut acl_p = scopeguard::guard(new_acl, |a| {
        xacl_free(a);
    });

    for entry in acl {
        let entry_p = xacl_create_entry(&mut acl_p)?;
        entry.to_raw(entry_p)?;
    }

    xacl_set_file(path, *acl_p)?;
    Ok(())
}

/// Validate an ACL.
///
/// Returns an optional error message if there is something wrong.
pub fn validate_acl(acl: &Acl) -> Option<String> {
    for (i, entry) in acl.iter().enumerate() {
        if let Some(msg) = entry.validate() {
            return Some(format!("entry {}: {}", i, msg));
        }
    }

    None
}
