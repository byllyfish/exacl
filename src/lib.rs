//! # exacl
//!
//! Rust library to manipulate access control lists on `macOS` and `Linux`.
//!
//! ## Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use exacl::{getfacl, setfacl, AclEntry, Perm};
//!
//! // Get the ACL from "./tmp/foo".
//! let mut acl = getfacl("./tmp/foo", None)?;
//!
//! // Print the contents of the ACL.
//! for entry in &acl {
//!     println!("{:?}", entry);
//! }
//!
//! // Add an ACL entry to the end.
//! acl.push(AclEntry::allow_user("some_user", Perm::READ, None));
//!
//! // Sort the ACL in canonical order.
//! acl.sort();
//!
//! // Set the ACL for "./tmp/foo".
//! setfacl("./tmp/foo", &acl, None)?;
//!
//! # Ok(()) }
//! ```
//!
//! ## High Level API
//!
//! This module provides two high level functions, [getfacl] and [setfacl].
//!
//! - [getfacl] retrieves the ACL for a file or directory. On Linux, the
//!     result includes the entries from the default ACL if there is one.
//! - [setfacl] sets the ACL for a file or directory, including the default
//!     ACL on Linux.
//!
//! Both [getfacl] and [setfacl] work with a vector of [`AclEntry`] structures.
//! The structure contains five fields:
//!
//! - kind : [`AclEntryKind`] - the kind of entry (User, Group, Unknown).
//! - name : [`String`] - name of the principal being given access. You can
//!     use a user/group name, decimal uid/gid, or UUID (on macOS). On Linux,
//!     use the special constants OWNER, OTHER, and MASK.
//! - perms : [`Perm`] - permission bits for the entry.
//! - flags : [`Flag`] - flags indicating whether an entry is inherited, etc.
//! - allow : [`bool`] - true if entry is allowed; false means deny. Linux only
//!     supports allow=true.
//!
//! [`AclEntry`] supports an ordering that corresponds to ACL canonical order. An
//! ACL in canonical order has deny entries first, and inherited entries last.
//! On Linux, entries for file-owner sort before named users. You can sort a
//! vector of `AclEntry` to put the ACL in canonical order.
//!
//! ## Low Level API
//!
//! The low level API is appropriate if you need finer grained control over
//! the ACL.
//!
//! - Manipulate the access ACL and default ACL independently on Linux.
//! - Manipulate the ACL's own flags on macOS.
//! - Use the platform specific text formats.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod aclentry;
mod bititer;
mod failx;
mod flag;
mod perm;
mod sys;
mod util;

// Export AclEntry, AclEntryKind, Flag and Perm.
pub use aclentry::{AclEntry, AclEntryKind};
pub use flag::Flag;
pub use perm::Perm;

use bitflags::bitflags;
use failx::fail_custom;
use scopeguard::{self, ScopeGuard};
use std::io;
use std::path::Path;
use util::*;

bitflags! {
    /// Controls how ACL's are accessed.
    #[derive(Default)]
    pub struct AclOption : u32 {
        /// Get/set the ACL of the symlink itself (macOS only).
        const SYMLINK_ACL = 0x01;

        /// Get/set the default ACL (Linux only).
        const DEFAULT_ACL = 0x02;
    }
}

/// Access Control List native object wrapper.
pub struct Acl {
    /// Native acl.
    acl: acl_t,

    /// Set to true if `acl` was set from the default ACL for a directory
    /// using DEFAULT_ACL option. Used to return entries with the `DEFAULT`
    /// flag set.
    #[cfg(target_os = "linux")]
    default_acl: bool,
}

impl Acl {
    /// Specify the file owner (Linux).
    pub const OWNER: &'static str = OWNER_NAME;

    /// Specify other than file owner or group owner (Linux).
    pub const OTHER: &'static str = OTHER_NAME;

    /// Specify mask for user/group permissions (Linux).
    pub const MASK: &'static str = MASK_NAME;

    /// Read ACL for specified file.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn read<P: AsRef<Path>>(path: P, options: AclOption) -> io::Result<Acl> {
        let symlink_acl = options.contains(AclOption::SYMLINK_ACL);
        let default_acl = options.contains(AclOption::DEFAULT_ACL);

        let acl_p = xacl_get_file(path.as_ref(), symlink_acl, default_acl)?;

        Ok(Acl {
            acl: acl_p,
            #[cfg(target_os = "linux")]
            default_acl,
        })
    }

    /// Write ACL for specified file.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.  
    pub fn write<P: AsRef<Path>>(&self, path: P, options: AclOption) -> io::Result<()> {
        let symlink_acl = options.contains(AclOption::SYMLINK_ACL);
        let default_acl = options.contains(AclOption::DEFAULT_ACL);

        // Don't check ACL if it's an empty, default ACL.
        if !default_acl || !self.is_empty() {
            xacl_check(self.acl)?;
        }

        xacl_set_file(path.as_ref(), self.acl, symlink_acl, default_acl)
    }

    /// Construct ACL from slice of [`AclEntry`].
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn from_entries(entries: &[AclEntry]) -> io::Result<Acl> {
        let new_acl = xacl_init(entries.len())?;

        // Use the smart pointer form of scopeguard; acl_p can change value.
        let mut acl_p = scopeguard::guard(new_acl, |a| {
            xacl_free(a);
        });

        for (i, entry) in entries.iter().enumerate() {
            let entry_p = xacl_create_entry(&mut acl_p)?;
            if let Err(err) = entry.to_raw(entry_p) {
                return fail_custom(&format!("entry {}: {}", i, err));
            }
        }

        Ok(Acl {
            acl: ScopeGuard::into_inner(acl_p),
            #[cfg(target_os = "linux")]
            default_acl: false,
        })
    }

    /// Return ACL as a vector of [`AclEntry`].
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn entries(&self) -> io::Result<Vec<AclEntry>> {
        let mut entries = Vec::<AclEntry>::with_capacity(xacl_entry_count(self.acl));

        xacl_foreach(self.acl, |entry_p| {
            let entry = AclEntry::from_raw(entry_p)?;
            entries.push(entry);
            Ok(())
        })?;

        #[cfg(target_os = "linux")]
        if self.default_acl {
            // Set DEFAULT flag on each entry.
            for entry in &mut entries {
                entry.flags |= Flag::DEFAULT;
            }
        }

        Ok(entries)
    }

    /// Construct ACL from platform-dependent textual description.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn from_platform_text(text: &str) -> io::Result<Acl> {
        let acl_p = xacl_from_text(text)?;
        Ok(Acl {
            acl: acl_p,
            #[cfg(target_os = "linux")]
            default_acl: false,
        })
    }

    /// Return platform-dependent textual description.
    #[must_use]
    pub fn to_platform_text(&self) -> String {
        xacl_to_text(self.acl)
    }

    /// Return true if ACL is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        xacl_entry_count(self.acl) == 0
    }
}

impl Drop for Acl {
    fn drop(&mut self) {
        xacl_free(self.acl);
    }
}

/// Get access control list (ACL) for a file or directory.
///
/// On success, returns a vector of [`AclEntry`] with all access control entries
/// for the specified path. The semantics and permissions of the access control
/// list depend on the underlying platform.
///
/// # macOS
///
/// The ACL only includes the extended entries beyond the normal permssion mode
/// of the file. macOS provides several ACL entry flags to specify how entries
/// may be inherited by directory sub-items. If there's no extended ACL for a
/// file, this function may return zero entries.
///
/// If `path` points to a symlink, `getfacl` returns the ACL of the file pointed
/// to by the symlink. Use [`AclOption::SYMLINK_ACL`] to obtain the ACL of a symlink
/// itself.
///
/// [`AclOption::DEFAULT_ACL`] option is not supported on macOS.
///
/// # Linux
///
/// The ACL includes entries related to the permission mode of the file. These
/// are marked with names such as "@owner", "@other", and "@mask".
///
/// Both the access ACL and the default ACL are returned in one list, with
/// the default ACL entries indicated by a [`Flag::DEFAULT`] flag.
///
/// If `path` points to a symlink, `getfacl` returns the ACL of the file pointed
/// to by the symlink. [`AclOption::SYMLINK_ACL`] is not supported on Linux.
///
/// [`AclOption::DEFAULT_ACL`] causes `getfacl` to only include entries for the
/// default ACL, if present for a directory path. When called with
/// [`AclOption::DEFAULT_ACL`], `getfacl` may return zero entries.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use exacl::getfacl;
///
/// let entries = getfacl("./tmp/foo", None)?;
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// Returns an [`io::Error`] on failure.

pub fn getfacl<P, O>(_path: P, _options: O) -> io::Result<Vec<AclEntry>>
where
    P: AsRef<Path>,
    O: Into<Option<AclOption>>,
{
    Err(io::Error::from_raw_os_error(1))
}

/// Set access control list (ACL) for a file or directory.
///
/// Sets the ACL for the specified path using the given access control entries.
/// The semantics and permissions of the access control list depend on the
/// underlying platform.
///
/// # macOS
///
/// The ACL contains extended entries beyond the usual mode permission bits.
/// An entry may allow or deny access to a specific user or group.
/// To specify inherited entries, use the provided [Flag] values.
///
/// ### macOS Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use exacl::{setfacl, AclEntry, Flag, Perm};
///
/// let entries = vec![
///     AclEntry::allow_user("some_user", Perm::READ | Perm::WRITE, None),
///     AclEntry::deny_group("some_group", Perm::WRITE, None)
/// ];
///
/// setfacl("./tmp/foo", &entries, None)?;
/// # Ok(()) }
/// ```
///
/// # Linux
///
/// Each entry can only allow access; denying access using allow=false is not
/// supported on Linux.
///
/// The ACL *must* contain entries for the permssion modes of the file. Use
/// the "@owner" and "@other" name constants to specify the mode's
/// owner, group and other permissions.
///
/// If an ACL contains a named user or group, there should be a "@mask" entry
/// included. If a "@mask" entry is not provided, one will be computed and
/// appended.
///
/// The access control entries may include entries for the default ACL, if one
/// is desired. When `setfacl` is called with no [`Flag::DEFAULT`] entries, it
/// deletes the default ACL.
///
/// ### Linux Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use exacl::{setfacl, Acl, AclEntry, Flag, Perm};
///
/// let entries = vec![
///     AclEntry::allow_user(Acl::OWNER, Perm::READ | Perm::WRITE, None),
///     AclEntry::allow_group(Acl::OWNER, Perm::READ, None),
///     AclEntry::allow_group(Acl::OTHER, Perm::empty(), None),
///     AclEntry::allow_user("some_user", Perm::READ | Perm::WRITE, None),
///     AclEntry::allow_group(Acl::MASK, Perm::READ | Perm::WRITE, None),
/// ];
///
/// setfacl("./tmp/foo", &entries, None)?;
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// Returns an [`io::Error`] on failure.

pub fn setfacl<P, O>(_path: P, _entries: &[AclEntry], _options: O) -> io::Result<()>
where
    P: AsRef<Path>,
    O: Into<Option<AclOption>>,
{
    Err(io::Error::from_raw_os_error(1))
}
