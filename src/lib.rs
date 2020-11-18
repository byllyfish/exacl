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
//! setfacl(&["./tmp/foo"], &acl, None)?;
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
//! - [setfacl] sets the ACL for files or directories, including the default
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

mod acl;
mod aclentry;
mod bititer;
mod failx;
mod flag;
mod perm;
mod sys;
mod util;

// Export Acl, AclOption, AclEntry, AclEntryKind, Flag and Perm.
pub use acl::{Acl, AclOption};
pub use aclentry::{AclEntry, AclEntryKind};
pub use flag::Flag;
pub use perm::Perm;

use failx::custom_err;
use std::io;
use std::path::Path;

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

pub fn getfacl<P, O>(path: P, options: O) -> io::Result<Vec<AclEntry>>
where
    P: AsRef<Path>,
    O: Into<Option<AclOption>>,
{
    let options = options.into().unwrap_or_default();

    if options.contains(AclOption::DEFAULT_ACL) {
        // Return default ACL only. If `path` is a file, this will return a
        // PermissionDenied error.
        let acl = Acl::read(path, options)?;
        return Ok(acl.entries()?);
    }

    if cfg!(target_os = "macos") {
        // On macOS, there is only one ACL to read.
        let entries = Acl::read(&path, options)?.entries()?;
        Ok(entries)
    } else {
        // On Linux read the access ACL first, then try to read the default ACL.
        let mut entries = Acl::read(&path, options)?.entries()?;

        match Acl::read(&path, options | AclOption::DEFAULT_ACL) {
            Ok(default_acl) => {
                let mut default_entries = default_acl.entries()?;
                entries.append(&mut default_entries);
            }
            Err(err) => {
                // Accessing the default ACL on a file will result in a
                // PermissionDenied error, which we ignore.
                if err.kind() != io::ErrorKind::PermissionDenied {
                    return Err(err);
                }
            }
        }

        Ok(entries)
    }
}

/// Set access control list (ACL) for specified files and directories.
///
/// Sets the ACL for the specified paths using the given access control entries.
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
/// setfacl(&["./tmp/foo"], &entries, None)?;
/// # Ok(()) }
/// ```
///
/// # Linux
///
/// Each entry can only allow access; denying access using allow=false is not
/// supported on Linux.
///
/// The ACL *must* contain entries for the permssion modes of the file. Use
/// the [`OWNER`] and [`OTHER`] name constants to specify the mode's
/// owner, group and other permissions.
///
/// If an ACL contains a named user or group, there should be a [`MASK`] entry
/// included. If a [`MASK`] entry is not provided, one will be computed and
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
/// use exacl::{setfacl, AclEntry, Flag, Perm, OWNER, OTHER, MASK};
///
/// let entries = vec![
///     AclEntry::allow_user(OWNER, Perm::READ | Perm::WRITE, None),
///     AclEntry::allow_group(OWNER, Perm::READ, None),
///     AclEntry::allow_group(OTHER, Perm::empty(), None),
///     AclEntry::allow_user("some_user", Perm::READ | Perm::WRITE, None),
///     AclEntry::allow_group(MASK, Perm::READ | Perm::WRITE, None),
/// ];
///
/// setfacl(&["./tmp/foo"], &entries, None)?;
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// Returns an [`io::Error`] on failure.

pub fn setfacl<P, O>(paths: &[P], entries: &[AclEntry], options: O) -> io::Result<()>
where
    P: AsRef<Path>,
    O: Into<Option<AclOption>>,
{
    let options = options.into().unwrap_or_default();

    #[cfg(target_os = "macos")]
    {
        let acl = Acl::from_entries(entries).map_err(|err| custom_err("Invalid ACL", &err))?;

        for path in paths {
            acl.write(path, options)?;
        }
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, split into two vectors: access and default.
        let access_entries = entries
            .iter()
            .filter(|e| !e.flags.contains(Flag::DEFAULT))
            .cloned()
            .collect::<Vec<AclEntry>>();
        let default_entries = entries
            .iter()
            .filter(|e| e.flags.contains(Flag::DEFAULT))
            .cloned()
            .collect::<Vec<AclEntry>>();

        let access_acl = Acl::from_entries(&access_entries)?;
        let default_acl = Acl::from_entries(&default_entries)?;

        for path in paths {
            access_acl.write(&path, options)?;

            // We'll get a PermissionDenied error if called on a file.
            default_acl.write(&path, options | AclOption::DEFAULT_ACL)?;
        }
    }

    Ok(())
}

/// Specify the file owner (Linux).
pub const OWNER: &str = util::OWNER_NAME;

/// Specify other than file owner or group owner (Linux).
pub const OTHER: &str = util::OTHER_NAME;

/// Specify mask for user/group permissions (Linux).
pub const MASK: &str = util::MASK_NAME;
