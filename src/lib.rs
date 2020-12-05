//! # exacl
//!
//! Manipulate file system access control lists (ACL) on `macOS` and `Linux`.
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
//! This module provides two high level functions, [`getfacl`] and [`setfacl`].
//!
//! - [`getfacl`] retrieves the ACL for a file or directory. On Linux, the
//!     result includes the entries from the default ACL if there is one.
//! - [`setfacl`] sets the ACL for files or directories, including the default
//!     ACL on Linux.
//!
//! Both [`getfacl`] and [`setfacl`] work with a `Vec<AclEntry>`. The
//! [`AclEntry`] structure contains five fields:
//!
//! - kind : [`AclEntryKind`] - the kind of entry (User, Group, Other, Mask,
//!     or Unknown).
//! - name : [`String`] - name of the principal being given access. You can
//!     use a user/group name, decimal uid/gid, or UUID (on macOS).
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
//!
//! The low level API uses the [`Acl`] class which wraps the native ACL object.
//! Each [`Acl`] is immutable once constructed. To manipulate its contents, you
//! can retrieve a mutable vector of [`AclEntry`], modify the vector's contents,
//! then create a new [`Acl`].

#![cfg_attr(docsrs, feature(doc_cfg))]

mod acl;
mod aclentry;
mod bititer;
mod failx;
mod flag;
mod perm;
mod qualifier;
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
/// are marked with empty names ("").
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

    #[cfg(target_os = "macos")]
    {
        Acl::read(&path, options)?.entries()
    }

    #[cfg(not(target_os = "macos"))]
    {
        if options.contains(AclOption::DEFAULT_ACL) {
            Acl::read(&path, options)?.entries()
        } else {
            let mut entries = Acl::read(&path, options)?.entries()?;
            let mut default = Acl::read(
                &path,
                options | AclOption::DEFAULT_ACL | AclOption::IGNORE_EXPECTED_FILE_ERR,
            )?
            .entries()?;

            entries.append(&mut default);
            Ok(entries)
        }
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
/// the [`AclEntry::allow_other`] and [`AclEntry::allow_mask`] functions to
/// specify the mode's other and mask permissions. Use "" as the name for the
/// file owner and group owner.
///
/// If an ACL contains a named user or group, there should be a
/// [`AclEntryKind::Mask`] entry included. If a one entry is not provided, one
/// will be computed.
///
/// The access control entries may include entries for the default ACL, if one
/// is desired. When `setfacl` is called with no [`Flag::DEFAULT`] entries, it
/// deletes the default ACL.
///
/// ### Linux Example
///
/// ```ignore
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use exacl::{setfacl, AclEntry, Flag, Perm};
///
/// let entries = vec![
///     AclEntry::allow_user("", Perm::READ | Perm::WRITE, None),
///     AclEntry::allow_group("", Perm::READ, None),
///     AclEntry::allow_other(Perm::empty(), None),
///     AclEntry::allow_user("some_user", Perm::READ | Perm::WRITE, None),
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

    #[cfg(not(target_os = "macos"))]
    {
        if options.contains(AclOption::DEFAULT_ACL) {
            let acl = Acl::from_entries(entries).map_err(|err| custom_err("Invalid ACL", &err))?;

            if !acl.is_empty() {
                acl.check().map_err(|err| custom_err("Invalid ACL", &err))?
            }

            for path in paths {
                acl.write(path, options)?;
            }
        } else {
            let (access_acl, default_acl) = Acl::from_unified_entries(entries)
                .map_err(|err| custom_err("Invalid ACL", &err))?;

            access_acl
                .check()
                .map_err(|err| custom_err("Invalid ACL", &err))?;

            if !default_acl.is_empty() {
                default_acl
                    .check()
                    .map_err(|err| custom_err("Invalid ACL", &err))?;
            }

            for path in paths {
                // Try to set default acl first. This will fail if path is not
                // a directory and default_acl is non-empty. This ordering
                // avoids leaving the file's ACL in a partially changed state
                // after an error (simply because it was a non-directory).
                default_acl.write(
                    &path,
                    options | AclOption::DEFAULT_ACL | AclOption::IGNORE_EXPECTED_FILE_ERR,
                )?;
                access_acl.write(&path, options)?;
            }
        }
    }

    Ok(())
}
