//! Provides `Acl` and `AclOption` implementation.

use crate::aclentry::AclEntry;
use crate::failx::{fail_custom, path_err};
#[cfg(target_os = "linux")]
use crate::flag::Flag;
use crate::util::*;

use bitflags::bitflags;
use scopeguard::{self, ScopeGuard};
use std::io;
use std::path::Path;

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
    /// Read ACL for specified file.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn read<P: AsRef<Path>>(path: P, options: AclOption) -> io::Result<Acl> {
        let symlink_acl = options.contains(AclOption::SYMLINK_ACL);
        let default_acl = options.contains(AclOption::DEFAULT_ACL);

        let acl_p = xacl_get_file(path.as_ref(), symlink_acl, default_acl)
            .map_err(|err| path_err(path.as_ref(), &err))?;

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

        // Don't check ACL if it's an empty, default ACL (FIXME).
        if !default_acl || !self.is_empty() {
            xacl_check(self.acl).map_err(|err| path_err(path.as_ref(), &err))?;
        }

        xacl_set_file(path.as_ref(), self.acl, symlink_acl, default_acl)
            .map_err(|err| path_err(path.as_ref(), &err))?;

        Ok(())
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
