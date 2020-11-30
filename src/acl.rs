//! Provides `Acl` and `AclOption` implementation.

use crate::aclentry::AclEntry;
#[cfg(target_os = "linux")]
use crate::aclentry::AclEntryKind;
use crate::failx::{fail_custom, path_err};
#[cfg(target_os = "linux")]
use crate::flag::Flag;
#[cfg(target_os = "linux")]
use crate::perm::Perm;
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

        /// Get/set the default ACL only (Linux only).
        const DEFAULT_ACL = 0x02;

        /// Ignore expected error when using DEFAULT_ACL on a file (Linux only).
        #[doc(hidden)]
        const IGNORE_EXPECTED_FILE_ERR = 0x10;
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
    /// Convenience function to construct an `Acl`.
    #[allow(unused_variables)]
    fn new(acl: acl_t, default_acl: bool) -> Acl {
        assert!(!acl.is_null());
        Acl {
            acl,
            #[cfg(target_os = "linux")]
            default_acl,
        }
    }

    /// Read ACL for specified file.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn read<P: AsRef<Path>>(path: P, options: AclOption) -> io::Result<Acl> {
        let symlink_acl = options.contains(AclOption::SYMLINK_ACL);
        let default_acl = options.contains(AclOption::DEFAULT_ACL);
        let path = path.as_ref();

        let result = xacl_get_file(path, symlink_acl, default_acl);
        match result {
            Ok(acl) => Ok(Acl::new(acl, default_acl)),
            Err(err) => {
                // Trying to access the default ACL of a non-directory on Linux
                // will return an error. We can catch this error and return an
                // empty ACL instead; only if `IGNORE_EXPECTED_FILE_ERR` is set.
                if default_acl
                    && err.kind() == io::ErrorKind::PermissionDenied
                    && options.contains(AclOption::IGNORE_EXPECTED_FILE_ERR)
                    && is_non_directory(&path)
                {
                    // Return an empty acl.
                    Ok(Acl::new(xacl_init(1)?, default_acl))
                } else {
                    Err(path_err(path, &err))
                }
            }
        }
    }

    /// Write ACL for specified file.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn write<P: AsRef<Path>>(&self, path: P, options: AclOption) -> io::Result<()> {
        let symlink_acl = options.contains(AclOption::SYMLINK_ACL);
        let default_acl = options.contains(AclOption::DEFAULT_ACL);
        let path = path.as_ref();

        // If we're writing a default ACL to a non-directory, and we
        // specify the `IGNORE_EXPECTED_FILE_ERR` option, this function is a
        // no-op if the ACL is empty.
        if default_acl && is_non_directory(&path) {
            if self.is_empty() && options.contains(AclOption::IGNORE_EXPECTED_FILE_ERR) {
                return Ok(());
            } else {
                return fail_custom(&format!(
                    "File {:?}: Non-directory does not have default ACL",
                    path
                ));
            }
        }

        if let Err(err) = xacl_set_file(path, self.acl, symlink_acl, default_acl) {
            return Err(path_err(path, &err));
        }

        Ok(())
    }

    /// Check that ACL meets OS requirements.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn check(&self) -> io::Result<()> {
        xacl_check(self.acl)
    }

    /// Compute mask.
    #[cfg(target_os = "linux")]
    fn compute_mask_perms(entries: &[AclEntry], filter: (Flag, Flag)) -> Option<Perm> {
        let mut perms = Perm::empty();
        let mut need_mask = false;

        for entry in entries {
            // Skip over undesired entries in a unified ACL.
            if (entry.flags & filter.1) != filter.0 {
                continue;
            }

            match entry.kind {
                AclEntryKind::Mask => return None,
                AclEntryKind::User | AclEntryKind::Group if !entry.name.is_empty() => {
                    perms |= entry.perms;
                    need_mask = true;
                }
                AclEntryKind::Group => perms |= entry.perms,
                _ => (),
            }
        }

        if !need_mask {
            return None;
        }

        Some(perms)
    }

    /// Construct ACL from slice of [`AclEntry`].
    ///
    /// On Linux, if there is no mask `AclEntry`, one will be computed and
    /// added, if needed.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    pub fn from_entries(entries: &[AclEntry]) -> io::Result<Acl> {
        let new_acl = xacl_init(entries.len())?;

        // Use the smart pointer form of scopeguard; `acl_p` can change value
        // when we create entries in it.
        let mut acl_p = scopeguard::guard(new_acl, |a| {
            xacl_free(a);
        });

        for (i, entry) in entries.iter().enumerate() {
            if let Err(err) = entry.add_to_acl(&mut acl_p) {
                return fail_custom(&format!("entry {}: {}", i, err));
            }
        }

        #[cfg(target_os = "linux")]
        if let Some(mask_perms) = Acl::compute_mask_perms(entries, (Flag::empty(), Flag::empty())) {
            let mask = AclEntry::allow_mask(mask_perms, None);
            if let Err(err) = mask.add_to_acl(&mut acl_p) {
                return fail_custom(&format!("entry {}: {}", -1, err));
            }
        }

        Ok(Acl::new(ScopeGuard::into_inner(acl_p), false))
    }

    /// Construct pair of ACL's from slice of [`AclEntry`].
    ///
    /// Separate regular access entries from default entries on Linux.
    ///
    /// On Linux, if there is no mask `AclEntry` in either ACL, one will be
    /// computed and added, if needed.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on failure.
    #[cfg(target_os = "linux")]
    pub fn from_unified_entries(entries: &[AclEntry]) -> io::Result<(Acl, Acl)> {
        let new_access = xacl_init(entries.len())?;
        let new_default = xacl_init(entries.len())?;

        // Use the smart pointer form of scopeguard; acls can change value when
        // we create entries in them.
        let mut access_p = scopeguard::guard(new_access, |a| {
            xacl_free(a);
        });

        let mut default_p = scopeguard::guard(new_default, |a| {
            xacl_free(a);
        });

        for (i, entry) in entries.iter().enumerate() {
            let result = if entry.flags.contains(Flag::DEFAULT) {
                entry.add_to_acl(&mut default_p)
            } else {
                entry.add_to_acl(&mut access_p)
            };
            if let Err(err) = result {
                return fail_custom(&format!("entry {}: {}", i, err));
            }
        }

        if let Some(mask_perms) = Acl::compute_mask_perms(entries, (Flag::empty(), Flag::DEFAULT)) {
            let mask = AclEntry::allow_mask(mask_perms, None);
            if let Err(err) = mask.add_to_acl(&mut access_p) {
                return fail_custom(&format!("mask entry: {}", err));
            }
        }

        if let Some(mask_perms) = Acl::compute_mask_perms(entries, (Flag::DEFAULT, Flag::DEFAULT)) {
            let mask = AclEntry::allow_mask(mask_perms, Flag::DEFAULT);
            if let Err(err) = mask.add_to_acl(&mut default_p) {
                return fail_custom(&format!("default mask entry: {}", err));
            }
        }

        let access_acl = ScopeGuard::into_inner(access_p);
        let default_acl = ScopeGuard::into_inner(default_p);

        Ok((Acl::new(access_acl, false), Acl::new(default_acl, true)))
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
        let acl = xacl_from_text(text)?;
        Ok(Acl::new(acl, false))
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

/// Return true if path exists and it's not a directory.
fn is_non_directory(path: &Path) -> bool {
    if let Ok(meta) = path.metadata() {
        !meta.is_dir()
    } else {
        false
    }
}
