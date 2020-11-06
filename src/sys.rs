//! Rust bindings to system C API.

#![allow(nonstandard_style)]
#![allow(dead_code)]
#![allow(clippy::redundant_static_lifetimes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Demangle some MacOS constants. Linux provides these as-is.

#[cfg(target_os = "macos")]
pub const ACL_READ: acl_perm_t = acl_perm_t_ACL_READ_DATA;

#[cfg(target_os = "macos")]
pub const ACL_WRITE: acl_perm_t = acl_perm_t_ACL_WRITE_DATA;

#[cfg(target_os = "macos")]
pub const ACL_EXECUTE: acl_perm_t = acl_perm_t_ACL_EXECUTE;

#[cfg(target_os = "macos")]
pub const ACL_FIRST_ENTRY: i32 = acl_entry_id_t_ACL_FIRST_ENTRY;

#[cfg(target_os = "macos")]
pub const ACL_NEXT_ENTRY: i32 = acl_entry_id_t_ACL_NEXT_ENTRY;

// Linux doesn't have ACL flags; adding acl_flag_t makes the code more orthogonal.
#[cfg(target_os = "linux")]
pub type acl_flag_t = u32;

// MacOS uses acl_get_perm_np().
#[cfg(target_os = "macos")]
pub unsafe fn acl_get_perm(permset_d: acl_permset_t, perm: acl_perm_t) -> ::std::os::raw::c_int {
    acl_get_perm_np(permset_d, perm)
}

/// Non-portable ACL Permissions & Flags (MacOS only)
#[cfg(all(target_os = "macos", not(docsrs)))]
pub mod np {
    use super::*;

    pub const ACL_DELETE: acl_perm_t = acl_perm_t_ACL_DELETE;
    pub const ACL_APPEND_DATA: acl_perm_t = acl_perm_t_ACL_APPEND_DATA;
    pub const ACL_DELETE_CHILD: acl_perm_t = acl_perm_t_ACL_DELETE_CHILD;
    pub const ACL_READ_ATTRIBUTES: acl_perm_t = acl_perm_t_ACL_READ_ATTRIBUTES;
    pub const ACL_WRITE_ATTRIBUTES: acl_perm_t = acl_perm_t_ACL_WRITE_ATTRIBUTES;
    pub const ACL_READ_EXTATTRIBUTES: acl_perm_t = acl_perm_t_ACL_READ_EXTATTRIBUTES;
    pub const ACL_WRITE_EXTATTRIBUTES: acl_perm_t = acl_perm_t_ACL_WRITE_EXTATTRIBUTES;
    pub const ACL_READ_SECURITY: acl_perm_t = acl_perm_t_ACL_READ_SECURITY;
    pub const ACL_WRITE_SECURITY: acl_perm_t = acl_perm_t_ACL_WRITE_SECURITY;
    pub const ACL_CHANGE_OWNER: acl_perm_t = acl_perm_t_ACL_CHANGE_OWNER;
    pub const ACL_SYNCHRONIZE: acl_perm_t = acl_perm_t_ACL_SYNCHRONIZE;

    pub const ACL_FLAG_DEFER_INHERIT: acl_flag_t = acl_flag_t_ACL_FLAG_DEFER_INHERIT;
    pub const ACL_FLAG_NO_INHERIT: acl_flag_t = acl_flag_t_ACL_FLAG_NO_INHERIT;
    pub const ACL_ENTRY_INHERITED: acl_flag_t = acl_flag_t_ACL_ENTRY_INHERITED;
    pub const ACL_ENTRY_FILE_INHERIT: acl_flag_t = acl_flag_t_ACL_ENTRY_FILE_INHERIT;
    pub const ACL_ENTRY_DIRECTORY_INHERIT: acl_flag_t = acl_flag_t_ACL_ENTRY_DIRECTORY_INHERIT;
    pub const ACL_ENTRY_LIMIT_INHERIT: acl_flag_t = acl_flag_t_ACL_ENTRY_LIMIT_INHERIT;
    pub const ACL_ENTRY_ONLY_INHERIT: acl_flag_t = acl_flag_t_ACL_ENTRY_ONLY_INHERIT;
}

/// Non-portable ACL Permissions (Docs only)
#[cfg(all(not(target_os = "macos"), docsrs))]
pub mod np {
    use super::*;

    pub const ACL_DELETE: acl_perm_t = 0;
    pub const ACL_APPEND_DATA: acl_perm_t = 0;
    pub const ACL_DELETE_CHILD: acl_perm_t = 0;
    pub const ACL_READ_ATTRIBUTES: acl_perm_t = 0;
    pub const ACL_WRITE_ATTRIBUTES: acl_perm_t = 0;
    pub const ACL_READ_EXTATTRIBUTES: acl_perm_t = 0;
    pub const ACL_WRITE_EXTATTRIBUTES: acl_perm_t = 0;
    pub const ACL_READ_SECURITY: acl_perm_t = 0;
    pub const ACL_WRITE_SECURITY: acl_perm_t = 0;
    pub const ACL_CHANGE_OWNER: acl_perm_t = 0;
    pub const ACL_SYNCHRONIZE: acl_perm_t = 0;

    pub const ACL_FLAG_DEFER_INHERIT: acl_flag_t = 0;
    pub const ACL_FLAG_NO_INHERIT: acl_flag_t = 0;
    pub const ACL_ENTRY_INHERITED: acl_flag_t = 0;
    pub const ACL_ENTRY_FILE_INHERIT: acl_flag_t = 0;
    pub const ACL_ENTRY_DIRECTORY_INHERIT: acl_flag_t = 0;
    pub const ACL_ENTRY_LIMIT_INHERIT: acl_flag_t = 0;
    pub const ACL_ENTRY_ONLY_INHERIT: acl_flag_t = 0;
}
