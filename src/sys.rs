//! Rust bindings to system C API.

#![allow(nonstandard_style)]
#![allow(dead_code)]
#![allow(clippy::redundant_static_lifetimes)]
#![allow(clippy::unseparated_literal_suffix)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::too_many_lines)]

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

// Convenience constants where the API expects an i32 type, but bindgen
// provides u32.

#[allow(clippy::cast_possible_wrap)]
pub const ENOENT_I32: i32 = ENOENT as i32;

#[allow(clippy::cast_possible_wrap)]
pub const ENOTSUP_I32: i32 = ENOTSUP as i32;

#[allow(clippy::cast_possible_wrap)]
pub const EINVAL_I32: i32 = EINVAL as i32;

#[allow(clippy::cast_possible_wrap)]
pub const ENOMEM_I32: i32 = ENOMEM as i32;

#[cfg(target_os = "macos")]
#[allow(clippy::cast_possible_wrap)]
pub const O_SYMLINK_I32: i32 = O_SYMLINK as i32;

// Verify that no constants will wrap when converted to i32.
#[cfg(test)]
fn test_constants_u32_to_i32() {
    #![allow(clippy::cast_possible_wrap)]

    assert!(ENOENT as i32 > 0);
    assert!(ENOTSUP as i32 > 0);
    assert!(EINVAL as i32 > 0);
    assert!(ENOMEM as i32 > 0);

    #[cfg(target_os = "macos")]
    assert!(O_SYMLINK as i32 > 0);
}
