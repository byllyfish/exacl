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

// Linux doesn't have ACL flags; adding acl_flag_t makes the code more orthogonal.
// On FreeBSD, acl_flag_t is a u16.
#[cfg(target_os = "linux")]
pub type acl_flag_t = u32;

// Linux doesn't have ACL_MAX_ENTRIES, so define it as 2 billion.
#[cfg(target_os = "linux")]
pub const ACL_MAX_ENTRIES: u32 = 2_000_000_000;

// MacOS and FreeBSD use acl_get_perm_np().
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub unsafe fn acl_get_perm(permset_d: acl_permset_t, perm: acl_perm_t) -> ::std::os::raw::c_int {
    acl_get_perm_np(permset_d, perm)
}

/// Non-portable ACL Permissions & Flags (`macOS` only)
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

/// Non-portable ACL Permissions (Docs only). These are fabricated constants to
/// make it possible for docs to be built on macOS and Linux.
#[cfg(docsrs)]
pub mod np {
    use super::*;

    pub const ACL_DELETE: acl_perm_t = 1 << 10;
    pub const ACL_APPEND_DATA: acl_perm_t = 1 << 11;
    pub const ACL_DELETE_CHILD: acl_perm_t = 1 << 12;
    pub const ACL_READ_ATTRIBUTES: acl_perm_t = 1 << 13;
    pub const ACL_WRITE_ATTRIBUTES: acl_perm_t = 1 << 14;
    pub const ACL_READ_EXTATTRIBUTES: acl_perm_t = 1 << 15;
    pub const ACL_WRITE_EXTATTRIBUTES: acl_perm_t = 1 << 16;
    pub const ACL_READ_SECURITY: acl_perm_t = 1 << 17;
    pub const ACL_WRITE_SECURITY: acl_perm_t = 1 << 18;
    pub const ACL_CHANGE_OWNER: acl_perm_t = 1 << 19;
    pub const ACL_SYNCHRONIZE: acl_perm_t = 1 << 20;

    pub const ACL_FLAG_DEFER_INHERIT: acl_flag_t = 1 << 21;
    pub const ACL_FLAG_NO_INHERIT: acl_flag_t = 1 << 22;
    pub const ACL_ENTRY_INHERITED: acl_flag_t = 1 << 23;
    pub const ACL_ENTRY_FILE_INHERIT: acl_flag_t = 1 << 24;
    pub const ACL_ENTRY_DIRECTORY_INHERIT: acl_flag_t = 1 << 25;
    pub const ACL_ENTRY_LIMIT_INHERIT: acl_flag_t = 1 << 26;
    pub const ACL_ENTRY_ONLY_INHERIT: acl_flag_t = 1 << 27;
}

// Convenience constants where the API expects a signed i32 type, but bindgen
// provides u32.

pub mod sg {
    #![allow(clippy::cast_possible_wrap)]

    pub const ENOENT: i32 = super::ENOENT as i32;
    pub const ENOTSUP: i32 = super::ENOTSUP as i32;
    pub const EINVAL: i32 = super::EINVAL as i32;
    pub const ENOMEM: i32 = super::ENOMEM as i32;
    pub const ACL_MAX_ENTRIES: i32 = super::ACL_MAX_ENTRIES as i32;

    #[cfg(target_os = "macos")]
    pub const ACL_FIRST_ENTRY: i32 = super::acl_entry_id_t_ACL_FIRST_ENTRY;
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub const ACL_FIRST_ENTRY: i32 = super::ACL_FIRST_ENTRY as i32;

    #[cfg(target_os = "macos")]
    pub const ACL_NEXT_ENTRY: i32 = super::acl_entry_id_t_ACL_NEXT_ENTRY;
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub const ACL_NEXT_ENTRY: i32 = super::ACL_NEXT_ENTRY as i32;

    #[cfg(target_os = "macos")]
    pub const O_SYMLINK: i32 = super::O_SYMLINK as i32;

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub const ACL_USER_OBJ: i32 = super::ACL_USER_OBJ as i32;
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub const ACL_USER: i32 = super::ACL_USER as i32;
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub const ACL_GROUP_OBJ: i32 = super::ACL_GROUP_OBJ as i32;
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub const ACL_GROUP: i32 = super::ACL_GROUP as i32;
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub const ACL_MASK: i32 = super::ACL_MASK as i32;
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub const ACL_OTHER: i32 = super::ACL_OTHER as i32;

    #[cfg(target_os = "macos")]
    pub const ID_TYPE_UID: i32 = super::ID_TYPE_UID as i32;
    #[cfg(target_os = "macos")]
    pub const ID_TYPE_GID: i32 = super::ID_TYPE_GID as i32;

    #[test]
    fn test_signed() {
        assert!(super::ENOENT as i32 >= 0);
        assert!(super::ENOTSUP as i32 >= 0);
        assert!(super::EINVAL as i32 >= 0);
        assert!(super::ENOMEM as i32 >= 0);
        assert!(super::ACL_MAX_ENTRIES as i32 >= 0);

        #[cfg(target_os = "linux")]
        assert!(super::ACL_FIRST_ENTRY as i32 >= 0);

        #[cfg(target_os = "linux")]
        assert!(super::ACL_NEXT_ENTRY as i32 >= 0);

        #[cfg(target_os = "macos")]
        assert!(super::O_SYMLINK as i32 >= 0);

        #[cfg(target_os = "linux")]
        assert!(super::ACL_USER_OBJ as i32 >= 0);
        #[cfg(target_os = "linux")]
        assert!(super::ACL_USER as i32 >= 0);
        #[cfg(target_os = "linux")]
        assert!(super::ACL_GROUP_OBJ as i32 >= 0);
        #[cfg(target_os = "linux")]
        assert!(super::ACL_GROUP as i32 >= 0);
        #[cfg(target_os = "linux")]
        assert!(super::ACL_MASK as i32 >= 0);
        #[cfg(target_os = "linux")]
        assert!(super::ACL_OTHER as i32 >= 0);

        #[cfg(target_os = "macos")]
        assert!(super::ID_TYPE_UID as i32 >= 0);
        #[cfg(target_os = "macos")]
        assert!(super::ID_TYPE_GID as i32 >= 0);
    }
}
