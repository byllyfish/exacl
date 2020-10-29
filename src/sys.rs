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
