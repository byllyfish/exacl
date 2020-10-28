//! Rust bindings to system C API.

#![allow(nonstandard_style)]
#![allow(dead_code)]
#![allow(clippy::redundant_static_lifetimes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(target_os = "linux")]
pub type acl_flag_t = u32;
