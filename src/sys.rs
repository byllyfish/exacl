//! Rust bindings to system C API.

#![allow(nonstandard_style)]
#![allow(dead_code)]
#![allow(clippy::redundant_static_lifetimes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
