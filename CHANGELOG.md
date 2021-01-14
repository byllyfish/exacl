# Changelog

## [0.4.0] - 2021-01-13

- Add support for symbolic links on `FreeBSD`.
- Add support for `ACCESS_ACL` option to `getfacl` and `setfacl`.
- Allow for `-` in permission abbreviation, e.g. `r-x`.
- Update rust toolchain to latest stable version and fix clippy/lint issues.
- Fix package metadata for docs.rs; improve platform-specific documentation.

## [0.3.0] - 2021-01-02

- Add support for Posix.1e ACLs on `FreeBSD`.
- Add `from_str` and `to_string` top-level functions.
- Remove the `Acl::check` function from public API.

## [0.2.0] - 2020-12-22

- Implement buildtime_bindgen feature; use prebuilt bindings by default. 
- Implement `FromStr` and `Display` for `AclEntry`.
- Add `to_writer` and `from_reader` top-level functions for parsing text.

## [0.1.1] - 2020-12-08

- Fix docs build on docs.rs by including platform bindings for macos and linux.

## [0.1.0] - 2020-12-06

Initial release.
