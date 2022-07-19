# Changelog

## [Unreleased]

- Fix code coverage CI script to address GHA build issue.
- Include ubuntu-22.04 and macos-12 in CI build.

## [0.9.0] - 2022-06-08

- Fix compilation on various Linux architectures where `c_char` is signed (Issue #107).
- Disable `layout_tests` option in `bindgen`.
- Update version dependencies for `bindgen` and `uuid`.
- Improve code coverage CI script.
- Fix clippy warnings.

## [0.8.0] - 2022-02-03

- `serde` is now an optional dependency. Use `features = ["serde"]` to enable (Issue #95).
- Remove the `num_enum` dependency (PR #94, contributed by bjorn3).
- Update example code to use clap 3.

## [0.7.0] - 2021-12-25

- Add the `from_mode` top level function.
- Remove `Acl` (low level interface) from the public exported API.
- Remove dependency on the `nix` crate.
- Update version dependencies for bindgen and env_logger.
- Update Rust edition from 2018 to 2021.

## [0.6.0] - 2021-06-20

- Fix new rust clippy warnings.
- Update version dependencies for bindgen and nix.
- Update valgrind suppressions used in testing.

## [0.5.0] - 2021-02-22

- Add support for NFSv4 ACL's on `FreeBSD`.
- Remove support for platform-specific text formats.

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
