# Exacl &emsp; [![CRATE]][crates] [![API]][docs] [![CI]][actions] [![BUILD]][cirrus]

[CRATE]: https://img.shields.io/crates/v/exacl
[crates]: https://crates.io/crates/exacl
[CI]: https://github.com/byllyfish/exacl/workflows/CI/badge.svg
[actions]: https://github.com/byllyfish/exacl/actions?query=branch%3Amain
[API]: https://docs.rs/exacl/badge.svg
[docs]: https://docs.rs/exacl
[BUILD]: https://api.cirrus-ci.com/github/byllyfish/exacl.svg
[cirrus]: https://cirrus-ci.com/github/byllyfish/exacl

Rust library to manipulate file system access control lists (ACL) on `macOS`, `Linux`, and `FreeBSD`.

## Example

```rust
use exacl::{getfacl, setfacl, AclEntry, Perm};

// Get the ACL from "./tmp/foo".
let mut acl = getfacl("./tmp/foo", None)?;

// Print the contents of the ACL.
for entry in &acl {
    println!("{}", entry);
}

// Add an ACL entry to the end.
acl.push(AclEntry::allow_user("some_user", Perm::READ, None));

// Set the ACL for "./tmp/foo".
setfacl(&["./tmp/foo"], &acl, None)?;
```

## High Level API

This module provides two high level functions, `getfacl` and `setfacl`.

- `getfacl` retrieves the ACL for a file or directory.
- `setfacl` sets the ACL for files or directories.

On Linux and FreeBSD, the ACL contains entries for the default ACL, if
present.

Both `getfacl` and `setfacl` work with a `Vec<AclEntry>`. The
`AclEntry` structure contains five fields:

- kind : `AclEntryKind` - the kind of entry (User, Group, Other, Mask,
    or Unknown).
- name : `String` - name of the principal being given access. You can
    use a user/group name, decimal uid/gid, or UUID (on macOS).
- perms : `Perm` - permission bits for the entry.
- flags : `Flag` - flags indicating whether an entry is inherited, etc.
- allow : `bool` - true if entry is allowed; false means deny. Linux only
    supports allow=true.

## Low Level API

Use the `Acl` class if you need finer grained control over the ACL.

- Manipulate the access ACL and default ACL independently on Linux.
- Manipulate the ACL's own flags on macOS.
- Use the platform specific text formats.
