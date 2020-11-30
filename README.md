# Exacl

Rust library for access control lists on `macOS` and `Linux`.

## Example

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use exacl::{getfacl, setfacl, AclEntry, Perm};

// Get the ACL from "./tmp/foo".
let mut acl = getfacl("./tmp/foo", None)?;

// Print the contents of the ACL.
for entry in &acl {
    println!("{:?}", entry);
}

// Add an ACL entry to the end.
acl.push(AclEntry::allow_user("some_user", Perm::READ, None));

// Sort the ACL in canonical order.
acl.sort();

// Set the ACL for "./tmp/foo".
setfacl(&["./tmp/foo"], &acl, None)?;

# Ok(()) }
```

## High Level API

This module provides two high level functions, [getfacl] and [setfacl].

- [getfacl] retrieves the ACL for a file or directory. On Linux, the
    result includes the entries from the default ACL if there is one.
- [setfacl] sets the ACL for files or directories, including the default
    ACL on Linux.

Both [getfacl] and [setfacl] work with a vector of [`AclEntry`] structures.
The structure contains five fields:

- kind : [`AclEntryKind`] - the kind of entry (User, Group, Other, Mask,
    or Unknown).
- name : [`String`] - name of the principal being given access. You can
    use a user/group name, decimal uid/gid, or UUID (on macOS).
- perms : [`Perm`] - permission bits for the entry.
- flags : [`Flag`] - flags indicating whether an entry is inherited, etc.
- allow : [`bool`] - true if entry is allowed; false means deny. Linux only
    supports allow=true.

[`AclEntry`] supports an ordering that corresponds to ACL canonical order. An
ACL in canonical order has deny entries first, and inherited entries last.
On Linux, entries for file-owner sort before named users. You can sort a
vector of `AclEntry` to put the ACL in canonical order.

## Low Level API

The low level API is appropriate if you need finer grained control over
the ACL.

- Manipulate the access ACL and default ACL independently on Linux.
- Manipulate the ACL's own flags on macOS.
- Use the platform specific text formats.
