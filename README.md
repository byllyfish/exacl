# exacl

Rust library to manipulate access control lists on macOS and Linux.

## Example

```rust
use exacl::{getfacl, AclOption};

let acl = getfacl("./tmp/foo", AclOption::empty())?;

for entry in acl {
    println!("{:?}", entry);
}
```

## Set Up Development Environment

Linux

```sh
apt install clang llvm-dev acl libacl1-dev shunit2 valgrind
```
