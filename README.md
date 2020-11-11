# exacl

Rust library to manipulate access control lists on macOS and Linux.

## Example

```rust
use exacl::{Acl, AclOption};

let acl = Acl::read("./foo/bar.txt", AclOption::default())?;

for entry in &acl.entries()? {
    println!("{:?}", entry);
}
```

## Set Up Development Environment

Linux

```sh
apt install clang llvm-dev acl libacl1-dev shunit2 valgrind
```
