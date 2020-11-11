# exacl

Rust library to manipulate access control lists on macOS and Linux.

## Example

```rust
use exacl::{Acl, AclOption};
use std::path::Path;

let path = Path::new("./foo/bar.txt");
let acl = Acl::read(&path, AclOption::default())?;

for entry in &acl.entries()? {
    println!("{:?}", entry);
}
```

## Set Up Development Environment

Linux

```sh
apt install clang llvm-dev acl libacl1-dev shunit2 valgrind
```
