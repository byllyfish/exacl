# exacl

Rust library to manipulate access control lists on macOS and Linux.

## Example

```rust
use exacl::getfacl;

let acl = getfacl("./tmp/foo", None)?;

for entry in acl {
    println!("{:?}", entry);
}
```

## Set Up Development Environment

Linux

```sh
apt install clang llvm-dev acl libacl1-dev shunit2 shellcheck shfmt valgrind
```
