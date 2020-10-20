# exacl

Rust library to manipulate access control lists on MacOS.

## API

- read_acl
- write_acl
- validate_acl

## Example

```rust
use exacl;
use std::path::Path;

let path = Path::new("./foo/bar.txt");
let acl = exacl::read_acl(&path)?;
for entry in &acl {
    println!("{:?}", entry);
}
```
