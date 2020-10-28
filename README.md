# exacl

Rust library to manipulate access control lists on MacOS.

## Example

```rust
use exacl::Acl;
use std::path::Path;

let path = Path::new("./foo/bar.txt");
let acl = Acl::read(&path)?;

for entry in &acl.entries()? {
    println!("{:?}", entry);
}
```
