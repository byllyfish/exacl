#! /usr/bin/env bash

# Test the `buildtime_bindgen` feature.

set -eu

# Build using bindgen.
cargo clean
cargo build --features buildtime_bindgen

# Set $target to current OS name.
os="$(uname -s)"
case "$os" in
"Darwin")
    target="macos"
    ;;
"Linux")
    target="linux"
    ;;
"FreeBSD")
    target="freebsd"
    ;;
*)
    echo "Unknown OS: $os"
    exit 1
    ;;
esac

# Test that generated bindings match the prebuilt version.
prebuilt_bindings="./bindgen/bindings_$target.rs"
bindings=$(find ./target/debug/build -name "bindings.rs")

echo "Comparing $bindings and $prebuilt_bindings"
diff "$bindings" "$prebuilt_bindings"

exit 0
