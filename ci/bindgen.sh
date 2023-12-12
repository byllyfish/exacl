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

diff_out="$(mktemp)"
echo "$diff_out"
trap '{ rm -f -- "$diff_out"; }' EXIT

if diff "$bindings" "$prebuilt_bindings" > "$diff_out"; then
    echo "Success."
    rm "$diff_out"
    exit 0
fi

echo "Differences exist."

# FreeBSD 14 includes several additional ACL API's that are not used.
# Check the diff output against the approved diff output.
freebsd_diff="./bindgen/bindings_freebsd14.diff"

if [ "$target" = "freebsd" ]; then
    echo "Comparing diff output ($diff_out) and $freebsd_diff"
    diff "$diff_out" "$freebsd_diff"
    echo "Success."
    exit 0
else
    cat "$diff_out"
fi

exit 1
