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
trap '{ rm -f -- "$diff_out"; }' EXIT

if diff --ignore-space-change "$bindings" "$prebuilt_bindings" >"$diff_out"; then
    echo "Success."
    rm "$diff_out"
    exit 0
fi

echo "Differences exist."

# FreeBSD 14 & 15 include several additional ACL API's that are not used.
# Check the diff output against the approved diff output.

if [ "$target" = "freebsd" ]; then
    release="$(freebsd_release)"
    echo "Running on FreeBSD: $release"

    case "$release" in
    15.*)
        freebsd_diff="./bindgen/bindings_freebsd15.diff"
        ;;
    *)
        freebsd_diff="./bindgen/bindings_freebsd14.diff"
        ;;
    esac

    echo "Comparing diff output ($diff_out) and $freebsd_diff"
    if diff "$diff_out" "$freebsd_diff"; then
        echo "Success (FreeBSD)."
        exit 0
    fi
fi

echo "==== Failure: Differences in bindings! ===="
cat "$diff_out"

exit 1
