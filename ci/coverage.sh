#! /usr/bin/env bash

# Script to analyze Rust code using grcov.
#
# Usage:   ./code_coverage.sh [open|codecov]

set -e

arg1="$1"
os=$(uname -s | tr '[:upper:]' '[:lower:]')

# Install Rust nightly.
rustup install nightly

# Set up grcov.
rustup component add llvm-tools-preview
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="exacl-%p-%m.profraw"
cargo +nightly install grcov

# Build & Test
cargo +nightly clean
cargo +nightly test --features serde
cargo +nightly build --features serde
./tests/run_tests.sh

if [ "$arg1" = "open" ]; then
    echo "Producing HTML Report locally"
    grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing --ignore "/*" -o ./target/debug/coverage/
    open target/debug/coverage/src/index.html
elif [ "$arg1" = "codecov" ]; then
    echo "Producing lcov report and uploading it to codecov.io"
    grcov . --binary-path ./target/debug/ -s . -t lcov --branch --ignore-not-existing --ignore "/*" -o lcov.info
    bash <(curl -s https://codecov.io/bash) -f lcov.info -n "$os"
fi

exit 0
