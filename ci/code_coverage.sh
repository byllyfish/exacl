#!/bin/sh

# Script to analyze Rust code using grcov.
#
# Usage:   ./code_coverage.sh [open|codecov]

set -e

arg1="$1"

# Don't include "-Cpanic=abort" in RUSTFLAGS, otherwise bindgen build will fail.
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests"
export RUSTDOCFLAGS="-Cpanic=abort"

# Build & Test
cargo +nightly install grcov
cargo +nightly test
cargo +nightly build
./tests/run_tests.sh

if [ $arg1 = "open" ]; then
    echo "Producing HTML Report locally."
    grcov ./target/debug/ -s src -t html --llvm --branch --ignore-not-existing -o ./target/debug/coverage/
    open target/debug/coverage/index.html
elif [ $arg1 = "codecov" ]; then
    echo "Producing lcov report and uploading it to codecov.io"
    zip -0 ccov.zip `find . \( -name "exacl*.gc*" \) -print`
    grcov ccov.zip -s src -t lcov --llvm --branch --ignore-not-existing --ignore "/*" -o lcov.info
    bash <(curl -s https://codecov.io/bash) -f lcov.info
fi

exit 0
