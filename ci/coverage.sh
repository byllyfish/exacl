#!/bin/bash

# Script to analyze Rust code using grcov.
#
# Usage:   ./code_coverage.sh [open|codecov]

set -e

arg1="$1"
os=$(uname -s | tr '[:upper:]' '[:lower:]')

# Install Rust nightly and grcov.
rustup install nightly
cargo +nightly install grcov

# Don't include "-Cpanic=abort" in RUSTFLAGS, otherwise bindgen build will fail.
# Use exclusion patterns for lines and patterns: https://github.com/mozilla/grcov/pull/416

excl_br_line='#\[derive\(|debug!|assert!|assert_eq!|process::exit\('

# Work-around grcov issue where an isolated closing curly brace is counted as missing in code coverage (11/21/2020).
excl_line='^[ \t]*\}$'

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Cdebug-assertions=no -Zpanic_abort_tests"
export RUSTDOCFLAGS="-Cpanic=abort"

# Build & Test
cargo +nightly clean
cargo +nightly test
cargo +nightly build
./tests/run_tests.sh

if [ "$arg1" = "open" ]; then
    echo "Producing HTML Report locally"
    # shellcheck disable=SC2046
    zip -0 ccov$$.zip $(find . \( -name "exacl*.gc*" \) -print)
    grcov ccov$$.zip -s . -t html --llvm --branch --ignore-not-existing --ignore "/*" --excl-br-line "$excl_br_line" --excl-line "$excl_line" -o ./target/debug/coverage/
    rm ccov$$.zip
    open target/debug/coverage/index.html
elif [ "$arg1" = "codecov" ]; then
    echo "Producing lcov report and uploading it to codecov.io"
    # shellcheck disable=SC2046
    zip -0 ccov$$.zip $(find . \( -name "exacl*.gc*" \) -print)
    grcov ccov$$.zip -s . -t lcov --llvm --branch --ignore-not-existing --ignore "/*" --excl-br-line "$excl_br_line" --excl-line "$excl_line" -o lcov.info
    rm ccov$$.zip
    bash <(curl -s https://codecov.io/bash) -f lcov.info -n "$os"
fi

exit 0
