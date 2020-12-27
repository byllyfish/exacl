#! /usr/bin/env bash

# Script to analyze Rust code using grcov.
#
# Usage:   ./code_coverage.sh [open|codecov]

set -e

arg1="$1"
os=$(uname -s | tr '[:upper:]' '[:lower:]')

unit_tests() {
    # Find executable files without file extensions.
    bins="$(find ./target/debug/deps -type f -executable -print | grep -vE '\w+\.\w+$')"
    # Prefix each with "--object"
    result=""
    for bin in $bins; do
        result="$result --object $bin"
    done
    echo "$result"
}

if [ "$os" = "darwin" ]; then
    llvm-profdata() {
        xcrun llvm-profdata "$@"
    }
    llvm-cov() {
        xcrun llvm-cov "$@"
    }
fi

# Install Rust nightly.
rustup install nightly

# Don't include "-Cpanic=abort" in RUSTFLAGS, otherwise bindgen build will fail.
# Use exclusion patterns for lines and patterns: https://github.com/mozilla/grcov/pull/416

excl_br_line='#\[derive\(|debug!|assert!|assert_eq!|process::exit\('

if [ "$arg1" = "llvm-cov" ]; then
    export RUSTFLAGS="-Zinstrument-coverage"
    export LLVM_PROFILE_FILE=/tmp/llvm_profile/profile-%p.profraw
    cargo +nightly install rustfilt
else
    export CARGO_INCREMENTAL=0
    export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests"
    export RUSTDOCFLAGS="-Cpanic=abort"
    cargo +nightly install grcov
fi

# Build & Test
cargo +nightly clean
cargo +nightly test
cargo +nightly build
./tests/run_tests.sh

if [ "$arg1" = "open" ]; then
    echo "Producing HTML Report locally"
    # shellcheck disable=SC2046
    zip -0 ccov$$.zip $(find . \( -name "exacl*.gc*" \) -print)
    grcov ccov$$.zip -s . -t html --llvm --branch --ignore-not-existing --ignore "/*" --excl-br-line "$excl_br_line" -o ./target/debug/coverage/
    rm ccov$$.zip
    open target/debug/coverage/index.html
elif [ "$arg1" = "codecov" ]; then
    echo "Producing lcov report and uploading it to codecov.io"
    # shellcheck disable=SC2046
    zip -0 ccov$$.zip $(find . \( -name "exacl*.gc*" \) -print)
    grcov ccov$$.zip -s . -t lcov --llvm --branch --ignore-not-existing --ignore "/*" --excl-br-line "$excl_br_line" -o lcov.info
    rm ccov$$.zip
    bash <(curl -s https://codecov.io/bash) -f lcov.info -n "$os"
elif [ "$arg1" = "llvm-cov" ]; then
    echo "Producing llvm-cov report in Terminal."
    llvm-profdata merge -sparse /tmp/llvm_profile/profile-*.profraw -o coverage.profdata
    # shellcheck disable=SC2046
    llvm-cov show -Xdemangler=rustfilt -ignore-filename-regex='/\.cargo/|/out/bindings\.rs|/thread/local\.rs' -instr-profile=coverage.profdata -show-line-counts-or-regions -show-instantiations=0 ./target/debug/exacl $(unit_tests)
fi

exit 0
