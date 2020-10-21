#!/bin/sh

# Script to analyze Rust code using grcov.

# Don't include "-Cpanic=abort" in RUSTFLAGS, otherwise bindgen build will fail.
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests"
export RUSTDOCFLAGS="-Cpanic=abort"

# rustup default nightly
cargo build
cargo test
./tests/run_tests.sh

if [ $arg1 = "show" ]; then
    grcov ./target/debug/ -s src -t html --llvm --branch --ignore-not-existing -o ./target/debug/coverage/
    open target/debug/coverage/index.html
fi
