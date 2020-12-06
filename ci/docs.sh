#!/bin/bash

# Script to build rust docs.
#
# Usage:  ./ci/docs.sh [open]

set -e

arg1="$1"

# Install Rust nightly.
rustup install nightly

export RUSTDOCFLAGS='--cfg docsrs'

if [ "$arg1" = "open" ]; then
    cargo +nightly doc --no-deps --open
else
    cargo +nightly doc --no-deps
fi

exit 0
