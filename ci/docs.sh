#! /usr/bin/env bash

# Script to build rust docs.
#
# Usage:  ./ci/docs.sh [open]

set -e

arg1="$1"

# Install Rust nightly.
rustup install nightly

export RUSTDOCFLAGS='--cfg docsrs'
export DOCS_RS=1

if [ "$arg1" = "open" ]; then
    cargo +nightly doc --no-deps --open
else
    cargo +nightly doc --no-deps

    # Add an index.html file that redirects to our main page.
    if [ ! -f "target/doc/index.html" ]; then
        echo '<meta http-equiv=refresh content=0;url=exacl/index.html>' >"target/doc/index.html"
    fi
fi

exit 0
