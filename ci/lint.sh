#!/bin/bash

# Script to run lint checks.

set -eu

# Space-separated list of ignored clippy lints.
IGNORE="similar-names wildcard_imports"

allow=""
for name in $IGNORE; do 
    allow="$allow -A clippy::$name"
done

cargo clean
cargo clippy -- -D clippy::all -W clippy::pedantic $allow

exit 0
