#!/bin/bash

# Script to run lint checks.

set -eu

# Space-separated list of ignored clippy lints.
IGNORE="similar-names wildcard_imports"

allow=""
for name in $IGNORE; do 
    allow="$allow -A clippy::$name"
done

rustup component add clippy
cargo clean
cargo clippy --all-targets --all-features -- -D clippy::all -W clippy::pedantic -W clippy::cargo $allow

shellcheck --severity=warning tests/*.sh

exit 0
