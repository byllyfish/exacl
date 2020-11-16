#!/bin/bash

# Script to run lint checks.

set -eu

# Space-separated list of ignored clippy lints.
IGNORE="similar-names wildcard_imports"

allow=""
for name in $IGNORE; do
    allow="$allow -A clippy::$name"
done

# Check rust code with clippy.
rustup component add clippy
cargo clippy --version
cargo clean
# shellcheck disable=SC2086
cargo clippy --all-targets --all-features -- -D clippy::all -W clippy::pedantic -W clippy::cargo $allow

# Check bash scripts with shellcheck.
shellcheck --version
export SHELLCHECK_OPTS="-e SC2086"
shellcheck ci/*.sh tests/*.sh

exit 0
