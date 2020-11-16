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

shellcheck --version
export SHELLCHECK_OPTS="-e SC1091 -e SC2006 -e SC2016 -e SC2018 -e SC2019 -e SC2086"
shellcheck ci/*.sh tests/*.sh

exit 0
