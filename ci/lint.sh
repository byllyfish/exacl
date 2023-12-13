#! /usr/bin/env bash

# Script to run lint checks.

set -eu

# Space-separated list of ignored clippy lints.
IGNORE="similar-names wildcard_imports use_self module_name_repetitions needless_raw_string_hashes"

allow=""
for name in $IGNORE; do
    allow="$allow -A clippy::$name"
done

# Check rust code with clippy.
rustup component add clippy
cargo clippy --version
cargo clean
cargo clippy --all-targets --all-features -- -D clippy::all -W clippy::pedantic -W clippy::cargo -W clippy::nursery $allow

# Check bash scripts with shellcheck.
shellcheck --version || exit 0
SHELLCHECK_OPTS="-e SC2086" shellcheck ci/*.sh tests/*.sh

exit 0
