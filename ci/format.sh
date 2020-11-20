#!/bin/bash

# Script to check code formatting.

set -eu

# Check rust formatting.
cargo fmt -- --check

# Check shell script formatting.
if command -v shfmt &>/dev/null; then
    shfmt -i 4 -d ci/*.sh tests/*.sh
else
    echo "shfmt is not installed."
fi

exit 0
