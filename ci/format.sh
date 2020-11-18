#!/bin/bash

# Script to check code formatting.

set -eu

# Check rust formatting.
cargo fmt -- --check

# Check shell script formatting.
shfmt -i 4 -d ci/*.sh tests/*.sh

exit 0
