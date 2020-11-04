#!/bin/bash

# Run all test suites.

set -u

OS=`uname -s | tr A-Z a-z`

script_dir=`dirname "$0"`
cd "$script_dir"

if [ ! -f ../target/debug/exacl ]; then
    echo "exacl executable not found!"
    exit 1
fi

for t in testsuite*_all.sh testsuite*_${OS}.sh; do
    # Before running test, print name of file underlined with = signs.
    printf "\n%s\n%s\n" "$t" `printf '=%.0s' $(seq 1 ${#t})`
    ./$t
done
