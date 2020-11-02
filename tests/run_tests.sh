#!/bin/bash

# Run all test suites using shunit2.

OS=`uname -s | tr A-Z a-z`

script_dir=`dirname "$0"`
cd "$script_dir"

if [ ! -f ../target/debug/exacl ]; then
    echo "exacl executable not found!"
    exit 1
fi

for t in testsuite*_all.sh testsuite*_${OS}.sh; do 
    ./$t
done
