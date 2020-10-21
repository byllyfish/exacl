#!/bin/sh

# Run all test suites using shunit2.

script_dir=`dirname "$0"`
cd "$script_dir"

if [ ! -f ../target/debug/exacl ]; then
    echo "exacl executable not found!"
    exit 1
fi

for t in testsuite_*.sh ; do 
    shunit2 $t
done
