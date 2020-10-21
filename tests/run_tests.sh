#!/bin/sh

# Run all test suites using shunit2.

for t in testsuite_*.sh ; do 
    shunit2 $t
done
