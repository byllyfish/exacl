#!/bin/bash

# Run all test suites.

OS=`uname -s | tr A-Z a-z`

arg1="$1"
script_dir=`dirname "$0"`
cd "$script_dir"

if [ ! -f ../target/debug/exacl ]; then
    echo "exacl executable not found!"
    exit 1
fi

unit_tests() {
    # Find executable files without file extensions.
    find ../target/debug/deps -type f -executable -print | grep -vE '\w+\.\w+$'
}

if [ "$arg1" = "memcheck" ]; then
    export MEMCHECK="valgrind -q"
    for test in `unit_tests`; do
        $MEMCHECK $test
    done
fi

exit_status=0

for test in testsuite*_all.sh testsuite*_${OS}.sh; do
    # Before running test, print name of file underlined with = signs.
    printf "\n%s\n%s\n" "$test" `printf '=%.0s' $(seq 1 ${#test})`
    # Run the test.
    ./$test
    status=$?;

    # Track if any test returns a non-zero exit status.
    if [ $status -ne 0 ]; then
        exit_status=$status
    fi
done

exit $exit_status
