#!/bin/bash

# Run all test suites.
#
# If run with `memcheck` argument, run all tests under valgrind.

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

arg1="$1"
script_dir=$(dirname "$0")
cd "$script_dir" || exit 1

if [ ! -f ../target/debug/exacl ]; then
    echo "exacl executable not found!"
    exit 1
fi

unit_tests() {
    # Find executable files without file extensions.
    find ../target/debug/deps -type f -executable -print | grep -vE '\w+\.\w+$'
}

exit_status=0

if [ "$arg1" = "memcheck" ]; then
    # Enable memory check command and re-run unit tests under memcheck.
    export MEMCHECK="valgrind -q --error-exitcode=9 --leak-check=full --errors-for-leak-kinds=definite --suppressions=valgrind.supp --gen-suppressions=all"

    vers=$(valgrind --version)
    echo "Running tests with memcheck ($vers)"
    echo

    for test in $(unit_tests); do
        $MEMCHECK "$test"
        status=$?

        # Track if any memcheck returns a non-zero exit status.
        if [ $status -ne 0 ]; then
            exit_status=$status
        fi
    done
fi

for test in testsuite*_all.sh testsuite*_"$OS".sh; do
    # Before running test, print name of file underlined with = signs.
    # shellcheck disable=SC2046
    printf "\n%s\n%s\n" "$test" $(printf '=%.0s' $(seq 1 ${#test}))
    # Run the test.
    ./"$test"
    status=$?

    # Track if any test returns a non-zero exit status.
    if [ $status -ne 0 ]; then
        exit_status=$status
    fi
done

# Log non-zero exit status.
if [ $exit_status -ne 0 ]; then
    echo "Exit Status: $exit_status"
fi

exit $exit_status
