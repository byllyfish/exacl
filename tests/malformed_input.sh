#!/bin/sh
#
# Test exacl with malformed JSON input.

#set -eu

alias exacl=../target/debug/exacl
export RUST_LOG=debug

exacl --set file1 <<EOF
{}
EOF

exacl --set file1 <<EOF
[
EOF

# Non-existant user name.
exacl --set file1 <<EOF
[
    {"kind":"user","name":"non_existant_user","perms":["execute"],"flags":[],"allow":true}
]
EOF

# Non-existant group name.
exacl --set file1 <<EOF
[
    {"kind":"group","name":"non_existant_group","perms":["execute"],"flags":[],"allow":true}
]
EOF

# Numeric uid for name
exacl --set file1 <<EOF
[
    {"kind":"user","name":"501","perms":["execute"],"flags":[],"allow":true}
]
EOF

# name: uid too big
exacl --set file1 <<EOF
[
    {"kind":"user","name":"4294967296","perms":["execute"],"flags":[],"allow":true}
]
EOF

# kind: unknown
exacl --set file1 <<EOF
[
    {"kind":"unknown","name":"7","perms":["read"],"flags":[],"allow":true}
]
EOF

# Missing flags.
exacl --set file1 <<EOF
[
    {"kind":"user","name":"501","perms":["read"],"allow":true}
]
EOF

# Unrecognized flag.
exacl --set file1 <<EOF
[
    {"kind":"user","name":"501","perms":["read"],"flags":["whatever"], "allow":true}
]
EOF

# Additional attribute.
exacl --set file1 <<EOF
[
    {"kind":"user","name":"501","perms":["read"],"flags":[], "allow":true, "ignore": 0}
]
EOF

# Misspelled attribute "kin".
exacl --set file1 <<EOF
[
    {"kin":"user","name":"501","perms":["read"],"flags":[], "allow":true}
]
EOF

# File with inherited flags.
touch file1
exacl --set file1 <<EOF
[
    {"kind":"user","name":"501","perms":["read"],"flags":["directory_inherit", "inherited"], "allow":true}
]
EOF

exacl file1
ls -le   # ls doesn't display directory_inherit?
