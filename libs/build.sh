#!/bin/bash

set -eux

# Remove old builds
rm -rf acl

# Clone the repo and switch to latest version
git clone https://git.savannah.nongnu.org/git/acl.git
cd acl || exit 1
git checkout tags/v2.3.1

# Generate the library (static and pie/pic included)
./autogen.sh
./configure --enable-static --with-pic --prefix "$(pwd)/usr"
make
make install

# Exit and remove artefacts
cd .. || exit 1
cp -r acl/usr .
rm -rf acl
