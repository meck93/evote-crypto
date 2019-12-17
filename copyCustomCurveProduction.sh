#!/bin/bash

# this script is run after each npm install
# please see package.json -> scripts -> postinstall

# get relative paths, so that this also works when called from
# outisde this directory

readonly name=$(basename $0)
readonly dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly parentDir="$(dirname "$dir")"
readonly parentParentDir="$(dirname "$parentDir")"

fileToCopy=$dir/curves.js
copyDestination=$parentParentDir/elliptic/lib/elliptic/curves.js

# replace curve file inside elliptic package
# this adds the elliptic curve. curve25519 in weierstrass form to the elliptic library
# since this pull request is not merged yet: https://github.com/indutny/elliptic/pull/113
cp $fileToCopy $copyDestination
