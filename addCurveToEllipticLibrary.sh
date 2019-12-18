#!/bin/bash

# this script is run after each npm install
# please see package.json -> scripts -> postinstall

# get relative paths, so that this also works when called from
# outisde this directory

readonly name=$(basename $0)
readonly dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly parentDir="$(dirname "$dir")"
readonly parentParentDir="$(dirname "$parentDir")"

# replace curve file inside elliptic package
# this adds the elliptic curve. curve25519 in weierstrass form to the elliptic library
# since this pull request is not merged yet: https://github.com/indutny/elliptic/pull/113
fileToCopy=$dir/curves.js

# top level node_modules (e.g., node_modules/elliptic)
topLevelDest=$parentParentDir/elliptic/lib/elliptic/curves.js

# node_modules inside @meck93/evote-crypto -> bundled dependencies (e.g., node_modules/@meck93/evote-crypto/node_modules/elliptic)
dependencyDest=$dir/node_modules/elliptic/lib/elliptic/curves.js

# check if the top level destination exist -> if yes, copy the custom curve file
if [ -f "$topLevelDest" ]; then 
    echo "$topLevelDest exist."
    cp -f $fileToCopy $topLevelDest
    echo "$fileToCopy patched."
fi

# check if the top level destination exist -> if yes, copy the custom curve file
if [ -f "$dependencyDest" ]; then 
    echo "$dependencyDest exist."
    cp -f $fileToCopy $dependencyDest
    echo "$fileToCopy patched."
fi
