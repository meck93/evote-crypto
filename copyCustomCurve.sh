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
copyDestination=$dir/node_modules/elliptic/lib/elliptic/curves.js

# replace curve file inside elliptic package
cp $fileToCopy $copyDestination
