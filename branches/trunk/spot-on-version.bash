#!/usr/bin/env bash
# Alexis Megas.

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Please specify the version: $0 <VERSION>."
    exit 1
fi

for file in */control; do
    sed -i "s/Version: .*/Version: $VERSION/" $file
done

for file in Distributions/build*; do
    sed -i "s/Spot-On-.*_/Spot-On-$VERSION\_/" $file
done

FILE="Common/spot-on-version.h"

sed -i 's/\(SPOTON_VERSION_STR "\)[0-9]\+\(\.[0-9]\+\)*"/\1'"$VERSION"'"/' \
    $FILE
echo "Please modify ReleaseNotes.html."
