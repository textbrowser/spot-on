#!/usr/bin/env bash

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <VERSION>"
    exit 1
fi

# Debian release packages.

for file in */control; do
    sed -i "s/Version: .*/Version: $VERSION/" $file
done

# Version configuration.

FILE="Common/spot-on-version.h"

sed -i 's/\(SPOTON_VERSION_STR "\)[0-9]\+\(\.[0-9]\+\)*"/\1'"$VERSION"'"/' $FILE
