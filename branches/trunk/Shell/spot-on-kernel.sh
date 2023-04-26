#!/usr/bin/env sh
# Alexis Megas.

if [ -r /usr/local/spot-on/Spot-On-Kernel ] && \
   [ -x /usr/local/spot-on/Spot-On-Kernel ]
then
    export LD_LIBRARY_PATH=/usr/local/spot-on/Lib
    cd /usr/local/spot-on && exec ./Spot-On-Kernel "$@"
    exit $?
else
    echo "Could not locate /usr/local/spot-on/Spot-On-Kernel."
    exit 1
fi
