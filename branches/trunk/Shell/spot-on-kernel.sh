#!/bin/sh

if [ -r /usr/local/spot-on-qt4/Spot-On-Kernel ] && \
   [ -x /usr/local/spot-on-qt4/Spot-On-Kernel ]
then
    export LD_LIBRARY_PATH=/usr/local/spot-on-qt4/Lib
    cd /usr/local/spot-on-qt4 && exec ./Spot-On-Kernel "$@"
    exit $?
else
    exit 1
fi
