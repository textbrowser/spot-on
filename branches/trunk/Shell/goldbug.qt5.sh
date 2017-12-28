#!/bin/sh

if [ -r /usr/local/goldbug/GoldBug ] && [ -x /usr/local/goldbug/GoldBug ]
then
    export LD_LIBRARY_PATH=/usr/local/goldbug/Lib
    cd /usr/local/goldbug && exec ./GoldBug -style fusion "$@"
    exit $?
else
    exit 1
fi
