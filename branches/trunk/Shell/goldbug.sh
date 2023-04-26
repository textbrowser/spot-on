#!/usr/bin/env sh
# Alexis Megas.

if [ -r /usr/local/goldbug/GoldBug ] && [ -x /usr/local/goldbug/GoldBug ]
then
    export LD_LIBRARY_PATH=/usr/local/goldbug/Lib
    export QT_AUTO_SCREEN_SCALE_FACTOR=1

    # Disable https://en.wikipedia.org/wiki/MIT-SHM.

    export QT_X11_NO_MITSHM=1
    cd /usr/local/goldbug && exec ./GoldBug "$@"
    exit $?
else
    echo "Could not locate /usr/local/goldbug/GoldBug."
    exit 1
fi
