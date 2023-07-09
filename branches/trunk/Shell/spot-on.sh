#!/usr/bin/env sh
# Alexis Megas.

if [ -r /opt/spot-on/Spot-On ] && [ -x /opt/spot-on/Spot-On ]
then
    export LD_LIBRARY_PATH=/opt/spot-on/Lib
    export QT_AUTO_SCREEN_SCALE_FACTOR=1

    # Disable https://en.wikipedia.org/wiki/MIT-SHM.

    export QT_X11_NO_MITSHM=1
    cd /opt/spot-on && exec ./Spot-On "$@"
    exit $?
else
    echo "Could not locate /opt/spot-on/Spot-On."
    exit 1
fi
