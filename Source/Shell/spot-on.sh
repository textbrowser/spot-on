#!/usr/bin/env sh

# Alexis Megas.

os=$(uname -o 2>/dev/null)

if [ "$os" = "Darwin" ]
then
    if [ -x ./Spot-On.app/Contents/MacOS/Spot-On ]
    then
	export DYLD_LIBRARY_PATH=../libNTRU
	./Spot-On.app/Contents/MacOS/Spot-On "$@"
	exit $?
    else
	echo "Could not locate ./Spot-On.app/Contents/MacOS/Spot-On."
	exit 1
    fi
fi

if [ -r /opt/spot-on/Spot-On ] && [ -x /opt/spot-on/Spot-On ]
then
    export LD_LIBRARY_PATH=/opt/spot-on/Lib
    export QT_AUTO_SCREEN_SCALE_FACTOR=1

    if [ ! -z "$(which qt6ct)" ]
    then
	echo "Exporting QT_QPA_PLATFORMTHEME as qt6ct."

	export QT_QPA_PLATFORMTHEME=qt6ct
    fi

    # Disable https://en.wikipedia.org/wiki/MIT-SHM.

    export QT_X11_NO_MITSHM=1

    cd /opt/spot-on && ./Spot-On "$@"
    exit $?
else
    echo "Could not locate /opt/spot-on/Spot-On."
    exit 1
fi
