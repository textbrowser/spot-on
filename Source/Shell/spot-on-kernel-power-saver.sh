#!/usr/bin/env sh

# Alexis Megas.

os=$(uname -o 2>/dev/null)

if [ "$os" = "Darwin" ]
then
    if [ -x ./Spot-On-Kernel.app/Contents/MacOS/Spot-On-Kernel ]
    then
	export DYLD_LIBRARY_PATH=../libNTRU
	./Spot-On-Kernel.app/Contents/MacOS/Spot-On-Kernel \
	    --disable-mail \
	    --disable-poptastic \
	    --disable-starbeam \
	    --disable-ui-server \
	    --passphrase \
	    "$@"
	exit $?
    else
	echo "Could not locate ./Spot-On-Kernel.app/" \
	     "Contents/MacOS/Spot-On-Kernel."
	exit 1
    fi
fi

if [ -r /opt/spot-on/Spot-On-Kernel ] && [ -x /opt/spot-on/Spot-On-Kernel ]
then
    export LD_LIBRARY_PATH=/opt/spot-on/Lib
    cd /opt/spot-on && ./Spot-On-Kernel \
		       --disable-mail \
		       --disable-poptastic \
		       --disable-starbeam \
		       --disable-ui-server \
		       --passphrase \
		       "$@"
    exit $?
else
    echo "Could not locate /opt/spot-on/Spot-On-Kernel."
    exit 1
fi
