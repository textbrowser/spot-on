#!/usr/bin/env sh
# Alexis Megas.

if [ -r /opt/spot-on/Spot-On-Kernel ] && [ -x /opt/spot-on/Spot-On-Kernel ]
then
    export LD_LIBRARY_PATH=/opt/spot-on/Lib
    cd /opt/spot-on && exec ./Spot-On-Kernel \
			    --disable-mail \
			    --disable-starbeam \
			    --disable-ui-server \
			    --passphrase \
			    "$@"
    exit $?
else
    echo "Could not locate /opt/spot-on/Spot-On-Kernel."
    exit 1
fi
