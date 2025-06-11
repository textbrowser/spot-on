#!/usr/bin/env bash

# Alexis Megas.

if [ ! -x /usr/bin/dpkg-deb ]; then
    echo "Please install dpkg-deb."
    exit 1
fi

if [ ! -x /usr/bin/fakeroot ]; then
    echo "Please install fakeroot."
    exit 1
fi

# Preparing ./opt/spot-on:

make distclean 2>/dev/null
mkdir -p ./opt/spot-on/Documentation
mkdir -p ./opt/spot-on/Lib
mkdir -p ./opt/spot-on/SQL
mkdir -p ./opt/spot-on/Sounds
mkdir -p ./opt/spot-on/Translations
qmake -o Makefile spot-on.powerpc.pro
lupdate spot-on.powerpc.pro 2>/dev/null
lrelease spot-on.powerpc.pro 2>/dev/null
make -j $(nproc)
cp -p ../../libNTL/unix.d/src/.libs/libntl.so* ./opt/spot-on/Lib/.
cp -p ../../libNTRU/libntru.so ./opt/spot-on/Lib/.
cp -p ./Data/spot-on-neighbors.txt ./opt/spot-on/.
cp -p ./Icons/Logo/spot-on-logo.png ./opt/spot-on/.
cp -p ./SQL/* ./opt/spot-on/SQL/.
cp -p ./Shell/spot-on-git.sh ./opt/spot-on/.
cp -p ./Shell/spot-on-kernel.sh ./opt/spot-on/.
cp -p ./Shell/spot-on.sh ./opt/spot-on/.
cp -p ./Sounds/* ./opt/spot-on/Sounds/.
cp -p ./Spot-On ./opt/spot-on/.
cp -p ./Spot-On-Kernel ./opt/spot-on/.
cp -p ./Translations/*.qm ./opt/spot-on/Translations/.
cp -pr ./Documentation/* ./opt/spot-on/Documentation/.
chmod -x ./opt/spot-on/Lib/lib*
find ./opt/spot-on -type f -exec chmod g+w {} \;
rm ./opt/spot-on/Documentation/*.qrc

# Preparing Spot-On-2025.06.27_powerpc.deb:

mkdir -p spot-on-debian/opt
mkdir -p spot-on-debian/usr/share/applications
cp -p ./Distributions/spot-on.desktop spot-on-debian/usr/share/applications/.
cp -pr ./DEBIAN-POWERPC spot-on-debian/DEBIAN
cp -r ./opt/spot-on spot-on-debian/opt/.
fakeroot dpkg-deb --build spot-on-debian Spot-On-2025.06.27_powerpc.deb
make distclean
rm -fr ./opt
rm -fr ./spot-on-debian
