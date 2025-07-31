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
mkdir -p ./opt/spot-on/Translations

if [ ! -z "$(which qmake)" ]; then
    qmake -o Makefile spot-on.arm.pro
else
    qmake6 -o Makefile spot-on.arm.pro
fi

lupdate spot-on.arm.pro 2>/dev/null
lrelease spot-on.arm.pro 2>/dev/null
make -j $(nproc)
cp -p ../../libNTRU/libntru.so ./opt/spot-on/Lib/.
cp -p ./Data/spot-on-neighbors.txt ./opt/spot-on/.
cp -p ./Icons/Logo/spot-on-logo.png ./opt/spot-on/.
cp -p ./SQL/* ./opt/spot-on/SQL/.
cp -p ./Shell/spot-on-git.sh ./opt/spot-on/.
cp -p ./Shell/spot-on-kernel.sh ./opt/spot-on/.
cp -p ./Shell/spot-on.sh ./opt/spot-on/.
cp -p ./Spot-On ./opt/spot-on/.
cp -p ./Spot-On-Kernel ./opt/spot-on/.
cp -p ./Translations/*.qm ./opt/spot-on/Translations/.
cp -pr ./Documentation/* ./opt/spot-on/Documentation/.
chmod -x ./opt/spot-on/Lib/lib*
find ./opt/spot-on -type f -exec chmod g+w {} \;
rm ./opt/spot-on/Documentation/*.qrc

# Preparing Spot-On-2025.07.04_$architecture.deb:

architecture="$(dpkg --print-architecture)"

mkdir -p spot-on-debian/opt
mkdir -p spot-on-debian/usr/share/applications
cp -p ./Distributions/spot-on.desktop spot-on-debian/usr/share/applications/.

if [ "$architecture" = "armhf" ]; then
    cp -pr ./DEBIAN-ARM spot-on-debian/DEBIAN
else
    cp -pr ./DEBIAN-ARM64 spot-on-debian/DEBIAN
fi

cp -r ./opt/spot-on spot-on-debian/opt/.
fakeroot dpkg-deb --build spot-on-debian Spot-On-2025.07.04_$architecture.deb
make distclean
rm -fr ./opt
rm -fr ./spot-on-debian
