#!/usr/bin/env bash
# Alexis Megas.

if [ ! -x /usr/bin/dpkg-deb ]; then
    echo "Please install dpkg-deb."
    exit
fi

if [ ! -x /usr/bin/fakeroot ]; then
    echo "Please install fakeroot."
    exit 1
fi

# Preparing ./usr/local/spot-on:

make distclean 2>/dev/null
mkdir -p ./usr/local/spot-on/Documentation
mkdir -p ./usr/local/spot-on/Lib
mkdir -p ./usr/local/spot-on/SQL
mkdir -p ./usr/local/spot-on/Sounds
mkdir -p ./usr/local/spot-on/Translations
qmake -o Makefile spot-on.arm.pro && make -j $(nproc)
cp -p ../../libNTL/unix.d/src/.libs/libntl.so* ./usr/local/spot-on/Lib/.
cp -p ../../libNTRU/libntru.so ./usr/local/spot-on/Lib/.
cp -p ./Data/spot-on-neighbors.txt ./usr/local/spot-on/.
cp -p ./Icons/Logo/spot-on-logo.png ./usr/local/spot-on/.
cp -p ./SQL/* ./usr/local/spot-on/SQL/.
cp -p ./Shell/spot-on-kernel.sh ./usr/local/spot-on/.
cp -p ./Shell/spot-on.sh ./usr/local/spot-on/.
cp -p ./Sounds/* ./usr/local/spot-on/Sounds/.
cp -p ./Spot-On ./usr/local/spot-on/.
cp -p ./Spot-On-Kernel ./usr/local/spot-on/.
cp -p ./Translations/*.qm ./usr/local/spot-on/Translations/.
cp -pr ./Documentation/* ./usr/local/spot-on/Documentation/.
chmod -x ./usr/local/spot-on/Lib/lib*
find ./usr/local/spot-on -type f -exec chmod g+w {} \;
rm ./usr/local/spot-on/Documentation/*.qrc

# Preparing Spot-On-x_armhf.deb:

mkdir -p spot-on-debian/usr/local
mkdir -p spot-on-debian/usr/share/applications
cp -p ./spot-on.desktop spot-on-debian/usr/share/applications/.
cp -pr ./DEBIAN-ARM spot-on-debian/DEBIAN
cp -r ./usr/local/spot-on spot-on-debian/usr/local/.
fakeroot dpkg-deb --build spot-on-debian Spot-On-2022.11.11_armhf.deb
make distclean
rm -fr ./spot-on-debian
rm -fr ./usr
