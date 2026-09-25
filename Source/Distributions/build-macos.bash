#!/usr/bin/env bash
# Alexis Megas.

if [ ! -e spot-on.macos.pro ]
then
    echo "Please issue $0 from the primary directory."
    exit 1
fi

make distclean 2>/dev/null

qmake="$(echo ~/Qt/6.8.3/macos/bin/qmake)"

if [ -x "$qmake" ]
then
    $qmake -o Makefile spot-on.macos.pro
else
    echo "Cannot locate $qmake."
    echo "Please install the official Qt."
    exit 1
fi

make -j $(sysctl -n hw.ncpu)
make install
codesign --deep --force -s "textbrowser" ./Spot-On.d/Spot-On.app
codesign --deep --force -s "textbrowser" ./Spot-On.d/Spot-On-Kernel.app
codesign --deep --force -s "textbrowser" \
	 ./Spot-On.d/Spot-On-Web-Server-Child.app
make dmg

if [ ! -r Spot-On.d.dmg ]
then
    echo "Spot-On.d.dmg is not a readable file."
    exit 1
fi

mv Spot-On.d.dmg Spot-On-2026.09.25_Universal.d.dmg
make distclean 2>/dev/null
rm -fr ./Spot-On.d
