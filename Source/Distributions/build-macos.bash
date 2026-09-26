#!/usr/bin/env bash
# Alexis Megas.

if [ ! -e spot-on.macos.pro ]
then
    echo "Please issue $0 from the primary directory."
    exit 1
fi

make distclean 2>/dev/null

qmake="$(echo ~/Qt/6.8.3/macos/bin/qmake)"

if [ ! -x "$qmake" ]
then
    qmake="$(echo ~/Qt/6.11.1/macos/bin/qmake)"
fi

if [ -x "$qmake" ]
then
    $qmake -o Makefile spot-on.macos.pro
else
    echo "Cannot locate $qmake."
    echo "Please install the official Qt."
    exit 1
fi

make -j $(sysctl -n hw.ncpu)
/bin/echo -n "Issuing a make install... "
make install 1>/dev/null 2>/dev/null

if [ $? -eq 0 ]
then
    echo "OK!"
else
    echo "Failure on make-install. Bye!"
    exit 1
fi

declare -a packages=("./Spot-On.d/Spot-On.app"
		     "./Spot-On.d/Spot-On-Kernel.app"
		     "./Spot-On.d/Spot-On-Web-Server-Child.app")

for i in "${packages[@]}"
do
    /bin/echo -n "Signing $i... "
    codesign --deep --force -s "textbrowser" "$i" 2>/dev/null

    if [ $? -eq 0 ]
    then
	echo "OK."
    else
	echo "Problem! Continuing."
    fi
done

echo "Generating the DMG."
make dmg 2>/dev/null

if [ ! -r Spot-On.d.dmg ]
then
    echo "Spot-On.d.dmg is not a readable file."
    exit 1
fi

if [ "$(uname -m)" = "arm64" ]
then
    mv Spot-On.d.dmg Spot-On-2026.09.25_ARM64.d.dmg
else
    mv Spot-On.d.dmg Spot-On-2026.09.25_X86-64.d.dmg
fi

make distclean 2>/dev/null
rm -fr ./Spot-On.d
