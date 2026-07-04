#!/usr/bin/env bash

# Alexis Megas.

# Download dependencies for Windows.
# Must be executed in the top-level source directory.

if [ "$(which wget)" = "" ]
then
    echo "Could not locate wget."
    exit 1
fi

mingw64="mingw64.html"
msys2=https://repo.msys2.org/mingw/mingw64
rc=0

echo "Downloading $msys2."
rm -f "$mingw64"
wget --output-document="$mingw64" \
     --progress=bar \
     --quiet \
     https://repo.msys2.org/mingw/mingw64

rc=$?

if [ ! $rc -eq 0 ]
then
    echo "The command wget failed."
    exit $rc
fi

# Assuan

assuan="$(cat "$mingw64" | grep mingw-w64-x86_64-libassuan | \
	  grep -Po '"\K[^"]+' | \
	  sort --version-sort | grep '^m' | tail -2 | head -1)"

if [ -z "$assuan" ]
then
    echo "Cannot find assuan name."
    rm -fr "$mingw64"
    exit 1
fi

echo "Downloading $assuan."
rm -f "$assuan"
wget --output-document="$assuan" --progress=bar --quiet "$msys2/$assuan"

rc=$?

if [ $rc -eq 0 ] && [ -r "$assuan" ]
then
    tar -I zstd -vxf "$assuan" 1>/dev/null
    mkdir -p libAssuan/Libraries.win64
    mv mingw64/bin/*.dll libAssuan/Libraries.win64/.
    chmod +w,-x libAssuan/Libraries.win64/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw64
elif [ $rc -eq 0 ]
then
    echo "Cannot read $assuan."

    rc=1
fi

rm -f "$assuan"

# GCrypt

gcrypt="$(cat "$mingw64" | grep mingw-w64-x86_64-libgcrypt | \
	  grep -Po '"\K[^"]+' | \
	  sort --version-sort | grep '^m' | tail -2 | head -1)"

if [ -z "$gcrypt" ]
then
    echo "Cannot find gcrypt name."
    rm -fr "$mingw64"
    exit 1
fi

echo "Downloading $gcrypt."
rm -f "$gcrypt"
wget --output-document="$gcrypt" --progress=bar --quiet "$msys2/$gcrypt"

rc=$?

if [ $rc -eq 0 ] && [ -r "$gcrypt" ]
then
    tar -I zstd -vxf "$gcrypt" 1>/dev/null
    mkdir -p libGCrypt/Include.win64
    mkdir -p libGCrypt/Libraries.win64
    mv mingw64/bin/*.dll libGCrypt/Libraries.win64/.
    mv mingw64/include/*.h libGCrypt/Include.win64/.
    chmod +w,-x libGCrypt/Libraries.win64/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw64
elif [ $rc -eq 0 ]
then
    echo "Cannot read $gcrypt."

    rc=1
fi

rm -f "$gcrypt"

# GPG-Error

gpgerror="$(cat "$mingw64" | grep mingw-w64-x86_64-libgpg-error | \
	    grep -Po '"\K[^"]+' | \
	    sort --version-sort | grep '^m' | tail -2 | head -1)"

if [ -z "$gcrypt" ]
then
    echo "Cannot find gpgerror name."
    rm -fr "$mingw64"
    exit 1
fi

echo "Downloading $gpgerror."
rm -f "$gpgerror"
wget --output-document="$gpgerror" --progress=bar --quiet "$msys2/$gpgerror"

rc=$?

if [ $rc -eq 0 ] && [ -r "$gpgerror" ]
then
    tar -I zstd -vxf "$gpgerror" 1>/dev/null
    mkdir -p libGCrypt/Include.win64
    mkdir -p libGCrypt/Libraries.win64
    mv mingw64/bin/*.dll libGCrypt/Libraries.win64/.
    mv mingw64/include/gpg-error.h libGCrypt/Include.win64/.
    chmod +w,-x libGCrypt/Libraries.win64/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw64
elif [ $rc -eq 0 ]
then
    echo "Cannot read $gpgerror."

    rc=1
fi

rm -f $gpgerror

# GPG-ME

gpgme="$(cat "$mingw64" | grep mingw-w64-x86_64-gpgme | \
	 grep -Po '"\K[^"]+' | \
         sort --version-sort | grep '^m' | tail -2 | head -1)"

if [ -z "$gpgme" ]
then
    echo "Cannot find gpgme name."
    rm -fr "$mingw64"
    exit 1
fi

echo "Downloading $gpgme."
rm -f "$gpgme"
wget --output-document="$gpgme" --progress=bar --quiet "$msys2/$gpgme"

rc=$?

if [ $rc -eq 0 ] && [ -r "$gpgme" ]
then
    tar -I zstd -vxf "$gpgme" 1>/dev/null
    mkdir -p libGPGME/Executables.win64
    mkdir -p libGPGME/Include.win64
    mkdir -p libGPGME/Libraries.win64
    mv mingw64/bin/*.dll libGPGME/Libraries.win64/.
    mv mingw64/bin/*.exe libGPGME/Executables.win64/.
    mv mingw64/include/gpgme.h libGPGME/Include.win64/.
    chmod +w,-x libGPGME/Libraries.win64/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw64
elif [ $rc -eq 0 ]
then
    echo "Cannot read $gpgme."

    rc=1
fi

rm -f "$gpgme"

# OpenSSL

openssl=openssl-3.6.2.zip

echo "Downloading $openssl."
rm -f "$openssl"
wget --output-document="$openssl" \
     --progress=bar \
     --quiet \
     "https://download.firedaemon.com/FireDaemon-OpenSSL/$openssl"

rc=$?

if [ $rc -eq 0 ] && [ -r "$openssl" ]
then
    rm -fr openssl.d
    unzip "$openssl" -d openssl.d 1>/dev/null
    mkdir -p libOpenSSL/Executables.win64
    mkdir -p libOpenSSL/Include.win64
    mkdir -p libOpenSSL/Libraries.win64
    rm -rf libOpenSSL/Include.win64/openssl
    mv openssl.d/x64/bin/libcrypto-3-x64.dll libOpenSSL/Libraries.win64/.
    mv openssl.d/x64/bin/libssl-3-x64.dll libOpenSSL/Libraries.win64/.
    mv openssl.d/x64/bin/openssl.exe libOpenSSL/Executables.win64/.
    mv openssl.d/x64/include/openssl libOpenSSL/Include.win64/.
    chmod +w,-x libOpenSSL/Libraries.win64/*.dll
    rm -fr openssl.d
elif [ $rc -eq 0 ]
then
    echo "Cannot read $openssl."

    rc=1
fi

rm -f "$mingw64"
rm -f "$openssl"
exit $rc
