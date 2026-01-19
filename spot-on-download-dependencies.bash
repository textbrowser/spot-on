#!/usr/bin/env bash

# Alexis Megas.

# Download dependencies for Windows.
# Must be executed in the top-level source directory.

if [ "$(which wget)" = "" ]
then
    echo "Could not locate wget."
    exit 1
fi

msys2=https://repo.msys2.org/mingw/mingw64
rc=0

# Assuan

assuan=mingw-w64-x86_64-libassuan-2.5.7-1-any.pkg.tar.zst

rm -f "$assuan"
wget --output-document="$assuan" --progress=bar "$msys2/$assuan"

rc=$?

if [ $rc -eq 0 ] && [ -r "$assuan" ]
then
    tar -I zstd -vxf "$assuan"
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

gcrypt=mingw-w64-x86_64-libgcrypt-1.11.2-1-any.pkg.tar.zst

rm -f "$gcrypt"
wget --output-document="$gcrypt" --progress=bar "$msys2/$gcrypt"

rc=$?

if [ $rc -eq 0 ] && [ -r "$gcrypt" ]
then
    tar -I zstd -vxf "$gcrypt"
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

gpgerror=mingw-w64-x86_64-libgpg-error-1.55-1-any.pkg.tar.zst

rm -f "$gpgerror"
wget --output-document="$gpgerror" --progress=bar "$msys2/$gpgerror"

rc=$?

if [ $rc -eq 0 ] && [ -r "$gpgerror" ]
then
    tar -I zstd -vxf "$gpgerror"
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

gpgme=mingw-w64-x86_64-gpgme-1.23.2-11-any.pkg.tar.zst

rm -f "$gpgme"
wget --output-document="$gpgme" --progress=bar "$msys2/$gpgme"

rc=$?

if [ $rc -eq 0 ] && [ -r "$gpgme" ]
then
    tar -I zstd -vxf "$gpgme"
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

openssl=openssl-3-6-zip

rm -f "$openssl"
wget --output-document="$openssl" \
     --progress=bar \
     "https://www.firedaemon.com/download-firedaemon-$openssl"

rc=$?

if [ $rc -eq 0 ] && [ -r "$openssl" ]
then
    rm -fr openssl.d
    unzip "$openssl" -d openssl.d
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

rm -f "$openssl"
exit $rc
