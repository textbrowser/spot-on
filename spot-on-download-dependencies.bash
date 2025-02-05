#!/usr/bin/env bash
# Alexis Megas.

# Download dependencies for Windows.
# Must be executed in the top-level source directory.

if [ "$(which wget)" = "" ]
then
    echo "Could not locate wget."
    exit 1
fi

rc=0

# GCrypt

gcrypt=mingw-w64-x86_64-libgcrypt-1.11.0-2-any.pkg.tar.zst

rm -f $gcrypt
wget --output-document=$gcrypt \
     --progress=bar \
     https://repo.msys2.org/mingw/mingw64/$gcrypt

if [ -r "$gcrypt" ]
then
    tar -I zstd -vxf $gcrypt
    mkdir -p libGCrypt/Include.win64
    mkdir -p libGCrypt/Libraries.win64
    mv mingw64/bin/*.dll libGCrypt/Libraries.win64/.
    mv mingw64/include/*.h libGCrypt/Include.win64/.
    chmod +w,-x libGCrypt/Libraries.win64/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw64
    rm -f $gcrypt
else
    echo "Cannot read $gcrypt."
    rc=1
fi

# GPG-Error

gpgerror=mingw-w64-x86_64-libgpg-error-1.51-1-any.pkg.tar.zst

rm -f $gpgerror
wget --output-document=$gpgerror \
     --progress=bar \
     https://repo.msys2.org/mingw/mingw64/$gpgerror

if [ -r "$gpgerror" ]
then
    tar -I zstd -vxf $gpgerror
    mkdir -p libGCrypt/Include.win64
    mkdir -p libGCrypt/Libraries.win64
    mv mingw64/bin/*.dll libGCrypt/Libraries.win64/.
    mv mingw64/include/gpg-error.h libGCrypt/Include.win64/.
    chmod +w,-x libGCrypt/Libraries.win64/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw64
    rm -f $gpgerror
else
    echo "Cannot read $gpgerror."
    rc=1
fi

# GPG-ME

gpgme=mingw-w64-x86_64-gpgme-1.23.2-8-any.pkg.tar.zst

rm -f $gpgme
wget --output-document=$gpgme \
     --progress=bar \
     https://repo.msys2.org/mingw/mingw64/$gpgme

if [ -r "$gpgme" ]
then
    tar -I zstd -vxf $gpgme
    mkdir -p libGPGME/Include.win64
    mkdir -p libGPGME/Libraries.win64
    mv mingw64/bin/*.dll libGPGME/Libraries.win64/.
    mv mingw64/bin/*.exe libGPGME/Libraries.win64/.
    mv mingw64/include/gpgme.h libGPGME/Include.win64/.
    chmod +w,-x libGPGME/Libraries.win64/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw64
    rm -f $gpgme
else
    echo "Cannot read $gpgme."
    rc=1
fi

# OpenSSL

openssl=openssl-3-4-zip

rm -f $openssl
wget --output-document=$openssl \
     --progress=bar \
     https://www.firedaemon.com/download-firedaemon-$openssl

if [ -r "$openssl" ]
then
    unzip $openssl -d openssl.d
    mkdir -p libOpenSSL/Include.win64
    mkdir -p libOpenSSL/Libraries.win64
    rm -rf libOpenSSL/Include.win64/openssl
    mv openssl.d/x64/bin/libcrypto-3-x64.dll libOpenSSL/Libraries.win64/.
    mv openssl.d/x64/bin/libssl-3-x64.dll libOpenSSL/Libraries.win64/.
    mv openssl.d/x64/include/openssl libOpenSSL/Include.win64/.
    chmod +w,-x libOpenSSL/Libraries.win64/*.dll
    rm -f $openssl
    rm -fr openssl.d
else
    echo "Cannot read $openssl."
    rc=1
fi

echo $rc
