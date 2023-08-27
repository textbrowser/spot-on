#!/usr/bin/env bash
# Alexis Megas.

# Download and install dependencies for Windows.
# Must be executed in the top-level source directory.

# GCrypt

gcrypt=mingw-w64-x86_64-libgcrypt-1.9.4-1-any.pkg.tar.zst

rm -f $gcrypt
wget --output-document=$gcrypt \
     --progress=bar \
     https://repo.msys2.org/mingw/mingw64/$gcrypt

if [ -r "$gcrypt" ]; then
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
fi

# GPG-Error

gpgerror=mingw-w64-x86_64-libgpg-error-1.47-2-any.pkg.tar.zst

rm -f $gpgerror
wget --output-document=$gpgerror \
     --progress=bar \
     https://repo.msys2.org/mingw/mingw64/$gpgerror

if [ -r "$gpgerror" ]; then
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
fi

# OpenSSL

openssl=openssl-3.1-zip

rm -f $openssl
wget --output-document=$openssl \
     --progress=bar \
     https://www.firedaemon.com/download-firedaemon-$openssl

if [ -r "$openssl" ]; then
    unzip $openssl
    mkdir -p libOpenSSL/Include.win64
    mkdir -p libOpenSSL/Libraries.win64
    rm -rf libOpenSSL/Include.win64/openssl
    mv openssl-*/x64/bin/libcrypto-3-x64.dll libOpenSSL/Libraries.win64/.
    mv openssl-*/x64/bin/libssl-3-x64.dll libOpenSSL/Libraries.win64/.
    mv openssl-*/x64/include/openssl libOpenSSL/Include.win64/.
    chmod +w,-x libOpenSSL/Libraries.win64/*.dll
    rm -f $openssl
    rm -fr openssl-3*
else
    echo "Cannot read $openssl."
fi
