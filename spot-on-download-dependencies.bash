#!/usr/bin/env bash
# Alexis Megas.

# Download and install dependencies for Windows.
# Must be executed in the top-level source directory.

# GCrypt

gcrypt=mingw-w64-i686-libgcrypt-1.9.4-1-any.pkg.tar.zst

rm -f $gcrypt
wget --output-document=$gcrypt \
     --progress=bar \
     https://repo.msys2.org/mingw/i686/$gcrypt

if [ -r "$gcrypt" ]; then
    tar -I zstd -vxf $gcrypt
    mkdir -p libSpotOn/Include.win32
    mkdir -p libSpotOn/Libraries.win32
    mv mingw32/bin/*.dll libSpotOn/Libraries.win32/.
    mv mingw32/include/*.h libSpotOn/Include.win32/.
    chmod +w,-x libSpotOn/Libraries.win32/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw32
    rm -f $gcrypt
else
    echo "Cannot read $gcrypt."
fi

# GPG-Error

gpgerror=mingw-w64-i686-libgpg-error-1.47-1-any.pkg.tar.zst

rm -f $gpgerror
wget --output-document=$gpgerror \
     --progress=bar \
     https://repo.msys2.org/mingw/i686/$gpgerror

if [ -r "$gpgerror" ]; then
    tar -I zstd -vxf $gpgerror
    mkdir -p libSpotOn/Include.win32
    mkdir -p libSpotOn/Libraries.win32
    mv mingw32/bin/*.dll libSpotOn/Libraries.win32/.
    mv mingw32/include/gpg-error.h libSpotOn/Include.win32/.
    chmod +w,-x libSpotOn/Libraries.win32/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw32
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

# SQLite Binaries

sqlite=sqlite-dll-win32-x86-3420000.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2023/$sqlite

if [ -r $sqlite ]; then
    unzip -q -o $sqlite
    mkdir -p libSpotOn/Libraries.win32
    mv sqlite3.def sqlite3.dll libSpotOn/Libraries.win32/.
    chmod +w,-x libSpotOn/Libraries.win32/*.dll*
    rm -f $sqlite
else
    echo "Cannot read $sqlite."
fi

# SQLite Source

sqlite=sqlite-amalgamation-3420000.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2023/$sqlite

if [ -r $sqlite ]; then
    unzip -q -o $sqlite
    rm -f $sqlite
else
    echo "Cannot read $sqlite."
fi

sqlite=sqlite-amalgamation-3420000

if [ -r $sqlite ]; then
    mkdir -p libSpotOn/Include.win32
    mv $sqlite/*.h libSpotOn/Include.win32/.
    rm -fr $sqlite
else
    echo "Cannot read $sqlite."
fi
