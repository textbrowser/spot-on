#!/bin/bash

# Download and install dependencies for Windows.
# Must be executed in the top-level source directory.

# CURL

curl=curl-7.80.0-win32-mingw
dlcurl=dl-7.80.0

rm -f $curl.zip
rm -fr $curl
wget --progress=bar \
     https://curl.se/windows/$dlcurl/$curl.zip

if [ -r "$curl.zip" ]; then
    unzip -q $curl.zip -d curl-temporary.d
    mv curl-temporary.d/*/bin/curl-ca-bundle.crt libcURL/.
    mv curl-temporary.d/*/bin/libcurl.dll libcURL/Win32.d/bin/.
    mv curl-temporary.d/*/include/curl/*.h libcURL/Win32.d/include/curl/.
    rm -f $curl.zip
    rm -fr curl-temporary.d
else
    echo "Cannot read $curl."
fi

# GCrypt

gcrypt=mingw-w64-i686-libgcrypt-1.9.4-1-any.pkg.tar.zst

rm -f $gcrypt
wget --output-document=$gcrypt \
     --progress=bar \
     https://repo.msys2.org/mingw/i686/$gcrypt

if [ -r "$gcrypt" ]; then
    tar -I zstd -vxf $gcrypt
    mv mingw32/bin/*.dll libSpotOn/Libraries.win32/.
    mv mingw32/include/*.h libSpotOn/Include.win32/.
    chmod +w,-x libSpotOn/Libraries.win32/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw32
    rm -f $gcrypt
else
    echo "Cannot read $gcrypt."
fi

# GPG-Error

gpgerror=mingw-w64-i686-libgpg-error-1.43-1-any.pkg.tar.zst

rm -f $gpgerror
wget --output-document=$gpgerror \
     --progress=bar \
     https://repo.msys2.org/mingw/i686/$gpgerror

if [ -r "$gpgerror" ]; then
    tar -I zstd -vxf $gpgerror
    mv mingw32/bin/*.dll libSpotOn/Libraries.win32/.
    mv mingw32/include/gpg-error.h libSpotOn/Include.win32/.
    chmod +w,-x libSpotOn/Libraries.win32/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw32
    rm -f $gpgerror
else
    echo "Cannot read $gpgerror."
fi

# GeoIP

geoip=mingw-w64-i686-geoip-1.6.12-1-any.pkg.tar.xz

rm -f $geoip
wget --output-document=$geoip \
     --progress=bar \
     https://repo.msys2.org/mingw/i686/$geoip

if [ -r "$geoip" ]; then
    tar -vxf $geoip
    mv mingw32/bin/*.dll libGeoIP/Libraries.win32/.
    mv mingw32/include/*.h libGeoIP/Include.win32/.
    chmod +w,-x libGeoIP/Libraries.win32/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw32
    rm -f $geoip
else
    echo "Cannot read $geoip."
fi

# OpenSSL 1.1.1

openssl=mingw-w64-i686-openssl-1.1.1.l-1-any.pkg.tar.zst

rm -f $openssl
wget --output-document=$openssl \
     --progress=bar \
     https://repo.msys2.org/mingw/i686/$openssl

if [ -r "$openssl" ]; then
    tar -I zstd -vxf $openssl
    rm -rf libOpenSSL/Include.win32/openssl
    mv mingw32/bin/libcrypto-1_1.dll libOpenSSL/Libraries.win32/.
    mv mingw32/bin/libssl-1_1.dll libOpenSSL/Libraries.win32/.
    mv mingw32/include/openssl libOpenSSL/Include.win32/.
    chmod +w,-x libOpenSSL/Libraries.win32/*.dll
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw32
    rm -f $openssl
else
    echo "Cannot read $openssl."
fi

# PostgreSQL

postgresql=postgresql.zip

rm -f $postgresql
wget --output-document=$postgresql \
     --progress=bar \
     "https://get.enterprisedb.com/postgresql/postgresql-10.19-1-windows-binaries.zip"

if [ -r $postgresql ]; then
    unzip -q $postgresql
    mv pgsql/bin/libiconv-2.dll PostgreSQL/Libraries.win32/.
    mv pgsql/bin/libintl-8.dll PostgreSQL/Libraries.win32/.
    mv pgsql/bin/libpq.dll PostgreSQL/Libraries.win32/.
    mv pgsql/bin/libxml2.dll PostgreSQL/Libraries.win32/.
    mv pgsql/bin/libxslt.dll PostgreSQL/Libraries.win32/.
    mv pgsql/include/libpq-fe.h PostgreSQL/Include.win32/.
    mv pgsql/include/pg_config_ext.h PostgreSQL/Include.win32/.
    mv pgsql/include/postgres_ext.h PostgreSQL/Include.win32/.
    chmod +w,-x PostgreSQL/Include.win32/*.h
    chmod +w,-x PostgreSQL/Libraries.win32/*.dll
    rm -f $postgresql
    rm -fr pgsql
else
    echo "Cannot read $postgresql."
fi

# SQLite Binaries

sqlite=sqlite-dll-win32-x86-3370000.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2021/$sqlite

if [ -r $sqlite ]; then
    unzip -q -o $sqlite
    mv sqlite3.def sqlite3.dll libSpotOn/Libraries.win32/.
    chmod +w,-x libSpotOn/Libraries.win32/*.dll*
    rm -f $sqlite
else
    echo "Cannot read $sqlite."
fi

# SQLite Source

sqlite=sqlite-amalgamation-3370000.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2021/$sqlite

if [ -r $sqlite ]; then
    unzip -q -o $sqlite
    rm -f $sqlite
else
    echo "Cannot read $sqlite."
fi

sqlite=sqlite-amalgamation-3370000

if [ -r $sqlite ]; then
    mv $sqlite/*.h libSpotOn/Include.win32/.
    rm -fr $sqlite
else
    echo "Cannot read $sqlite."
fi
