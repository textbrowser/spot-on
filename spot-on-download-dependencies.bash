#!/usr/bin/env bash
# Alexis Megas.

# Download and install dependencies for Windows.
# Must be executed in the top-level source directory.

# CURL

curl=curl-8.1.0_1-win32-mingw
dlcurl=dl-8.1.0_1

rm -f $curl.zip
rm -fr $curl
wget --progress=bar \
     https://curl.se/windows/$dlcurl/$curl.zip

if [ -r "$curl.zip" ]; then
    unzip -q $curl.zip -d curl-temporary.d
    mkdir -p libcURL/Win32.d/bin
    mkdir -p libcURL/Win32.d/include/curl
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

# GeoIP

geoip=mingw-w64-i686-geoip-1.6.12-1-any.pkg.tar.xz

rm -f $geoip
wget --output-document=$geoip \
     --progress=bar \
     https://repo.msys2.org/mingw/i686/$geoip

if [ -r "$geoip" ]; then
    tar -vxf $geoip
    mkdir -p libGeoIP/Include.win32
    mkdir -p libGeoIP/Libraries.win32
    mv mingw32/bin/*.dll libGeoIP/Libraries.win32/.
    mv mingw32/include/*.h libGeoIP/Include.win32/.
    chmod +w,-x libGeoIP/Libraries.win32/*.dll*
    rm -fr .BUILDINFO .MTREE .PKGINFO mingw32
    rm -f $geoip
else
    echo "Cannot read $geoip."
fi

# OpenSSL 1.1.1

openssl=openssl-1.1.1t.zip

# openssl=mingw-w64-i686-openssl-1.1.1.s-1-any.pkg.tar.zst

rm -f $openssl
wget --output-document=$openssl \
     --progress=bar \
     https://download.firedaemon.com/FireDaemon-OpenSSL/$openssl

if [ -r "$openssl" ]; then
    unzip $openssl
    mkdir -p libOpenSSL/Include.win32
    mkdir -p libOpenSSL/Libraries.win32
    rm -rf libOpenSSL/Include.win32/openssl
    mv openssl-1.1/x86/bin/libcrypto-1_1.dll libOpenSSL/Libraries.win32/.
    mv openssl-1.1/x86/bin/libssl-1_1.dll libOpenSSL/Libraries.win32/.
    mv openssl-1.1/x86/include/openssl libOpenSSL/Include.win32/.
    chmod +w,-x libOpenSSL/Libraries.win32/*.dll
    rm -f $openssl
    rm -fr openssl-1.1
else
    echo "Cannot read $openssl."
fi

# PostgreSQL

postgresql=postgresql.zip

rm -f $postgresql
wget --output-document=$postgresql \
     --progress=bar \
     "https://get.enterprisedb.com/postgresql/postgresql-10.23-1-windows-binaries.zip"

if [ -r $postgresql ]; then
    unzip -q $postgresql
    mkdir -p PostgreSQL/Libraries.win32
    mkdir -p PostgreSQL/Include.win32
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
