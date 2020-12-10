#!/bin/bash

# Download dependencies for Windows.
# Must be executed in the top-level source directory.

# CURL

curl=curl-7.74.0-win32-mingw
dlcurl=dl-7.74.0

rm -f $curl.zip
rm -fr $curl
wget --progress=bar \
     https://curl.haxx.se/windows/$dlcurl/$curl.zip

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

# OpenSSL 1.1.1

openssl=openssl-1.1.1h-win32-mingw

rm -f $openssl.zip
rm -fr $openssl
rm -fr libOpenSSL/Include.win32/openssl
wget --output-document=$openssl.zip \
     --progress=bar \
     https://bintray.com/vszakats/generic/download_file?file_path=$openssl.zip

if [ -r "$openssl.zip" ]; then
    unzip -q -o $openssl.zip
    mv $openssl/include/openssl libOpenSSL/Include.win32/.
    mv $openssl/libcrypto-1_1.dll libOpenSSL/Libraries.win32/.
    mv $openssl/libssl-1_1.dll libOpenSSL/Libraries.win32/.
    chmod +w,-x libOpenSSL/Libraries.win32/*.dll
    rm -f $openssl.zip
    rm -fr $openssl
else
    echo "Cannot read $openssl.zip."
fi

# PostgreSQL

postgresql=postgresql.zip

rm -f $postgresql
wget --output-document=$postgresql \
     --progress=bar \
     "https://get.enterprisedb.com/postgresql/postgresql-9.6.20-1-windows-binaries.zip"

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

sqlite=sqlite-dll-win32-x86-3340000.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2020/$sqlite

if [ -r $sqlite ]; then
    unzip -q -o $sqlite
    mv sqlite3.def sqlite3.dll libSpotOn/Libraries.win32/.
    chmod +w,-x libSpotOn/Libraries.win32/*.dll*
    rm -f $sqlite
else
    echo "Cannot read $sqlite."
fi

# SQLite Source

sqlite=sqlite-amalgamation-3340000.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2020/$sqlite

if [ -r $sqlite ]; then
    unzip -q -o $sqlite
    rm -f $sqlite
else
    echo "Cannot read $sqlite."
fi

sqlite=sqlite-amalgamation-3340000

if [ -r $sqlite ]; then
    mv $sqlite/*.h libSpotOn/Include.win32/.
    rm -fr $sqlite
else
    echo "Cannot read $sqlite."
fi
