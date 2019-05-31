#!/bin/bash

# Must be executed in the top-level source directory.

# CURL

curl=curl-7.65.0_1-win32-mingw

rm -f $curl.zip
rm -fr $curl
wget --progress=bar \
     https://curl.haxx.se/windows/dl-7.65.0_1/$curl.zip
unzip $curl.zip -d curl-temporary.d
mv curl-temporary.d/*/bin/curl-ca-bundle.crt libcURL/.
mv curl-temporary.d/*/bin/libcurl.dll libcURL/Win32.d/bin/.
mv curl-temporary.d/*/include/curl/*.h libcURL/Win32.d/include/curl/.
rm -f $curl.zip
rm -fr curl-temporary.d

# OpenSSL

openssl=openssl-1.1.1c-win32-mingw

rm -f $openssl.zip
rm -fr $openssl
wget --output-document=$openssl.zip \
     --progress=bar \
     https://bintray.com/vszakats/generic/download_file?file_path=$openssl.zip
unzip -o $openssl.zip
mv $openssl/libcrypto-1_1.dll libOpenSSL/Libraries.win32/.
mv $openssl/libssl-1_1.dll libOpenSSL/Libraries.win32/.
mv $openssl/include/openssl/*.h libOpenSSL/Include.win32/openssl/.
chmod +w libOpenSSL/Include.win32/openssl/*.h
chmod +w,-x libOpenSSL/Libraries.win32/*.dll
rm -f $openssl.zip
rm -fr $openssl

# PostgreSQL

postgresql=postgresql.zip

rm -f $postgresql
wget --output-document=$postgresql \
     --progress=bar \
     "https://get.enterprisedb.com/postgresql/postgresql-9.6.13-1-windows-binaries.zip"
unzip $postgresql
mv pgsql/bin/libeay32.dll PostgreSQL/Libraries.win32/.
mv pgsql/bin/libiconv-2.dll PostgreSQL/Libraries.win32/.
mv pgsql/bin/libintl-8.dll PostgreSQL/Libraries.win32/.
mv pgsql/bin/libpq.dll PostgreSQL/Libraries.win32/.
mv pgsql/bin/libxml2.dll PostgreSQL/Libraries.win32/.
mv pgsql/bin/libxslt.dll PostgreSQL/Libraries.win32/.
mv pgsql/include/libpq-fe.h PostgreSQL/Include.win32/.
mv pgsql/include/pg_config_ext.h PostgreSQL/Include.win32/.
mv pgsql/include/postgres_ext.h PostgreSQL/Include.win32/.
chmod -x PostgreSQL/Include.win32/*.h
chmod -x PostgreSQL/Libraries.win32/*.dll
rm -f $postgresql
rm -fr pgsql

# SQLite Binaries

sqlite=sqlite-dll-win32-x86-3280000.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2019/$sqlite
unzip -o $sqlite
mv sqlite3.def sqlite3.dll libSpotOn/Libraries.win32/.
chmod -x libSpotOn/Libraries.win32/*.dll
rm -f $sqlite

# SQLite Source

sqlite=sqlite-amalgamation-3280000.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2019/$sqlite
unzip -o $sqlite
rm -f $sqlite

sqlite=sqlite-amalgamation-3280000

mv $sqlite/*.h libSpotOn/Include.win32/.
rm -fr $sqlite
