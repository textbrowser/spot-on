#/bin/bash

# PostgreSQL

postgresql=postgresql.zip

rm -f $postgresql
wget --output-document=$postgresql \
     --progress=bar \
     "https://get.enterprisedb.com/postgresql/postgresql-9.6.12-1-windows-binaries.zip?ls=Crossover&type=Crossover&_ga=2.53582379.223986836.1553804077-504097994.1552479753"

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
rm -fr pgsql
rm -r $postgresql

# SQLite Binaries

sqlite=sqlite-dll-win32-x86-3270200.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2019/$sqlite
unzip -o $sqlite
mv sqlite3.def sqlite3.dll libSpotOn/Libraries.win32/.
rm -f $sqlite

# SQLite Source

sqlite=sqlite-amalgamation-3270200.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2019/$sqlite
unzip -o $sqlite
rm -f $sqlite

sqlite=sqlite-amalgamation-3270200

mv $sqlite/*.h libSpotOn/Include.win32/.
rm -fr $sqlite
