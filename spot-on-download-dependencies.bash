#/bin/bash

# SQLite Binaries

sqlite=sqlite-dll-win32-x86-3270200.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2019/$sqlite
unzip -o $sqlite
mv sqlite3.def sqlite3.dll ./libSpotOn/Libraries.win32/.
rm -f $sqlite

# SQLite Source

sqlite=sqlite-amalgamation-3270200.zip

rm -f $sqlite
wget --progress=bar https://sqlite.org/2019/$sqlite
unzip -o $sqlite
rm -f $sqlite

sqlite=sqlite-amalgamation-3270200

mv $sqlite/*.h ./libSpotOn/Include.win32/.
rm -fr $sqlite
