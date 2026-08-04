#!/usr/bin/env sh

# Alexis Megas.

date=$(date "+%Y%m%d")
rc=0

echo "Exporting the PostgreQL database spot-on-user-db via pg_dump."
pg_dump -U postgres \
	--clean \
	--file=spot-on-user-db.$date.sql spot_on_user_db 2>/dev/null 1>&2

rc=$?

if [ ! $rc -eq 0 ]
then
    echo "Failure with pg_dump."
    exit $rc
fi

echo "Exporting global objects (roles and tables) via pg_dumpall."
pg_dumpall -U postgres \
	   --clean \
	   --globals-only \
	   --file=globals.$date.sql 2>/dev/null 1>&2

rc=$?

if [ ! $rc -eq 0 ]
then
    echo "Failure with pg_dumpall."
    exit $rc
fi

echo "Compressing spot-on-user-db.$date.sql via gzip."
gzip --force --keep spot-on-user-db.$date.sql 2>/dev/null 1>&2

rc=$?

if [ ! $rc -eq 0 ]
then
    echo "Failure with gzip."
    exit $rc
fi

echo "Setting permissions on globals.$date.sql, spot-on-user-db.$date.sql."
chmod -rw globals.$date.sql spot-on-user-db.$date.sql 2>/dev/null 1>&2

rc=$?

if [ ! $rc -eq 0 ]
then
    echo "Failure with chmod."
    exit $rc
fi

exit $rc
