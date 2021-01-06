#!/bin/sh

date=$(date "+%Y%m%d")

pg_dump -U postgres \
	--clean --file=/disk0/spot-on.d/spot-on-user-db.$date.sql spot_on_user_db
pg_dumpall -U postgres \
	   --clean --globals-only --file=/disk0/spot-on.d/globals.$date.sql
gzip --force --keep /disk0/spot-on.d/spot-on-user-db.$date.sql
