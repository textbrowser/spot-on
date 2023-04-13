#!/usr/bin/env sh

date=$(date "+%Y%m%d")

pg_dump -U postgres --clean --file=spot-on-user-db.$date.sql spot_on_user_db
pg_dumpall -U postgres --clean --globals-only --file=globals.$date.sql
gzip --force --keep spot-on-user-db.$date.sql
