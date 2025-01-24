#!/usr/bin/env sh
# Alexis Megas.

if [ -z ${GIT_A} ]
then
    echo "Please export the account (GIT_A)."
    exit 1
fi

if [ -z ${GIT_T} ]
then
    echo "Please export the token (GIT_T)."
    exit 1
fi

site=https://${GIT_A}:${GIT_T}@github.com/${GIT_A}/prison-blues

while
    git pull
    git push $site
    sleep 5
do true
done

exit 0
