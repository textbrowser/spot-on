#!/usr/bin/env sh
# Alexis Megas.

local_directory="/var/tmp/prison-blues.d"
site="https://github.com/textbrowser/prison-blues"

git clone -q "$site" "$local_directory" 2>/dev/null

if [ ! $? -eq 0 ]
then
    if [ ! -r "$local_directory" ]
    then
	echo "Cloning of $site failed. Bye!"
	exit 1
    fi
fi

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

cd $local_directory

if [ ! $? -eq 0 ]
then
    echo "No! Cannot proceed to $local_directory."
    exit 1
else
    git pull 2>/dev/null

    if [ $? -eq 0 ]
    then
	git add . 2>/dev/null
	git commit -m "New message(s)." 2>/dev/null

	site="https://${GIT_A}:${GIT_T}@github.com/${GIT_A}/prison-blues"

	git push "$site" 2>/dev/null
	exit 0
    else
	exit 1
    fi
fi

exit 0
