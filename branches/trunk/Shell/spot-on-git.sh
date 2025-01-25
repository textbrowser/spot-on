#!/usr/bin/env sh
# Alexis Megas.

if [ -z ${GIT_A} ]
then
    echo "Please export GIT_A."
    exit 1
fi

if [ -z ${GIT_LOCAL_DIRECTORY} ]
then
    echo "Please export GIT_LOCAL_DIRECTORY."
    exit 1
fi

if [ -z ${GIT_SITE_CLONE} ]
then
    echo "Please export GIT_SITE_CLONE."
    exit 1
fi

if [ -z ${GIT_SITE_PUSH} ]
then
    echo "Please export GIT_SITE_PUSH."
    exit 1
fi

if [ -z ${GIT_T} ]
then
    echo "Please export GIT_T."
    exit 1
fi

local_directory="${GIT_LOCAL_DIRECTORY}"
site=$(eval "echo ${GIT_SITE_CLONE}")

git clone -q "$site" "$local_directory" 2>/dev/null

if [ ! $? -eq 0 ]
then
    if [ ! -r "$local_directory" ]
    then
	echo "Cloning of $site failed. Bye!"
	exit 1
    fi
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

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "GIT-ADD failure."
	    exit $rc
	fi

	git commit -m "New message(s)." 2>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "GIT-COMMIT failure."
	    exit $rc
	fi

	site=$(eval "echo ${GIT_SITE_PUSH}")

	git push "$site" 2>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "GIT-PUSH failure."
	    exit $rc
	fi
    else
	echo "GIT-PULL failure."
	exit 1
    fi
fi

exit 0
