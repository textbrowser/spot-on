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

if [ ! -r "$local_directory" ]
then
    site=$(eval "echo ${GIT_SITE_CLONE}")

    git clone -q "$site" "$local_directory" 2>/dev/null

    if [ ! $? -eq 0 ]
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
    # Merge.

    git config pull.rebase false 2>/dev/null

    # Pull?

    git pull 2>/dev/null

    if [ $? -eq 0 ]
    then
	rc=$(git ls-files --deleted --exclude-standard --others \
		 2>/dev/null | wc -l)

	if [ $rc -lt 1 ]
	then
	    echo "All set."
	    exit 0
	fi

	git add --all 2>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "GIT-ADD failure."
	    exit $rc
	fi

	git commit -m "New data." 2>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "GIT-COMMIT failure."
	    exit $rc
	fi

	git pull 2>/dev/null

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
