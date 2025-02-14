#!/usr/bin/env sh

# Alexis Megas.

# We will not correct GIT errors.

# If git has locked the local directory, a git command will fail.
# We will not remove the lock.

# If the local directory already exists, a git-clone will fail.
# We will not remove the local directory!

if [ -z ${GIT_A} ]
then
    echo "Please export GIT_A. Bye!"
    exit 1
fi

if [ -z ${GIT_LOCAL_DIRECTORY} ]
then
    echo "Please export GIT_LOCAL_DIRECTORY. Bye!"
    exit 1
fi

if [ -z ${GIT_SITE_CLONE} ]
then
    echo "Please export GIT_SITE_CLONE. Bye!"
    exit 1
fi

if [ -z ${GIT_SITE_PUSH} ]
then
    echo "Please export GIT_SITE_PUSH. Bye!"
    exit 1
fi

if [ -z ${GIT_T} ]
then
    echo "Please export GIT_T. Bye!"
    exit 1
fi

local_directory="${GIT_LOCAL_DIRECTORY}"

if [ ! -r "$local_directory" ]
then
    site=$(eval "echo ${GIT_SITE_CLONE}")

    echo "Cloning $site into $local_directory."
    git clone -q "$site" "$local_directory" 2>&1 1>/dev/null

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "[GIT-CLONE failed! Bye!]"
	exit $rc
    else
	echo "[Great!]"
    fi
fi

echo "Setting $local_directory as the current directory."
cd "$local_directory"

if [ ! $? -eq 0 ]
then
    echo "[Cannot set current directory! Bye!]"
    exit 1
else
    # Remove files older than five minutes.

    echo "Removing files older than five minutes."
    find "$local_directory" \
	 ! -path "*.git*" \
	 -daystart \
	 -mmin +5 \
	 -name "*Smoke*.txt" \
	 -type f \
	 -exec rm -f {} \;

    # Merge.

    echo "Instructing GIT to avoid the rebase strategy. " \
	 "Merge changes instead."
    git config pull.rebase false 2>&1 1>/dev/null

    if [ ! $? eq 0 ]
    then
	echo "[GIT-CONFIG failed!]"
    else
	echo "[Great!]"
    fi

    # Pull?

    echo "Issuing a GIT-PULL request."
    git pull 2>&1 1>/dev/null

    rc=$?

    if [ $rc -eq 0 ]
    then
	echo "[Great!]"
	echo "Determining if there are local revisions."
	rc=$(git ls-files --deleted --exclude-standard --others \
		 2>/dev/null | wc -l)

	if [ $rc -lt 1 ]
	then
	    echo "[All set! Bye!]"
	    exit 0
	fi

	echo "Adding local text files."
	git add --all */*.txt 2>&1 1>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "[GIT-ADD failed! Bye!]"
	    exit $rc
	fi

	echo "Committing new data."
	git commit -a -m "New data." 2>&1 1>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "[GIT-COMMIT failed! Bye!]"
	    exit $rc
	else
	    echo "[Great!]"
	fi

	echo "Issuing a GIT-PULL request."
	git pull --no-log 2>&1 1>/dev/null

	if [ ! $? -eq 0 ]
	then
	    echo "[GIT-PULL failed!]"
	else
	    echo "[Great!]"
	fi

	site=$(eval "echo ${GIT_SITE_PUSH}")

	echo "Issuing a GIT-PUSH request."
	git push "$site" 2>&1 1>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "[GIT-PUSH failed! Bye!]"
	    exit $rc
	else
	    echo "[Great!]"
	fi
    else
	echo "[GIT-PULL failed! Bye!]"
	exit $rc
    fi
fi

echo "$0 completed successfully!"
exit 0
