#!/usr/bin/env sh

# Alexis Megas.

# We will not correct GIT errors.

# If git has locked the local directory, a git command will fail.
# We will not remove the lock.

# If the local directory already exists, a git-clone will fail.
# We will not remove the local directory.

pull_only=0

if [ "$1" = "1" ]
then
    pull_only=1
fi

if [ -z "$(which git)" ]
then
    echo "Please install git."
    exit 1
fi

if [ -z ${GIT_LOCAL_DIRECTORY} ]
then
    echo "Please export GIT_LOCAL_DIRECTORY. Bye!"
    exit 1
fi

if [ -z ${GIT_SITE} ]
then
    echo "Please export GIT_SITE. Bye!"
    exit 1
fi

local_directory="${GIT_LOCAL_DIRECTORY}"
site=$(eval "echo ${GIT_SITE}")

if [ ! -e "$local_directory" ]
then
    echo "Cloning $site into $local_directory."
    git clone --depth 1 -q "$site" "$local_directory" 1>/dev/null 2>/dev/null

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "GIT-CLONE failed! Bye!"
	exit $rc
    else
	echo "Great!"
    fi
fi

echo "Setting $local_directory as the current directory."
cd "$local_directory"

if [ ! $? -eq 0 ]
then
    echo "Cannot set current directory! Bye!"
    exit 1
fi

if [ ! -e "$local_directory/.git" ]
then
    echo "The directory $local_directory/.git does not exist!"
    echo "Cloning $site into $local_directory/tmp.d."
    rm -fr tmp.d 2>/dev/null
    git clone --depth 1 -q "$site" tmp.d 1>/dev/null 2>/dev/null

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "GIT-CLONE failed! Bye!"
	exit $rc
    else
	echo "Great!"
    fi

    echo "Moving tmp.d/.git into the current directory."
    mv tmp.d/.git . 2>/dev/null

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "MV failed! Bye!"
	exit $rc
    else
	echo "Great!"
    fi

    rm -fr tmp.d
    echo "Checking out remote repository."
    git checkout . 1>/dev/null 2>/dev/null

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "GIT-CHECKOUT failed! Bye!"
	exit $rc
    else
	echo "Great!"
    fi
fi

# Remove files older than five minutes.

echo "Removing Smoke files older than one minute."
find "$local_directory" \
     ! -path "*.git*" \
     -mmin +1 \
     -name "*Smoke*.txt" \
     -type f \
     -exec rm -f {} 2>/dev/null \;
echo "Removing files older than fifteen days."
find "$local_directory" \
     ! -path "*.git*" \
     -mtime +15 \
     -name "PrisonBlues*.*" \
     -type f \
     -exec rm -f {} 2>/dev/null \;

# Merge.

echo "Instructing GIT to avoid the rebase strategy. Merge changes instead."
git config pull.rebase false 1>/dev/null 2>/dev/null

if [ ! $? -eq 0 ]
then
    echo "GIT-CONFIG failed!"
else
    echo "Great!"
fi

# Pull?

echo "Issuing a GIT-PULL request."
git pull --no-log 1>/dev/null 2>/dev/null

rc=$?

if [ $pull_only -eq 1 ]
then
    echo "Exiting after GIT-PULL!"
    exit $rc
fi

if [ $rc -eq 0 ]
then
    echo "Great!"
    echo "Determining if there are local revisions."
    rc=$(git ls-files --deleted --exclude-standard --others \
	     2>/dev/null | wc -l)

    if [ $rc -lt 1 ]
    then
	echo "All set! Bye!"

	if [ ! -z "$(git status | grep 'git push' 2>/dev/null)" ]
	then
	    echo "A git-push is required!"
	    git push "$site" 1>/dev/null 2>/dev/null
	fi

	git clean -df . 1>/dev/null 2>/dev/null
	exit 0
    fi

    echo "Adding local GPG and text files."
    git add --all */*.gpg */*.txt 1>/dev/null 2>/dev/null

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "GIT-ADD failed! Bye!"
	exit $rc
    fi

    echo "Committing new data."
    git commit -a -m "New data." 1>/dev/null 2>/dev/null

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "GIT-COMMIT failed! Bye!"
	exit $rc
    else
	echo "Great!"
    fi

    echo "Issuing a GIT-PULL request."
    git pull --no-log 1>/dev/null 2>/dev/null

    if [ ! $? -eq 0 ]
    then
	echo "GIT-PULL failed!"
    else
	echo "Great!"
    fi

    echo "Issuing a GIT-PUSH request."
    git push "$site" 1>/dev/null 2>/dev/null

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "GIT-PUSH failed! Bye!"
	exit $rc
    else
	echo "Great!"
    fi
else
    echo "GIT-PULL failed! Bye!"
    exit $rc
fi

echo "$0 completed successfully!"
exit 0
