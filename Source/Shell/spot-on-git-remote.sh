#!/usr/bin/env sh

# Alexis Megas.

# We will not correct GIT errors.

# If git has locked the local directory, a git command will fail.
# We will not remove the lock.

# If the local directory already exists, a git-clone will fail.
# We will not remove the local directory.

if [ -z "$(which git)" ]
then
    echo "[Please install git.]"
    exit 1
fi

git_site="https://account:token@github.com/account/prison-blues"
ip_address="192.168.178.15"
local_directory="/var/tmp/prison-blues.d"
port=5710

if [ -z "$ip_address" ]
then
    echo "[Please define ip_address. Bye!]"
    exit 1
fi

if [ -z "$git_site" ]
then
    echo "[Please define git_site. Bye!]"
    exit 1
fi

if [ ! -e "$local_directory" ]
then
    echo "Cloning $git_site into $local_directory."
    git clone -q "$git_site" "$local_directory" 1>/dev/null 2>/dev/null

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
fi

while
    echo "Listening on $ip_address:$port."
    nc -dkl "$ip_address" $port &

    rc=$?

    if [ ! $rc -eq 0 ]
    then
	echo "[Listen failure. Sleeping for 10 seconds.]"
	sleep 10
    else
	break
    fi
do true
done

while
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
	 -name "PrisonBlues*.txt" \
	 -type f \
	 -exec rm -f {} 2>/dev/null \;
    sleep 15

    # Merge.

    echo "Instructing GIT to avoid the rebase strategy. " \
	 "Merge changes instead."
    git config pull.rebase false 1>/dev/null 2>/dev/null

    if [ ! $? -eq 0 ]
    then
	echo "[GIT-CONFIG failed!]"
    else
	echo "[Great!]"
    fi

    # Pull?

    echo "Issuing a GIT-PULL request."
    git pull 1>/dev/null 2>/dev/null

    rc=$?

    if [ $rc -eq 0 ]
    then
	echo "[Great!]"
	echo "Determining if there are local revisions."
	rc=$(git ls-files --deleted --exclude-standard --others \
		 2>/dev/null | wc -l)

	if [ $rc -lt 1 ]
	then
	    echo "[All set!]"

	    if [ ! -z "$(git status | grep 'git push' 2>/dev/null)" ]
	    then
		echo "A git-push is required!"
		git push "$git_site" 1>/dev/null 2>/dev/null
	    fi

	    git clean -df . 1>/dev/null 2>/dev/null
	    continue
	fi

	echo "Adding local text files."
	git add --all */*.txt 1>/dev/null 2>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "[GIT-ADD failed!]"
	    continue
	fi

	echo "Committing new data."
	git commit -a -m "New data." 1>/dev/null 2>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "[GIT-COMMIT failed!]"
	    continue
	else
	    echo "[Great!]"
	fi

	echo "Issuing a GIT-PULL request."
	git pull --no-log 1>/dev/null 2>/dev/null

	if [ ! $? -eq 0 ]
	then
	    echo "[GIT-PULL failed!]"
	else
	    echo "[Great!]"
	fi

	echo "Issuing a GIT-PUSH request."
	git push "$git_site" 1>/dev/null 2>/dev/null

	rc=$?

	if [ ! $rc -eq 0 ]
	then
	    echo "[GIT-PUSH failed!]"
	else
	    echo "[Great!]"
	fi
    else
	echo "[GIT-PULL failed!]"
    fi
do true
done
