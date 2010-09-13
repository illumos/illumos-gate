#!/usr/bin/ksh93

#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# filemutexdemo1 - a simple locking demo which supports read/write
# locks and critical sections (like JAVA's "syncronized" keyword)
#

# Solaris needs /usr/xpg6/bin:/usr/xpg4/bin because the tools in /usr/bin are not POSIX-conformant
export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

# Make sure all math stuff runs in the "C" locale to avoid problems
# with alternative # radix point representations (e.g. ',' instead of
# '.' in de_DE.*-locales). This needs to be set _before_ any
# floating-point constants are defined in this script).
if [[ "${LC_ALL}" != "" ]] ; then
    export \
        LC_MONETARY="${LC_ALL}" \
        LC_MESSAGES="${LC_ALL}" \
        LC_COLLATE="${LC_ALL}" \
        LC_CTYPE="${LC_ALL}"
        unset LC_ALL
fi
export LC_NUMERIC=C

# Definition for a mutex which uses the filesystem for locking
typeset -T filemutex_t=(
	typeset name
	
	typeset lock_dirname
	
	typeset locked_exclusive="false"
	typeset locked_shared="false"
	
	# keep track of subshell level. The problem is that we do not know a
	# way to figure out whether someone calls "unlock" in a subshell and then
	# leaves the subshell and calls "unlock" again
	integer subshell=-1
	
	typeset lock_dirname
	
	# create a filemutex instance (including lock directory)
	function create
	{
		# make sure we return an error if the init didn't work
		set -o errexit

		[[ "$1" == "" ]] && return 1
		
		_.name="$1"
		_.lock_dirname="/tmp/filemutex_t_${_.name}.lock"
		
		mkdir "${_.lock_dirname}"
		
		# last entry, used to mark the mutex as initalised+valid
		(( _.subshell=.sh.subshell ))
		return 0
	}

	# use a filemutex instance (same as "create" but without creating 
	# the lock directory)
	function create_child
	{
		# make sure we return an error if the init didn't work
		set -o errexit

		[[ "$1" == "" ]] && return 1
		
		_.name="$1"
		_.lock_dirname="/tmp/filemutex_t_${_.name}.lock"
		
		# last entry, used to mark the mutex as initalised+valid
		(( _.subshell=.sh.subshell ))
		return 0
	}
	
	function check_subshell
	{
		(( _.subshell == .sh.subshell )) && return 0
		print -u2 -f "filemutex_t.%s(%s): Wrong subshell level\n" "$1" "${_.name}"
		return 1
	}

	function try_lock_shared
	{
		_.check_subshell "try_lock_shared" || return 1
		
		mkdir "${_.lock_dirname}/shared_${PPID}_$$" 2>/dev/null || return 1
		_.locked_shared="true"
		return 0
	}
	
	function lock_shared
	{
		float interval=0.2

		_.check_subshell "lock_shared" || return 1
		
		while ! _.try_lock_shared ; do sleep ${interval} ; (( interval+=interval/10. )) ; done
		return 0
	}

	function try_lock_exclusive
	{
		_.check_subshell "try_lock_exclusive" || return 1
		
		rmdir "${_.lock_dirname}" 2>/dev/null || return 1
		_.locked_exclusive="true"
		return 0
	}
			
	function lock_exclusive
	{
		float interval=0.2
		
		_.check_subshell "lock_exclusive" || return 1
		
		while ! _.try_lock_exclusive ; do sleep ${interval} ; (( interval+=interval/10. )) ; done
		return 0
	}
	
	# critical section support (like java's "synchronized" keyword)
	function synchronized
	{
		integer retcode

		_.check_subshell "synchronized" || return 1
		
		_.lock_exclusive
		
		"$@"
		(( retcode=$? ))

		_.unlock
		
		return ${retcode}
	}

	# critical section support with shared lock
	function synchronized_shared
	{
		integer retcode

		_.check_subshell "synchronized_shared" || return 1
		
		_.lock_shared
		
		"$@"
		(( retcode=$? ))

		_.unlock
		
		return ${retcode}
	}
		
	function unlock
	{
		# return an error if rmdir/mkdir/check_subshell fail...
		set -o errexit
		
		_.check_subshell "unlock"

		if ${_.locked_shared} ; then
			rmdir "${_.lock_dirname}/shared_${PPID}_$$"
			_.locked_shared="false"
			return 0
		elif ${_.locked_exclusive} ; then
			mkdir "${_.lock_dirname}"
			_.locked_exclusive="false"
			return 0
		fi

		print -u2 -f "filemutex_t.unlock(%s): mutex '%s' not locked." "$1" "${_.name}"
		return 1
	}
	
	# destroy mutex if noone is using it anymore (not the same as "unset" !!))
	function destroy
	{
		_.check_subshell "destroy" || return 1

		(${_.locked_exclusive} || ${_.locked_shared}) && _.unlock
		rmdir "${_.lock_dirname}"
		return 0
	}
)

# main
builtin mkdir
builtin rmdir

print "## Start."

typeset -r mymutexname="hello_world"

filemutex_t fs

fs.create "${mymutexname}" || print -u2 "Mutex init failed."

print "# Starting child which keeps an exclusive lock for 10 seconds..."
(
	filemutex_t child_fs
	
	child_fs.create_child "${mymutexname}"

	child_fs.lock_exclusive
	sleep 10
	child_fs.unlock
) &

sleep 1

printf "%T: # Waiting to obtain a shared lock...\n"
fs.lock_shared
printf "%T: # Obtained shared lock\n"

printf "fs.locked_exclusive=%s, fs.locked_shared=%s\n" "${fs.locked_exclusive}" "${fs.locked_shared}"

ls -lad /tmp/filemutex*/*

printf "%T: # Executing child which runs printf '|%%s|\\\n' 'hello' 'world' inside a synchronized section\n"
(
	filemutex_t child_fs
	
	child_fs.create_child "${mymutexname}"

	child_fs.synchronized printf '|%s|\n' 'hello' 'world'
) &

printf "%T: # Sleeping 5 secs while holding the shared lock...\n"
sleep 5.

printf "%T: # Releasing shared lock...\n"
fs.unlock

sleep 5.
print "# Destroying lock..."
fs.destroy

print "## Done."

exit 0
