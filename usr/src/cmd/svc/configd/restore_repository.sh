#!/sbin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2012 Nexenta Sysytems, Inc.  All rights reserved.
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PATH=/sbin:/usr/bin:/usr/sbin
LC_ALL=C
export PATH LC_ALL

. /lib/svc/share/smf_include.sh
. /lib/svc/share/fs_include.sh

usage()
{
	echo "usage: $0 [-r rootdir]" >&2
	echo "
See http://illumos.org/msg/SMF-8000-MY for more information on the use of
this script."
	exit 2;
}

repositorydir=etc/svc
repository=repository

myroot=/
while getopts r: opt; do
	case "$opt" in
	    r)	myroot=$OPTARG
		if [ ! -d $myroot ]; then
			echo "$myroot: not a directory" >&2
			exit 1
		fi
		# validate directory and make sure it ends in '/'.
		case "$myroot" in
		    //*) echo "$myroot: must begin with a single /" >&2
			usage;;
		    /)	echo "$myroot: alternate root cannot be /" >&2
			usage;;

		    /*/) ;;			# ends with /
		    /*) myroot="$myroot/";;	# add final /

		    *)	echo "$myroot: must be a full path" >&2
			usage;;
		esac;;
	    ?)	usage;;
	esac
done

if [ $OPTIND -le $# ]; then
	# getopts(1) didn't slurp up everything.
	usage
fi

#
# Note that the below test is carefully constructed to fail *open*;  if
# anything goes wrong, it will drive onward.
#
if [ -x /usr/bin/id -a -x /usr/bin/grep ] &&
    /usr/bin/id 2>/dev/null | /usr/bin/grep -v '^[^=]*=0(' >/dev/null 2>&1; then
	echo "$0: may only be invoked by root" >&2
	exit 2
fi

echo >&2 "
See http://illumos.org/msg/SMF-8000-MY for more information on the use of
this script to restore backup copies of the smf(5) repository.

If there are any problems which need human intervention, this script will
give instructions and then exit back to your shell."

if [ "$myroot" = "/" ]; then
	system="system"
	[ "`/sbin/zonename`" != global ] && system="zone"
	echo >&2 "
Note that upon full completion of this script, the $system will be rebooted
using reboot(1M), which will interrupt any active services.
"
fi

# check that the filesystem is as expected
cd "$myroot" || exit 1
cd "$myroot$repositorydir" || exit 1

nouser=false
rootro=false

# check to make sure /usr is mounted
if [ ! -x /usr/bin/pgrep ]; then
	nouser=true
fi

if [ ! -w "$myroot" ]; then
	rootro=true
fi

if [ "$nouser" = true -o "$rootro" = true ]; then
	if [ "$nouser" = true -a "$rootro" = true ]; then
		echo "The / filesystem is mounted read-only, and the /usr" >&2
		echo "filesystem has not yet been mounted." >&2
	elif [ "$nouser" = true ]; then
		echo "The /usr filesystem has not yet been mounted." >&2
	else
		echo "The / filesystem is mounted read-only." >&2
	fi

	echo >&2 "
This must be rectified before $0 can continue.

To properly mount / and /usr, run:
    /lib/svc/method/fs-root
then
    /lib/svc/method/fs-usr

After those have completed successfully, re-run:
    $0 $*

to continue.
"
	exit 1
fi

# at this point, we know / is mounted read-write, and /usr is mounted.
oldreps="`
	/bin/ls -1rt $repository-*-[0-9]*[0-9] | \
	    /bin/sed -e '/[^A-Za-z0-9_,.-]/d' -e 's/^'$repository'-//'
`"

if [ -z "$oldreps" ]; then
	cat >&2 <<EOF
There are no available backups of $myroot$repositorydir/$repository.db.
The only available repository is "-seed-".  Note that restoring the seed
will lose all customizations, including those made by the system during
the installation and/or upgrade process.

EOF
	prompt="Enter -seed- to restore from the seed, or -quit- to exit: \c"
	default=
else
	cat >&2 <<EOF
The following backups of $myroot$repositorydir/$repository.db exist, from
oldest to newest:

$oldreps

The backups are named based on their type and the time what they were taken.
Backups beginning with "boot" are made before the first change is made to
the repository after system boot.  Backups beginning with "manifest_import"
are made after svc:/system/manifest-import:default finishes its processing.
The time of backup is given in YYYYMMDD_HHMMSS format.

Please enter either a specific backup repository from the above list to
restore it, or one of the following choices:

	CHOICE		  ACTION
	----------------  ----------------------------------------------
	boot		  restore the most recent post-boot backup
	manifest_import	  restore the most recent manifest_import backup
	-seed-		  restore the initial starting repository  (All
			    customizations will be lost, including those
			    made by the install/upgrade process.)
	-quit-		  cancel script and quit

EOF
	prompt="Enter response [boot]: \c"
	default="boot"
fi

cont=false
while [ $cont = false ]; do
	echo "$prompt"

	read x || exit 1
	[ -z "$x" ] && x="$default"

	case "$x" in
	    -seed-)
		if [ $myroot != / -o "`/sbin/zonename`" = global ]; then
			file="$myroot"lib/svc/seed/global.db
		else
			file="$myroot"lib/svc/seed/nonglobal.db
		fi;;
	    -quit-)
		echo "Exiting."
		exit 0;;
	    /*)
		file="$x";;
	    */*)
		file="$myroot$x";;
	    ?*)
		file="$myroot$repositorydir/repository-$x";;
	    *)	file= ;;
	esac

	if [ -f $file ]; then
		if [ -r $file ]; then
			checkresults="`echo PRAGMA integrity_check\; | \
			    /lib/svc/bin/sqlite $file >&1 | grep -v '^ok$'`"

			if [ -n "$checkresults" ]; then
				echo "$file: integrity check failed:" >&2
				echo "$checkresults" >&2
				echo
			else
				cont=true
			fi
		else
			echo "$file: not readable"
		fi
	elif [ -n "$file" ]; then
		echo "$file: not found"
	fi
done

errors="$myroot"etc/svc/volatile/db_errors
repo="$myroot$repositorydir/$repository.db"
new="$repo"_old_"`date +%Y''%m''%d'_'%H''%M''%S`"

steps=
if [ "$myroot" = / ]; then
	steps="$steps
svc.startd(1M) and svc.configd(1M) will be quiesced, if running."
fi

if [ -r $repo ]; then
	steps="$steps
$repo
    -- renamed --> $new"
fi
if [ -r $errors ]; then
	steps="$steps
$errors
    -- copied --> ${new}_errors"
fi

cat >&2 <<EOF

After confirmation, the following steps will be taken:
$steps
$file
    -- copied --> $repo
EOF

if [ "$myroot" = / ]; then
	echo "and the system will be rebooted with reboot(1M)."
fi

echo
cont=false
while [ $cont = false ]; do
	echo "Proceed [yes/no]? \c"
	read x || x=n

	case "$x" in
	    [Yy]|[Yy][Ee][Ss])
		cont=true;;
	    [Nn]|[Nn][Oo])
		echo; echo "Exiting..."
		exit 0;
	esac;
done

umask 077		# we want files to be root-readable only.

startd_msg=
if [ "$myroot" = / ]; then
	zone="`zonename`"
	startd="`pgrep -z "$zone" -f svc.startd`"

	echo
	echo "Quiescing svc.startd(1M) and svc.configd(1M): \c"
	if [ -n "$startd" ]; then
		pstop $startd
		startd_msg=\
"To start svc.start(1M) running, do: /usr/bin/prun $startd"
	fi
	pkill -z "$zone" -f svc.configd

	sleep 1			# yes, this is hack

	echo "done."
fi

if [ -r "$repo" ]; then
	echo "$repo"
	echo "    -- renamed --> $new"
	if mv $repo $new; then
		:
	else
		echo "Failed.  $startd_msg"
		exit 1;
	fi
fi

if [ -r $errors ]; then
	echo "$errors"
	echo "    -- copied --> ${new}_errors"
	if cp -p $errors ${new}_errors; then
		:
	else
		mv -f $new $repo
		echo "Failed.  $startd_msg"
		exit 1;
	fi
fi

echo "$file"
echo "    -- copied --> $repo"

if cp $file $repo.new.$$ && mv $repo.new.$$ $repo; then
	:
else
	rm -f $repo.new.$$ ${new}_errors
	mv -f $new $repo
	echo "Failed.  $startd_msg"
	exit 1;
fi

echo
echo "The backup repository has been successfully restored."
echo

if [ "$myroot" = / ]; then
	echo "Rebooting in 5 seconds."
	sleep 5
	reboot
fi
