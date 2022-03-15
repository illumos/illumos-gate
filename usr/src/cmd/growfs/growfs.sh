#!/bin/sh
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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#exec newfs -G "$@"

myname=`basename $0`
USAGE="usage: $myname [ -M mount-point ] [ newfs-options ] raw-special-device"
if [ ! "$UFS_MKFS" ]; then
	UFS_MKFS="/usr/lib/fs/ufs/mkfs"
fi
verbose=""
mkfs_opts="-G"
mkfs_subopts=""
size=""
newsize=0
mount_pt=
UFS_MKFS_NOTENOUGHSPACE=33

add_opt() {
	mkfs_opts="$mkfs_opts $1"
}

add_subopt() {
	if [ ! "$mkfs_subopts" ]; then
		mkfs_subopts="-o $1"
	else
		mkfs_subopts="$mkfs_subopts,$1"
	fi
}

while getopts "GM:Nva:b:c:d:f:i:m:n:o:r:s:t:C:" c ; do
	save=$OPTIND

	case $c in
	G)	;;
	M)	add_opt "-M $OPTARG"; mount_pt="$OPTARG" ;;
	N)	add_subopt "N" ;;
	v)	verbose="1" ;;
	a)	add_subopt "apc=$OPTARG" ;;
	b)	add_subopt "bsize=$OPTARG" ;;
	c)	add_subopt "cgsize=$OPTARG" ;;
	d)	add_subopt "gap=$OPTARG" ;;
	f)	add_subopt "fragsize=$OPTARG" ;;
	i)	add_subopt "nbpi=$OPTARG" ;;
	m)	add_subopt "free=$OPTARG" ;;
	n)	add_subopt "nrpos=$OPTARG" ;;
	o)	add_subopt "opt=$OPTARG" ;;
	r)	add_subopt "rps=`expr $OPTARG / 60`" ;;
	s)	size=$OPTARG ;;
	t)	add_subopt "ntrack=$OPTARG" ;;
	C)	add_subopt "maxcontig=$OPTARG" ;;
	\?)	echo $USAGE; exit 1 ;;
	esac

	OPTIND=$save
done

shift `expr $OPTIND - 1`
if [ $# -ne 1 ]; then
	echo $USAGE
	exit 1
fi
raw_special=$1

if [ ! "$size" ]; then
	size=`devinfo -p $raw_special | awk '{ print $5 }'`
	if [ $? -ne 0 -o ! "$size" ]; then
		echo "$myname: cannot get partition size"
		exit 2
	fi
fi

cmd="$UFS_MKFS $mkfs_opts $mkfs_subopts $raw_special $size"
if [ -n "$verbose" ]; then
	echo $cmd
fi
$cmd; retv=$?

if [ $retv -eq $UFS_MKFS_NOTENOUGHSPACE ]; then
	echo "Growing filesystem in increments due to limited available space."

	while [ "$newsize" -lt "$size" ]; do
		cmd="$UFS_MKFS $mkfs_opts $mkfs_subopts -P $raw_special $size"
		if [ -n "$verbose" ]; then
			echo $cmd
		fi
		newsize=`$cmd`; retv=$?
		if [ 0 -ne $retv -o -z "$newsize" ]; then
			echo "$myname: cannot probe the possible file system size"
			exit 2
		fi
		if [ 0 -eq "$newsize" ]; then
			echo "$myname: the file system is full and cannot be grown, please delete some files"
			exit 2
		fi

		cmd="$UFS_MKFS $mkfs_opts $mkfs_subopts $raw_special $newsize"; retv=$?
		if [ -n "$verbose" ]; then
			echo $cmd
		fi
		$cmd; retv=$?
		if [ 0 -ne $retv ]; then
			echo "$myname: cannot grow file system to $newsize sectors"
			exit  $retv
		fi
	done
	echo \
"\nThe incremental grow has successfully completed, but since the first growth \
attempt failed (see output from first mkfs(8) run), the filesystem is still \
locked and needs to be checked with fsck(8).\n\
Please run \`fsck -F ufs $raw_special' and then unlock the filesystem \
with \`lockfs -u $mount_pt'." | fmt;

fi

exit $retv
