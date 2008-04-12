#!/bin/sh
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T.
# All rights reserved.
#
#
#ident	"%Z%%M%	%I%	%E% SMI"

vfstab=${vfstab:=/etc/vfstab}

#
# readvfstab mount_point
#   -> (special, fsckdev, mountp, fstype, fsckpass, automnt, mntopts)
#
#   A vfstab-like input stream is scanned for the mount point specified
#   as $1.  Returns the fields of vfstab in the following shell
#   variables:
#
#       special		block device
#       fsckdev		raw device
#       mountp		mount point (must match $1, if found)
#       fstype		file system type
#       fsckpass	fsck(1M) pass number
#       automnt		automount flag (yes or no)
#       mntopts		file system-specific mount options.
#
#   If the mount point can not be found in the standard input stream,
#   then all fields are set to empty values.  This function assumes that
#   stdin is already set /etc/vfstab (or other appropriate input
#   stream).
#
readvfstab() {
	while read special fsckdev mountp fstype fsckpass automnt mntopts; do
		case "$special" in
			'' )	# Ignore empty lines.
				continue
				;;

			'#'* )	# Ignore comment lines.
				continue
				;;

			'-')	# Ignore "no-action" lines.
				continue
				;;
		esac

		[ "x$mountp" = "x$1" ] && break
	done
}

readswapdev() {
	while read special fsckdev mountp fstype fsckpass automnt mntopts; do
		# Ignore comments, empty lines, and no-action lines
		case "$special" in
		'#'* | '' | '-') continue;;
		esac

		[ "$fstype" != swap ] && continue

		[ "x$special" = "x$1" ] && break
	done
}

#
# readmnttab mount_point
#   -> (special, mountp, fstype, mntopts, mnttime)
#
#   A mnttab-like input stream is scanned for the mount point specified
#   as $1.  Returns the fields of mnttab in the following shell
#   variables:
#
#       special		block device
#       mountp		mount point (must match $1, if found)
#       fstype		file system type
#       mntopts		file system-specific mount options.
#	mnttime		time at which file system was mounted
#
#   If the mount point can not be found in the standard input stream,
#   then all fields are set to empty values.  This function assumes that
#   stdin is already set to /etc/mnttab (or other appropriate input
#   stream).
#
readmnttab() {
	while read special mountp fstype mntopts mnttime; do
		[ "x$mountp" = "x$1" ] && break
	done
}

cecho() {
	echo $*
	echo $* >/dev/msglog
}

#
# checkmessage raw_device fstype mountpoint
# checkmessage2 raw_device fstype mountpoint
#
#   Two simple auxilary routines to the shell function checkfs.  Both
#   display instructions for a manual file system check.
#
checkmessage() {
	cecho ""
	cecho "WARNING - Unable to repair the $3 filesystem. Run fsck"
	cecho "manually (fsck -F $2 $1)."
	cecho ""
}

checkmessage2() {
	cecho ""
	cecho "WARNING - fatal error from fsck - error $4"
	cecho "Unable to repair the $3 filesystem. Run fsck manually"
	cecho "(fsck -F $2 $1)."
	cecho ""
}

#
# checkfs raw_device fstype mountpoint
#
#   Check the file system specified. The return codes from fsck have the
#   following meanings.
#
#	 0	file system is unmounted and okay
#	32	file system is unmounted and needs checking (fsck -m only)
#	33	file system is already mounted
#	34	cannot stat device
#	35	modified root or something equally dangerous
#	36	uncorrectable errors detected - terminate normally (4.1 code 8)
#	37	a signal was caught during processing (4.1 exit 12)
#	39	uncorrectable errors detected - terminate rightaway (4.1 code 8)
#	40	 for root, same as 0 (used here to remount root)
#
checkfs() {
	# skip checking if the fsckdev is "-"
	[ "x$1" = x- ] && return

	# if fsck isn't present, it is probably because either the mount of
	# /usr failed or the /usr filesystem is badly damanged.  In either
	# case, there is not much to be done automatically.  Fail with
	# a message to the user.
	if [ ! -x /usr/sbin/fsck ]; then
		cecho ""
		cecho "WARNING - /usr/sbin/fsck not found.  Most likely the"
		cecho "mount of /usr failed or the /usr filesystem is badly"
		cecho "damaged."
		cecho ""
		return 1
	fi

	# If a filesystem-specific fsck binary is unavailable, then no
	# fsck pass is required.
	[ ! -x /usr/lib/fs/$2/fsck ] && [ ! -x /etc/fs/$2/fsck ] && return

	/usr/sbin/fsck -F $2 -m $1 >/dev/null 2>&1

	if [ $? -ne 0 ]; then
		# Determine fsck options by file system type
		case $2 in
			ufs)	foptions="-o p"
				;;
			*)	foptions="-y"
				;;
		esac

		cecho "The $3 file system ($1) is being checked."
		/usr/sbin/fsck -F $2 $foptions $1
	
		case $? in
		0|40)	# File system OK
			;;

		1|34|36|37|39)	# couldn't fix the file system - fail
			checkmessage "$1" "$2" "$3"
			return 1
			;;
		33)	# already mounted
			return 0
			;;

		*)	# fsck child process killed (+ error code 35)
			checkmessage2 "$1" "$2" "$3" "$?"
			return 1
			;;
		esac
	fi

	return 0
}

#
# checkopt option option-string
# -> ($option, $otherops)
#
#   Check to see if a given mount option is present in the comma
#   separated list gotten from vfstab.
#
#	Returns:
#	${option}       : the option if found the empty string if not found
#	${otherops}     : the option string with the found option deleted
#
checkopt() {
	option=
	otherops=

	[ "x$2" = x- ] && return

	searchop="$1"
	set -- `IFS=, ; echo $2`

	while [ $# -gt 0 ]; do
		if [ "x$1" = "x$searchop" ]; then
			option="$1"
		else
			if [ -z "$otherops" ]; then
				otherops="$1"
			else
				otherops="${otherops},$1"
			fi
		fi
		shift
	done
}

#
# hasopts $opts $allopts
#
#   Check if all options from the list $opts are present in $allopts.
#   Both $opts and $allopts should be in comma separated format.
#
# Return 0 on success, and 1 otherwise.
#
hasopts() {
	opts="$1"
	allopts="$2"

	set -- `IFS=, ; echo $opts`
	while [ $# -gt 0 ]; do
		if [ "$1" != "remount" ]; then
			checkopt $1 $allopts
			#
			# Don't report errors if the filesystem is already
			# read-write when mounting it as read-only.
			#
			[ -z "$option" ] && [ "$1" = "ro" ] && \
				checkopt rw $allopts
			[ -z "$option" ] && return 1
		fi
		shift
	done
	return 0
}

#
# mounted $path $fsopts $fstype
#
#   Check whether the specified file system of the given type is currently
#   mounted with all required filesystem options by going through /etc/mnttab
#   in our standard input.
#
#   Return values:
#   0	Success.
#   1	The filesystem is not currently mounted, or mounted without required
#	options, or a filesystem of a different type is mounted instead.
#
mounted() {
	path="$1"
	fsopts="$2"
	fstype="$3"

	while read mntspec mntpath mnttype mntopts on; do
		[ "$mntpath" = "$path" ] || continue
		[ "$fstype" != "-" ] && [ "$mnttype" != "$fstype" ] && return 1
		[ "$fsopts" = "-" ] && return 0
		hasopts $fsopts $mntopts && return 0
	done
	return 1
}

#
# mountfs $opts $path $type $fsopts $special
#
#   Try to mount a filesystem.  If failed, display our standard error
#   message on the console and print more details about what happened 
#   to our service log.
#
# Arguments:
#   $opts	- options for mount(1M)				[optional]
#   $path	- mount point
#   $type	- file system type				[optional]
#   $fsopts	- file system specific options (-o)		[optional]
#   $special	- device on which the file system resides	[optional]
#
# Return codes:
#   0		- success.
#   otherwise	- error code returned by mount(1M).
#
mountfs() {
	opts="$1"
	path="$2"
	special="$5"

	#
	# Take care of optional arguments
	#
	[ "$opts" = "-" ] && opts=""
	[ "$special" = "-" ] &&	special=""
	[ "$3" = "-" ] && type=""
	[ "$3" != "-" ] && type="-F $3"
	[ "$4" = "-" ] && fsopts=""
	[ "$4" != "-" ] && fsopts="-o $4"

	cmd="/sbin/mount $opts $type $fsopts $special $path"
	msg=`$cmd 2>&1`
	err=$?

	[ $err = 0 ] && return 0

	#
	# If the specified file system is already mounted with all
	# required options, and has the same filesystem type
	# then ignore errors and return success
	#
	mounted $path $4 $3 < /etc/mnttab && return 0

	echo "ERROR: $SMF_FMRI failed to mount $path "\
	     "(see 'svcs -x' for details)" > /dev/msglog
	echo "ERROR: $cmd failed, err=$err"
	echo $msg
	return $err
}
