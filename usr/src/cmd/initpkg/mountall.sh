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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.
#
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved
#

usage () {
	if [ -n "$1" ]; then
		echo "mountall: $1" 1>&2
	fi
	echo "Usage:\nmountall [-F FSType] [-l|-r|-g] [file_system_table]" 1>&2
	exit 2
}

PATH=/usr/sbin:/usr/bin
TYPES=all
FSTAB=/etc/vfstab
err=0

# Clear these in case they were already set in our environment.
FSType=
GFLAG=
RFLAG=
LFLAG=
SFLAG=
RemoteFSTypes=

#	checkmessage "fsck_device | mount_point"
#
# Simple auxilary routine to the shell function checkfs. Prints out
# instructions for a manual file system check before entering the shell.
#
checkmessage() {
	echo "" > /dev/console
	if [ "$1" != "" ] ; then
		echo "WARNING - Unable to repair one or more \c" > /dev/console
		echo "of the following filesystem(s):" > /dev/console
		echo "\t$1" > /dev/console
	else
		echo "WARNING - Unable to repair one or more filesystems." \
			> /dev/console
	fi
	echo "Run fsck manually (fsck filesystem...)." > /dev/console
	echo "" > /dev/console
}

#
#	checkfs raw_device fstype mountpoint
#
# Check the file system specified. The return codes from fsck have the
# following meanings.
#	 0 - file system is unmounted and okay
#	32 - file system is unmounted and needs checking (fsck -m only)
#	33 - file system is already mounted
#	34 - cannot stat device
#	36 - uncorrectable errors detected - terminate normally (4.1 code 8)
#	37 - a signal was caught during processing (4.1 exit 12)
#	39 - uncorrectable errors detected - terminate rightaway (4.1 code 8)
#	40 - for root, same as 0 (used by rcS to remount root)
#
checkfs() {
	/usr/sbin/fsck -F $2 -m $1  >/dev/null 2>&1

	if [ $? -ne 0 ]
	then
		# Determine fsck options by file system type
		case "$2" in
		ufs)	foptions="-o p"
			;;
		*)	foptions="-y"
			;;
		esac

		echo "The "$3" file system ("$1") is being checked."
		/usr/sbin/fsck -F $2 ${foptions} $1
	
		case $? in
		0|40)	# file system OK
			;;

		*)	# couldn't fix the file system
			echo "/usr/sbin/fsck failed with exit code "$?"."
			checkmessage "$1"
			;;
		esac
	fi
}

#
# Used to save an entry that we will want to mount either in
# a command file or as a mount point list.
#
# saveentry fstype options special mountp
#
saveentry() {
	if [ "$ALTM" ]; then
		echo "/sbin/mount -F $1 $2 $3 $4" >> $ALTM
	else
		mntlist="$mntlist $4"
	fi
}

# Do the passed mount options include "global"?
isglobal() {
	case ",${1}," in
	*,global,*)
		return 0
		;;
	esac
	return 1
}

# Is the passed fstype a "remote" one?
# Essentially: /usr/bin/grep "^$1" /etc/dfs/fstypes
isremote() {
	for t in $RemoteFSTypes
	do
		[ "$t" = "$1" ] && return 0
	done
	return 1
}

# Get list of remote FS types (just once)
RemoteFSTypes=`while read t junk; do echo $t; done < /etc/dfs/fstypes`


#
# Process command line args
#
while getopts ?grlsF: c
do
	case $c in
	g)	GFLAG="g";;
	r)	RFLAG="r";;
	l)	LFLAG="l";;
	s)	SFLAG="s";;
	F)	FSType="$OPTARG";
		if [ "$TYPES" = "one" ]
		then
			echo "mountall: more than one FSType specified"
			exit 2
		fi
		TYPES="one";

		case $FSType in
		?????????*) 
			echo "mountall: FSType $FSType exceeds 8 characters"
			exit 2
		esac
		;;
	\?)	usage "";;
	esac
done

shift `/usr/bin/expr $OPTIND - 1`	# get past the processed args

if [ $# -gt 1 ]; then
	usage "multiple arguments not supported"
fi

# get file system table name and make sure file exists
if [ $# = 1 ]; then
	case $1 in
	"-")	FSTAB=""
		;;
	*)	FSTAB=$1
		;;
	esac
fi
#
# if an alternate vfstab file is used or serial mode is specified, then
# use a mount command file
#
if [ $# = 1 -o "$SFLAG" ]; then
	ALTM=/var/tmp/mount$$
	rm -f $ALTM
fi

if [ "$FSTAB" != ""  -a  ! -s "$FSTAB" ]
then
	echo "mountall: file system table ($FSTAB) not found"
	exit 1
fi

#
# Check for incompatible args
#
if [ "$GFLAG" = "g" -a "$RFLAG$LFLAG" != "" -o \
     "$RFLAG" = "r" -a "$GFLAG$LFLAG" != "" -o \
     "$LFLAG" = "l" -a "$RFLAG$GFLAG" != "" ]
then
	usage "options -g, -r and -l are mutually exclusive"
fi

if [ "$LFLAG" = "l" -a -n "$FSType" ]; then
	# remote FSType not allowed
	isremote "$FSType" &&
	usage "option -l and FSType are incompatible"
fi

if [ "$RFLAG" = "r" -a -n "$FSType" ]; then
	# remote FSType required
	isremote "$FSType" ||
	usage "option -r and FSType are incompatible"
fi

#	file-system-table format:
#
#	column 1:	special- block special device or resource name
#	column 2: 	fsckdev- char special device for fsck 
#	column 3:	mountp- mount point
#	column 4:	fstype- File system type
#	column 5:	fsckpass- number if to be checked automatically
#	column 6:	automnt-	yes/no for automatic mount
#	column 7:	mntopts- -o specific mount options

#	White-space separates columns.
#	Lines beginning with \"#\" are comments.  Empty lines are ignored.
#	a '-' in any field is a no-op.

#
# Read FSTAB, fsck'ing appropriate filesystems:
#
exec < $FSTAB
while  read special fsckdev mountp fstype fsckpass automnt mntopts
do
	case $special in
	'#'* | '')	#  Ignore comments, empty lines
			continue ;;
	'-')		#  Ignore no-action lines
			continue
	esac

	if [ "$automnt" != "yes" ]; then
		continue
	fi
	if [ "$FSType" -a "$FSType" != "$fstype" ]; then
		# ignore different fstypes
		continue
	fi

	# The -g option is not in the man page, but according to
	# PSARC/1998/255 it's used by Sun Cluster (via contract) to
	# mount disk-based filesystems with the "global" option.
	# Also, the -l option now skips those "global" mounts.
	#
	# Note: options -g -l -r are mutually exclusive
	#
	if [ -n "$GFLAG" ]; then
		# Mount "local" filesystems that have
		# the "global" option in mntopts.
		isremote "$fstype" && continue
		isglobal "$mntopts" || continue
	fi
	if [ -n "$LFLAG" ]; then
		# Mount "local" filesystems, excluding
		# those marked "global".
		isremote "$fstype" && continue
		isglobal "$mntopts" && continue
	fi
	if [ -n "$RFLAG" ]; then
		# Mount "remote" filesystems.
		isremote "$fstype" || continue
	fi

	if [ "$fstype" = "-" ]; then
		echo "mountall: FSType of $special cannot be identified" 1>&2
		continue
	fi

	if [ "$ALTM" -a "$mntopts" != "-" ]; then
		OPTIONS="-o $mntopts"		# Use mount options if any
	else
		OPTIONS=""
	fi

	#
	# Ignore entries already mounted
	#
	/usr/bin/grep "	$mountp	" /etc/mnttab >/dev/null 2>&1 && continue

	#
	# Can't fsck if no fsckdev is specified
	#
	if [ "$fsckdev" = "-" ]; then
		saveentry $fstype "$OPTIONS" $special $mountp
		continue
	fi
	#
	# For fsck purposes, we make a distinction between file systems
	# that have a /usr/lib/fs/<fstyp>/fsckall script and those
	# that don't.  For those that do, just keep a list of them
	# and pass the list to the fsckall script for that file
	# file system type.
	# 
	if [ -x /usr/lib/fs/$fstype/fsckall ]; then

		#
		# add fstype to the list of fstypes for which
		# fsckall should be called, if it's not already
		# in the list.
		#
		found=no
		if [ "$fsckall_fstypes" != "" ] ; then
			for fst in $fsckall_fstypes; do
				if [ "$fst" = "$fstype" ] ; then
					found=yes
					break
				fi
			done
		fi
		if [ $found = no ] ; then
			fsckall_fstypes="$fsckall_fstypes ${fstype}"
		fi

		#
		# add the device to the name of devices to be passed
		# to the fsckall program for this file system type
		#
		cmd="${fstype}_fscklist=\"\$${fstype}_fscklist $fsckdev\""
		eval $cmd
		saveentry $fstype "$OPTIONS" $special $mountp
		continue
	fi
	#
	# fsck everything else:
 	#
 	# fsck -m simply returns true if the filesystem is suitable for
 	# mounting.
 	#
	/usr/sbin/fsck -m -F $fstype $fsckdev >/dev/null 2>&1
	case $? in
	0|40)	saveentry $fstype "$OPTIONS" $special $mountp
		continue
		;;
	32)	checkfs $fsckdev $fstype $mountp
		saveentry $fstype "$OPTIONS" $special $mountp
		continue
		;;
	33)	# already mounted
		echo "$special already mounted"
		;;
	34)	# bogus special device
		echo "Cannot stat $fsckdev - ignoring"
		err=1
		;;
	*)	# uncorrectable errors
		echo "$fsckdev uncorrectable error"
		err=1
		;;
	esac
done

#
# Call the fsckall programs
#
for fst in $fsckall_fstypes
do
	cmd="/usr/lib/fs/$fst/fsckall \$${fst}_fscklist"
	eval $cmd

	case $? in
	0)	# file systems OK
			;;

	*)	# couldn't fix some of the filesystems
		echo "fsckall failed with exit code "$?"."
		checkmessage
		;;
	esac
done

if [ "$ALTM" ]; then
	if [ ! -f "$ALTM" ]; then
		exit
	fi
	/sbin/sh $ALTM		# run the saved mount commands
	/usr/bin/rm -f $ALTM
	exit
fi

if [ -n "$FSType" ]; then
	/sbin/mount -a -F $FSType
	exit
fi

# Some remote filesystems (e.g. autofs) shouldn't be mounted
# with mountall, so the list here is explicit (not from /etc/dfs/fstypes)
if [ "$RFLAG" ]; then
	/sbin/mount -a -F nfs
	/sbin/mount -a -F smbfs
	exit
fi

if [ "$LFLAG" -o "$GFLAG" -o $err != 0 ]; then
	[ -z "$mntlist" ] || /sbin/mount -a $mntlist
	exit
fi

# else mount them all

/sbin/mount -a
