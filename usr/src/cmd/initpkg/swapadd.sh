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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
# All rights reserved.
#
#
#ident	"%Z%%M%	%I%	%E% SMI"

# Set noinuse checking during boot. We want to disable device in use checking
# so that normal swap use, such as specified in /etc/vfstab, will not cause
# swap devices to fail to be configured during boot.
NOINUSE_CHECK=1; export NOINUSE_CHECK

PATH=/usr/sbin:/usr/bin; export PATH
USAGE="Usage: swapadd [-12] [file_system_table]"

VFSTAB=/etc/vfstab	# Default file system table
PASS=2			# Default to checking for existing swap

#
# Check to see if there is an entry in the fstab for a specified file and
# mount it.  This allows swap files (e.g. nfs files) to be mounted before
# being added for swap.
#
checkmount()
{
	while read rspecial rfsckdev rmountp rfstype rfsckpass rautomnt rmntopts
	do
		#
		# Ignore comments, empty lines, and no-action lines
		#
		case "$rspecial" in
		'#'* | '' | '-') continue ;;
		esac

		if [ "x$rmountp" = "x$1" ]; then
			#
			# If mount options are '-', default to 'rw'
			#
			[ "x$rmntopts" = x- ] && rmntopts=rw

			if /sbin/mount -m -o $rmntopts $rspecial \
			    >/dev/null 2>&1; then
				echo "Mounting $rmountp for swap"
			else
				echo "Mount of $rmountp for swap failed"
			fi
			return
		fi
	done <$VFSTAB
}

die()
{
	echo "$*" >& 2
	exit 1
}

while getopts 12 opt; do
	case "$opt" in
	1|2) PASS=$opt ;;
	 \?) die "$USAGE" ;;
	esac
done
shift `expr $OPTIND - 1`

[ $# -gt 1 ] && die "$USAGE"
[ $# -gt 0 ] && VFSTAB="$1"

#
# If $VFSTAB is not "-" (stdin), re-open stdin as the specified file
#
if [ "x$VFSTAB" != x- ]; then
	[ -s "$VFSTAB" ] || die "swapadd: file system table ($VFSTAB) not found"
	exec <$VFSTAB
fi

#
# Read the file system table to find entries of file system type "swap".
# Add the swap device or file specified in the first column.
#
while read special t1 t2 fstype t3 t4 t5; do
	#
	# Ignore comments, empty lines, and no-action lines
	#
	case "$special" in
	'#'* | '' | '-') continue ;;
	esac

	#
	# Ignore non-swap fstypes
	#
	[ "$fstype" != swap ] && continue

	if [ $PASS = 1 ]; then
		#
		# Pass 1 should handle adding the swap files that
		# are accessable immediately; block devices, files
		# in / and /usr, and direct nfs mounted files.
		#
		if [ ! -b $special ]; then
			#
			# Read the file system table searching for mountpoints
			# matching the swap file about to be added.
			#
			# NB: This won't work correctly if the file to added
			# for swapping is a sub-directory of the mountpoint.
			# e.g.	swapfile-> servername:/export/swap/clientname
			# 	mountpoint-> servername:/export/swap
			#
			checkmount $special
		fi
		if [ -f $special -a -w $special -o -b $special ]; then
			swap -$PASS -a $special >/dev/null
		fi
	else
		#
		# Pass 2 should skip all the swap already added.  If something
		# added earlier uses the same name as something to be added
		# later, the following test won't work. This should only happen
		# if parts of a particular swap file are added or deleted by
		# hand between invocations.
		#
		swap -l 2>/dev/null | grep '\<'${special}'\>' >/dev/null 2>&1 \
		    || swap -$PASS -a $special >/dev/null
	fi
done
