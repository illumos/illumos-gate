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
#ident	"%Z%%M%	%I%	%E% SMI"
#

away() {
	echo $2 1>&2
	exit $1
}

COUNT=15

while getopts F: a; do
	case $a in
	F) case $OPTARG in
	   ufs) COUNT=15;;
	   hsfs) COUNT=15;;
	   zfs) COUNT=31;;
	   *) away 1 "$OPTARG: Unknown fstype";;
	   esac;;
	?) away 1 "unknows fstype: $fs"
	esac
done
shift `expr $OPTIND - 1`

Usage="Usage: `basename $0` bootblk raw-device"

test $# -ne 2 && away 1 "$Usage"

BOOTBLK=$1
DEVICE=$2
test ! -f $BOOTBLK && away 1 "$BOOTBLK: File not found"
test ! -c $DEVICE && away 1 "$DEVICE: Not a character device"
test ! -w $DEVICE && away 1 "$DEVICE: Not writeable"

# label at block 0, bootblk from block 1 through 15
stderr=`dd if=$BOOTBLK of=$DEVICE bs=1b oseek=1 count=$COUNT conv=sync 2>&1`
err=$? ; test $err -ne 0 && away $err "$stderr"
exit 0
