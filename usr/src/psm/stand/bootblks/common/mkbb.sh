#!/bin/ksh
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# defaults
bblen=7680
rdlen=256
totlen=7680

while getopts b:r:e: a; do
	case $a in
	b) bblen=$OPTARG;;
	r) rdlen=$OPTARG;;
	e) extra=$OPTARG
	   totlen=15872;;
	?) printf "Usage: %s: [ -b bb_len ] [ -r rd_len ] boot_fcode ramdisk_fcode bootblk\n" $0
	   exit -1;;
	esac
done
shift $(($OPTIND - 1))

#
# check boot code and ramdisk code for size overflow
#
rdoff=$(($bblen - $rdlen))

bbsize=$(ls -l $1 | awk -e '{ print $5 }')
if [ $bbsize -gt $rdoff ]; then
    printf "$1 must be smaller than $rdoff\n"
    exit -1
fi

rdsize=$(ls -l $2 | awk -e '{ print $5 }')
if [ $rdsize -gt $rdlen ]; then
    printf "$1 must be smaller than $rdlen\n"
    exit -1
fi

#
# make the bootblk
#
mkfile -n $totlen $3
chmod 644 $3
dd if=$1 of=$3 conv=notrunc bs=1
dd if=$2 of=$3 conv=notrunc bs=1 oseek=$rdoff

#
# extended bootblk for zfs debug
#
if [ $totlen -gt $bblen ]; then
    extsize=$(ls -l $extra | awk -e '{ print $5 }')
    if [ $extsize -gt 16384 ]; then
	printf "$1 must be smaller than 16k\n"
	exit -1
    fi
    dd if=$extra of=$3 conv=notrunc bs=1 oseek=$bblen
fi

exit 0
