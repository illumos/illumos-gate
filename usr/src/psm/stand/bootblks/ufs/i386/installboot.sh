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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PATH=/usr/bin

away() {
	echo $2 1>&2
	exit $1
}

Error="Error: `basename $0` is obsolete. Use installgrub(1M)"
Usage="Usage: `basename $0` --force_realmode pboot bootblk raw-device"

test $# -ne 4 && away 1 "$Error"
test $1 != "--force_realmode" && away 1 "$Error"
shift 1

PBOOT=$1
BOOTBLK=$2
DEVICE=$3
test ! -f $PBOOT && away 1 "$PBOOT: File not found"
test ! -f $BOOTBLK && away 1 "$BOOTBLK: File not found"
test ! -c $DEVICE && away 1 "$DEVICE: Not a character device"
test ! -w $DEVICE && away 1 "$DEVICE: Not writeable"

# pboot at block 0, label at blocks 1 and 2, bootblk from block 3 on
stderr=`dd if=$PBOOT of=$DEVICE bs=1b count=1 conv=sync 2>&1`
err=$? ; test $err -ne 0 && away $err "$stderr"
stderr=`dd if=$BOOTBLK of=$DEVICE bs=1b oseek=3 conv=sync 2>&1`
err=$? ; test $err -ne 0 && away $err "$stderr"
exit 0
