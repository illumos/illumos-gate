#!/bin/ksh -p
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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

PATH="/usr/bin:/usr/sbin:${PATH}"; export PATH
ARCH=$(uname -p)
KARCH=$(uname -m)

if [ "$ARCH" != "i386" -a "$ARCH" != "sparc" ] ; then
	echo "Unknown architecture: $ARCH"
	exit 1
fi

POOL="$1"
DEV=$(echo "$2" | sed -e 's+/dsk/+/rdsk/+')

if [ -z "${POOL}" -o -z "${DEV}" ]; then
	echo "Invalid usage"
	exit 1
fi

CURPOOL=$(df -k / | awk 'NR == 2 {print $1}' | sed 's,/.*,,')

if [ "$CURPOOL" != "$POOL" ] ; then
	echo "Modified pool must be current root pool"
	exit 1
fi

#
# 

if [ "${ARCH}" = "i386" ]; then
	STAGE1=/boot/grub/stage1
	STAGE2=/boot/grub/stage2
	/sbin/installgrub ${STAGE1} ${STAGE2} ${DEV}
	if [ $? != 0 ]; then
		echo "Failure installing GRUB on ${DEV}"
		exit 1
	fi
else
	BOOTBLK=/usr/platform/${KARCH}/lib/fs/zfs/bootblk
	/usr/sbin/installboot -F zfs ${BOOTBLK} ${DEV}
	if [ $? != 0 ]; then
		echo "Failure installing boot block on ${DEV}"
		exit 
	fi
fi

exit 0
