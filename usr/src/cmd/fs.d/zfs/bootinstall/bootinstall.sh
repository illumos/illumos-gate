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
# Copyright (c) 2015, Toomas Soome <tsoome@me.com>
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

PATH="/usr/bin:/usr/sbin:${PATH}"; export PATH
LOGGER="/bin/logger -t $0 -p daemon.notice"

POOL="$1"
DEV=$(echo "$2" | sed -e 's+/dsk/+/rdsk/+')

if [ -z "${POOL}" -o -z "${DEV}" ]; then
	$LOGGER "Invalid usage"
	exit 1
fi

CURPOOL=$(df -k / | awk 'NR == 2 {print $1}' | sed 's,/.*,,')

if [ "$CURPOOL" != "$POOL" ] ; then
	$LOGGER "Modified pool must be current root pool"
	exit 1
fi

/sbin/bootadm install-bootloader -f
if [ $? != 0 ]; then
	$LOGGER "Failure installing boot block on ${DEV}"
	exit 1
fi

exit 0
