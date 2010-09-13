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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# sn1 boot script.
#
# The argument to this script is the root of the zone.
#

PATH=/sbin:/usr/bin:/usr/sbin; export PATH

ZONEROOT=$1

if [ `uname -p` = "i386" ]; then
	ARCH64=amd64
elif [ `uname -p` = "sparc" ]; then
	ARCH64=sparcv9
else
	echo "Unsupported architecture: " `uname -p` >&2
	exit 2
fi

exit 0
