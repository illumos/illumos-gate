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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

PATH=/sbin:/usr/bin:/usr/sbin; export PATH

ZONENAME=$1
ZONEROOT=$2

# If the zone is already sys-unconfiged, then we're done.
if [ -f $ZONEROOT/etc/.UNCONFIGURED ]; then
	exit 0
fi

#
# Mount the zone.  The zone is still in the INCOMPLETE state, so we have to
# -f(orce) mount it.
#
zoneadm -z $ZONENAME mount -f
if [ $? -ne 0 ]; then
	echo `gettext "Could not mount zone for sys-unconfig"`
	exit 1
fi

# Log into the zone and sys-unconfig it.
zlogin -S $ZONENAME /usr/sbin/sys-unconfig -R /a
err=$?
if [ $err -ne 0 ]; then
	echo `gettext "sys-unconfig failed"`
fi

zoneadm -z $ZONENAME unmount
if [ $? -ne 0 ]; then
	echo `gettext "Could not unmount zone"`
	exit 1
fi

exit $err
