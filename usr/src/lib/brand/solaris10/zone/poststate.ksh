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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. /usr/lib/brand/solaris10/common.ksh

# States
# ZONE_STATE_CONFIGURED           0 (never see)
# ZONE_STATE_INCOMPLETE           1 (never see)
# ZONE_STATE_INSTALLED            2
# ZONE_STATE_READY                3
# ZONE_STATE_RUNNING              4
# ZONE_STATE_SHUTTING_DOWN        5
# ZONE_STATE_DOWN                 6
# ZONE_STATE_MOUNTED              7

# cmd
#
# ready			0
# boot			1
# halt			4

zonename=$1
zonepath=$2
state=$3
cmd=$4

# If we're readying the zone, update the zone index file to look like this is
# the global zone.
if (( $cmd == 0 )); then
	echo "global:installed:/" > $zonepath/root/etc/zones/index
fi

exit 0
