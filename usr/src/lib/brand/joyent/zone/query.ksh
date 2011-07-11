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
# Copyright (c) 2011, Oracle and/or its affiliates. All rights reserved.
#

PATH=/usr/bin:/usr/sbin
export PATH

. /usr/lib/brand/shared/common.ksh

zonename=$1
zonepath=$2
cmd=$3

if [ $3 == "env" ]; then
	#
	# zoneadmd reads one (arbitrary length) line of input from the query
	# hook.  If there is more than one environment variable to pass back,
	# delimit each one with tabs.  zoneadmd will split the line at the tabs
	# and set each key/value pair in its environment.
	#
	# Currently, only _ZONEADMD_ZPOOL is used to set the %P substitution
	# for the brand configuration.
	#
	entry=$(svccfg -s smartdc/init listprop '*/zpool')
	if [ -n "$entry" ]; then
		val=${entry##* * }
		[ -n "$val" ] && echo "_ZONEADMD_ZPOOL=/${val}\c"
	fi
fi

exit $ZONE_SUBPROC_OK
