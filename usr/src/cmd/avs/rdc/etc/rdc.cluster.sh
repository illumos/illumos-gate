#!/usr/bin/ksh
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
# SNDR start script
#
# Description:	This is the SNDR switchover script.
#		It is used to start or stop a specified cluster
#		resource group when invoked from the data service cluster
#		failover script.
#

PATH=/etc:/bin
RDCBOOT="/usr/sbin/sndrboot"
RDCSYNCD="/usr/lib/sndrsyncd"
USAGE="Usage: $0 {start|stop} cluster_resource"

SVCS=/usr/bin/svcs
SVCS_NAME=system/nws_rdc

# Determine if SMF service is online
#
ONLINE=`$SVCS -D $SVCS_NAME 2>>/dev/null | grep "^online"`
if [ -z $ONLINE ]
then
	echo "$SVCS_NAME not online"
	exit 1
fi

if [[ -z "$2" ]]
then
	echo "$USAGE"
	exit 1
fi

case "$1" in
'start')
	if [[ -x $RDCBOOT ]]
	then
		$RDCBOOT -r -C "$2"
	fi
	;;

'stop')
	if [[ -x $RDCBOOT ]]
	then
		$RDCBOOT -s -C "$2"
	fi
	;;

*)
	echo $USAGE
	exit 1
	;;
esac
