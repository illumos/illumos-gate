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
#

if [ ! -d /usr/sbin -o ! -d /usr/bin ]
then
	exit 1
fi

# Constants

SVBOOT=/usr/sbin/svboot
SVCS=/usr/bin/svcs
SVCS_NAME=system/nws_sv

# Functions

# main program

# Determine if SMF service is online
#
ONLINE=`$SVCS -D $SVCS_NAME 2>>/dev/null | grep "^online"`
if [ -z $ONLINE ]
then
	echo "$SVCS_NAME not online"
	exit 1
fi

if [[ ! -x $SVBOOT ]]
then
	echo "$0: cannot find $SVBOOT"
	exit 1
fi

if [[ -z "$2" ]]
then
	opt=usage
else
	opt=$1
fi

case "$opt" in
'start')
	$SVBOOT -C "$2" -r
	;;

'stop')

	$SVBOOT -C "$2" -s
	;;

*)
	echo "Usage: $0 { start | stop } cluster_resource"
	exit 1
	;;
esac
