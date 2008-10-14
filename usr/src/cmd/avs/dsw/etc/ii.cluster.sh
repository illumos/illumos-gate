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
CMD=/usr/sbin/iiboot
SVCS=/usr/bin/svcs
SVCS_NAME=system/nws_ii

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
	opt=usage
else
	opt=$1
fi

case $opt in
'start')
	if [[ -x $CMD ]]
	then
		$CMD -C "$2" -r > /dev/null 2>&1
	fi
	;;

'stop')
	if [[ -x $CMD ]]
	then
		$CMD -C "$2" -s > /dev/null 2>&1
	fi
	;;

*)
	echo "usage: ii {start|stop} cluster_resource"
	;;
esac
