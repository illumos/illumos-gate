#!/bin/sh
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
# Second SNDR start script
# - called after the TCP/IP stack has been initialised,
#   and networking enabled.
#
# - should be linked to /etc/rc2.d/S72rdcfinish as follows:
#
#       ln /etc/init.d/rdc /etc/rc2.d/S72rdcfinish
#
PATH=/etc:/bin
RDCD="/usr/lib/sndrd"
RDCSYNCD="/usr/lib/sndrsyncd"
USAGE="Usage: $0 start"

. /lib/svc/share/smf_include.sh

case "$1" in
'start')
	echo "Completing SNDR startup:\c"

	## 
	##	Start sndrd
	##

	if [ ! -f ${RDCD} ]
 	then
		echo "Cannot find ${RDCD}.\nSNDR services unavailable." > /dev/console
		exit $SMF_EXIT_MON_OFFLINE
	fi

	ps -e | grep sndrd > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		${RDCD}
		echo  " sndrd\c"
	else
		echo " sndrd already enabled\c"
	fi

	## 
	##	Start sndrsyncd
	##

	if [ ! -f ${RDCSYNCD} ]
 	then
 		echo "\nCannot find ${RDCSYNCD}.\nSNDR start aborted." > /dev/console
		exit $SMF_EXIT_MON_OFFLINE
	fi

	ps -e | grep sndrsyn > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		${RDCSYNCD}
		echo  " sndrsyncd\c"
	else
		echo " sndrsyncd already running\c"
	fi

	echo " done"
	;;
'stop')
	# Inserted for symmetry
	;;
*)
	echo $USAGE
	exit 1
	;;
esac
exit $SMF_EXIT_OK
