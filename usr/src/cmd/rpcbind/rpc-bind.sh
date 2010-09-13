#! /sbin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# rpcbind method
#
# Argument is the method name.
#

. /lib/svc/share/smf_include.sh

RB_OPT="$1"
RB_EXIT=0
RB_DOOR="/var/run/rpc_door"

case ${RB_OPT} in
	"start")
		if [ ! -x /usr/sbin/rpcbind ]
		then
			echo "ERROR: /usr/sbin/rpcbind does not exist."
			exit $SMF_EXIT_ERR_CONFIG
		fi

		[ -d ${RB_DOOR} ] || /usr/bin/mkdir -p -m 1777 ${RB_DOOR}

		/usr/sbin/rpcbind > /dev/msglog 2>&1

		RB_EXIT=${?}

		if [ $RB_EXIT != 0 ]
		then
			echo "rpcbind failed with $RB_EXIT."
			RB_EXIT=1
		fi
	;;
	"stop")
		# Kill service contract
		smf_kill_contract $2 TERM 1
		[ $? -ne 0 ] && RB_EXIT=1
		/usr/bin/rm -fr ${RB_DOOR}
	;;
	*)
		RB_EXIT=$SMF_EXIT_ERR_CONFIG
	;;
esac

exit ${RB_EXIT}
