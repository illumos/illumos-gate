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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 2000 by Sun Microsystems, Inc.
# All rights reserved.
#
# Startup script for Sun Fire 15000 Key Management Daemon
#

case "$1" in
'start')
	platform=${_INIT_UTS_PLATFORM:-`/sbin/uname -i`}
	starcat="SUNW,Sun-Fire-15000" 
	if [ ${platform} = "${starcat}" ]; then
		if [ -x /usr/platform/${platform}/lib/sckmd ]; then 
			/usr/platform/${platform}/lib/sckmd
		fi
	fi
	;;

'stop')
	/usr/bin/pkill -9 -x -u 0 sckmd
	;;

*)
	echo "Usage: $0 { start | stop }"
	exit 1
	;;
esac
exit 0
