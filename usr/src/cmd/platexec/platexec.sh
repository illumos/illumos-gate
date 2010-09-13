#!/usr/bin/sh
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
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Execute the platform-dependent version of a program, if it exists.
#

cmd=`basename $0`
platform=`/usr/bin/uname -i 2> /dev/null`

if [ $? -ne 0 ]
then
	echo "$cmd: could not determine platform" >& 2
else
	truepath=/usr/platform/$platform/sbin/$cmd

	if [ -x $truepath ]; then
		exec $truepath "$@"
	else
		echo "$cmd: not implemented on $platform" >& 2
	fi
fi

exit 255
