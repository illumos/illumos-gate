#! /bin/ksh
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#

################## Check parameters #################################

if [ $# -lt 3 -o $# -gt 4 ]; then
	echo "Usage: `basename $0` TITLE OKBUTTONTEXT [CANCELBUTTONTEXT]"
	exit 127
fi

################## Create the Main UI #################################

messageString="$1"
dialogTitle="$2"

if [ $# -eq 4 -a "$4" != "" ];then
	type="--question"
else
	type="--info"
fi

reply=$(/usr/bin/zenity $type \
	--title="$dialogTitle" \
	--height=100 \
	--width=200 \
	--text="$messageString")
exit $reply
