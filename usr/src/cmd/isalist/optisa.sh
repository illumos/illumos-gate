#!/bin/sh
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
#       Copyright (c) 1996 by Sun Microsystems, Inc. 
#	All Rights reserved.

PATH=/usr/bin:/usr/sbin

#ident	"%Z%%M%	%I%	%E% SMI"
#       isalist command 

if test $# -eq 0
then 
	echo "usage: $0 isalist"
	exit 1
fi

for i in `isalist`
do
        for j
        do
                if [ $i = $j ]
                then
                        echo $i
                        exit 0
                fi
        done
done
exit 1

