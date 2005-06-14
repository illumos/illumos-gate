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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1991 by Sun Microsystems, Inc.
#
#
# Replace /usr/ucb/df
#

ARG=-k
count=1
num=$#

if [ $# -lt 1 ]
then
	/usr/sbin/df $ARG
        exit $?
fi

while [ "$count" -le "$num" ]
do
	flag=$1
	case $flag in
	'-a')
		ARG="$ARG -a"
		;;
	'-t')
		ARG="$ARG -F"
		shift
		if [ "$1" = "4.2" ]
		then
			ARG="$ARG ufs"
		else
			ARG="$ARG $1"
		fi
		count=`expr $count + 1`
		;;
	'-i')
		ARG="$ARG -F ufs -o i"
		;;
	*)
		ARG="$ARG $flag"
                ;;
	esac
	if [ "$count" -lt "$num" ]
	then
		shift
	fi
	count=`expr $count + 1`
done
/usr/sbin/df $ARG
exit $?
