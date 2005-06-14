#!/bin/ksh
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
# Copyright 1993-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 
#ident	"%Z%%M%	%I%	%E% SMI"

opts=""
while getopts guplmsLv arg
do
	if [ "$arg" = "?" ]; then
		exit 1
	fi
	opts="$opts -$arg"
done

shift $(($OPTIND - 1))

if [ $# -le 3 ]; then
	echo "$0: at least 3 arguments required." >&2
	exit 1
fi

old="$1"; shift
new="$1"; shift
differ="$1"; shift

errlog=/tmp/protocmp.err.$$

protocmp $opts "$@" 2>$errlog |
	nawk -v old="$old" -v new="$new" -v differ="$differ" '
	/^\**$/ {
		next;
	}
	/^\* Entries/ {
		category++;
		next;
	}
	/^\* filea ==/ {
		filea = $NF;
		next;
	}
	/^\* fileb ==/ {
		fileb = $NF;
		next;
	}
	{
		buf[category, ++line[category]] = $0
	}
	END {
		if (line[1] > 2) {
			printf("\n%s\n\n", old);
			for (i = 1; i <= line[1]; i++) {
				print buf[1, i];
			}
		}
		if (line[2] > 2) {
			printf("\n%s\n\n", new);
			for (i = 1; i <= line[2]; i++) {
				print buf[2, i];
			}
		}
		if (line[3] > 2) {
			printf("\n%s\n\n", differ);
			for (i = 1; i <= line[3]; i++) {
				print buf[3, i];
			}
		}
	}'

if [ -s $errlog ]; then
	echo "\n====== protocmp ERRORS =====\n" 
	cat $errlog
fi
rm -f $errlog
