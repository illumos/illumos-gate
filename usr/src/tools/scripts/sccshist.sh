#!/bin/ksh -p
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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 
#ident	"%Z%%M%	%I%	%E% SMI"
#
#  Print sccs history of a file with
#  comment and differences for each delta.
#
# With the -r invocation style, only the deltas between the given sids are
# printed.  sccshist -r1.2 -r1.3, for example, prints the SID description for
# 1.3, followed by the diffs between 1.2 and 1.3.  The SID description for 1.2
# is not printed.
#
# With the -n invocation style, deltas to a given number of SIDs are printed.
# Given a file with 1.5, 1.4, ... 1.1, sccshist -n 2 will print the 1.5 SID
# header, 1.4 -> 1.5 diffs, the 1.4 SID header, and 1.3 -> 1.4 diffs.
#

PROGNAME=$(basename "$0")

SCCS=/usr/ccs/bin/sccs

die()
{
	echo "$PROGNAME: $@" >&2
	exit 1
}

usage()
{
	echo "Usage: $PROGNAME [-c|-u] [-r lowsid [-r highsid]] file" >&2
	echo "       $PROGNAME [-c|-u] [-n nsids] file" >&2
	exit 2
}

lowsid=
highsid=
typeset -i nsids=0
diffflags=

while getopts "cn:r:u" c ; do
	case $c in
	    c|u)
		[[ -n "$diffflags" ]] && usage
	    	diffflags="-$c"
		;;
	    n)
		expr "X$OPTARG" : 'X[0-9]*$' >/dev/null || usage
		nsids="$OPTARG"
		;;
	    r)
		if [[ -n "$highsid" ]] ; then
			usage
		elif [[ -n "$lowsid" ]] ; then
			highsid="$OPTARG"
		else
			lowsid="$OPTARG"
		fi
		;;
	    *)
		usage
		;;
	esac
done
shift $(($OPTIND - 1))

[[ -n "$lowsid" && $nsids -ne 0 ]] && usage
[[ $# -ne 1 ]] && usage

FILE=$1

[[ -r "$FILE" ]] || die "failed to open $FILE"

tmpf1=/tmp/sid1.$$
tmpf2=/tmp/sid2.$$
trap "rm -f $tmpf1 $tmpf2 ; exit" 0 1 2 3 15

#
# The main processing loop.  A new SID triggers a printing of the diffs between
# the new SID and the last one.  If there is no previous SID (if we're looking
# at the first one), no diff is printed.
#
if [[ -z "$highsid" ]] ; then
	printing=1
else
	printing=0
fi

typeset -i last=0
typeset -i count=0

$SCCS prt $FILE | while read LINE ; do
	set - $LINE

	if [[ $printing -eq 0 ]] ; then
		if [[ "$2" = "$highsid" ]] ; then
			printing=1
		else
			continue
		fi
	fi

	if [[ $1 != "D" ]] ; then
		echo "$LINE"
		continue
	fi

	# We calculate `last' before printing the diff, and defer breaking out
	# of the loop until after the diff, because we want to act upon the
	# value during the diff.
	[[ -n "$lowsid" && $printing -eq 1 && "$2" = "$lowsid" ]] && last=1
	if [[ "$nsids" -ne 0 ]] ; then
		count=$(($count + 1))
		[[ $count -gt $nsids ]] && last=1
	fi

	$SCCS get -s -p -k -r$2 $FILE > $tmpf1
	if [[ -r $tmpf2 ]] ; then
		diff -wt $diffflags $tmpf1 $tmpf2
		if [[ $last -eq 0 ]] ; then
			echo "________________________________________________________"
		fi
	fi
	mv $tmpf1 $tmpf2

	[[ $last -eq 1 ]] && break

	echo "$LINE"	# The new SID delta line
done
