#!/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2017, Joyent, Inc.
#

#
# Basic tests of date -r.
#

#
# Make sure that we're executing in the C locale and that a given user's
# locale doesn't impact this test.
#
export LANG=C

date_arg0="$(basename $0)"
date_prog=/usr/bin/date
date_curcmd=

fatal()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST FAILED: $date_arg0: $msg" >&2
	exit 1
}

compare()
{
	typeset time=$1
	typeset exp=$2
	typeset tz=$3
	typeset val ret

	date_curcmd="TZ=$3 $date_prog -r $1"
	val=$(TZ=$3 $date_prog -r $1)
	ret=$?
	if [[ $ret -ne 0 ]]; then
		fatal "date not exit zero, exited $ret; command: $date_curcmd"
	fi
	if [[ -z "$val" ]]; then
		fatal "date returned no output; command: $date_curcmd"
	fi

	if [[ "$val" != "$exp" ]]; then
		fatal "date output mismatch; command: $date_curcmd; expected: " \
		    "$exp; found: $val"
	fi
}

if [[ -n $DATE ]]; then
	date_prog=$DATE
fi

#
# date -r supports base 10, hex, and octal
#
compare 0 "Thu Jan  1 00:00:00 UTC 1970" UTC
compare 0 "Wed Dec 31 16:00:00 PST 1969" US/Pacific
compare 0 "Thu Jan  1 09:00:00 JST 1970" Japan
compare 1234567890 "Fri Feb 13 23:31:30 UTC 2009" UTC
compare -1234567890 "Tue Nov 18 00:28:30 UTC 1930" UTC
compare 2147483647 "Tue Jan 19 03:14:07 UTC 2038" UTC
compare -2147483647 "Fri Dec 13 20:45:53 UTC 1901" UTC
compare 558028800 "Mon Sep  7 16:00:00 UTC 1987" UTC
compare 0x2142d800 "Mon Sep  7 16:00:00 UTC 1987" UTC
compare 04120554000 "Mon Sep  7 16:00:00 UTC 1987" UTC

#
# Test the file related logic
#
touch -t 201712042323.23 $TMPDIR/test.$$
compare "$TMPDIR/test.$$" "Mon Dec  4 23:23:23 UTC 2017" UTC
rm -f $TMPDIR/test.$$

#
# date -r should not work with -a
#
if $date_prog -r 0 -a 10 2>/dev/null; then
	fatal "date -r 0 -a 10 exited zero when it should have failed"
fi

#
# date -r and -R or -u should work together
#
compare "0 -R" "Thu, 01 Jan 1970 02:00:00 +0200" Africa/Cairo
compare "0 -u" "Thu Jan  1 00:00:00 GMT 1970" Europe/Rome

echo "TEST PASSED: $date_arg0"
