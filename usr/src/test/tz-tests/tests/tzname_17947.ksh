#!/usr/bin/ksh
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
# Copyright 2025 Oxide Computer Company
#

#
# This test serves as a basic regression test for #17947 where we were
# incorrectly determining the value of tzname[] for various POSIX-style
# timezones due to how we had updated the data and incorrect assumptions made
# around indexes that were thrown off with the addition of LMT.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

tz_dir=$(dirname $0)
tz_n32="$tz_dir/tznames.32"
tz_n64="$tz_dir/tznames.64"
tz_exit=0

#
# When there is no DST style time zone, then the following empty string is used.
#
tz_none="   "

test_one()
{
	if ! $tz_n32 "$1" "$2" "$3"; then
		tz_exit=1
	fi

	if ! $tz_n64 "$1" "$2" "$3"; then
		tz_exit=1
	fi
}

test_one UTC UTC "$tz_none"
test_one UTC0UTC UTC UTC
test_one GMT0GMT GMT GMT
test_one FOO0BAR FOO BAR
test_one America/New_York EST EDT
test_one CET0 CET "$tz_none"
test_one CET0CET CET CET
test_one CET0CEST CET CEST
test_one Asia/Tokyo JST JDT
test_one Europe/Rome CET CEST
test_one Australia/Brisbane AEST AEDT

if (( tz_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

exit $tz_exit
