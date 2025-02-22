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
# This takes a few historical transition points in US time zones and verifies
# that we still see the expected date formats for a given POSIX time.  In
# particular we look at DST transitions before and after the Energy Policy Act
# of 2005 which changed the range of time that DST was in effect for.
#
# In addition, we use a few different time zones with the same time_t value to
# confirm that basic time zone functionality works. We also use some POSIX time
# zone strings. Note, strings that begin with a ':' according to POSIX use an
# implementation defined scheme, which for us is the same as the normal zoneinfo
# database.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

#
# Program paths that we allow someone to interpose on.
#
DATE=${DATE:-"/usr/bin/date"}

btz_exit=0

typeset -A btz_tzs=(
	["CHI (0)"]=(zone="America/Chicago" ts="834971400"
	    res="Sun Jun 16 19:30:00 CDT 1996")
	["CHI (1)"]=(zone="America/Chicago" ts="866253600"
	    res="Fri Jun 13 21:00:00 CDT 1997")
	["CHI (2)"]=(zone="America/Chicago" ts="897876000"
	    res="Sun Jun 14 21:00:00 CDT 1998")
	["CHI (3)"]=(zone="CST6CDT,M3.2.0/2:00:00,M11.1.0/2:00:00"
	    ts="834971400" res="Sun Jun 16 19:30:00 CDT 1996")
	["CHI (4)"]=(zone="CST6CDT,M3.2.0/2:00:00,M11.1.0/2:00:00"
	    ts="866253600" res="Fri Jun 13 21:00:00 CDT 1997")
	["CHI (5)"]=(zone="CST6CDT,M3.2.0/2:00:00,M11.1.0/2:00:00"
	    ts="866253600" res="Fri Jun 13 21:00:00 CDT 1997")
	["PST (0)"]=(zone="US/Pacific" ts="1080738123"
	    res="Wed Mar 31 05:02:03 PST 2004")
	["PST (1)"]=(zone="US/Pacific" ts="1082728984"
	    res="Fri Apr 23 07:03:04 PDT 2004")
	["PST (2)"]=(zone="US/Pacific" ts="1680267723"
	    res="Fri Mar 31 06:02:03 PDT 2023")
	["PST (3)"]=(zone="US/Pacific" ts="1682258584"
	    res="Sun Apr 23 07:03:04 PDT 2023")
	["PST (4)"]=(zone="US/Pacific" ts="969650527"
	    res="Fri Sep 22 12:22:07 PDT 2000")
	["PST (5)"]=(zone="US/Pacific" ts="1095880927"
	    res="Wed Sep 22 12:22:07 PDT 2004")
	#
	# These variants hard code the transition points which means that they
	# should differ from the PST examples above which follow Olson. Note the
	# way to read M3.2.0 is the first day (Sunday) of the second week of the
	# 3rd month (March).
	#
	["PST/POSIX (0)"]=(zone="PST8PDT,M3.2.0/2:00:00,M11.1.0/2:00:00" ts="1080738123"
	    res="Wed Mar 31 06:02:03 PDT 2004")
	["PST/POSIX (1)"]=(zone="PST8PDT,M3.2.0/2:00:00,M11.1.0/2:00:00" ts="1079254984"
	    res="Sun Mar 14 01:03:04 PST 2004")
	["PST/POSIX (2)"]=(zone="PST8PDT,M3.2.0/2:00:00,M11.1.0/2:00:00" ts="1079258584"
	    res="Sun Mar 14 03:03:04 PDT 2004")
	["PST/POSIX (3)"]=(zone="PST8PDT,M3.2.0/2:00:00,M11.1.0/2:00:00" ts="941965199"
	    res="Sun Nov  7 01:59:59 PDT 1999")
	["PST/POSIX (4)"]=(zone="PST8PDT,M3.2.0/2:00:00,M11.1.0/2:00:00" ts="941968799"
	    res="Sun Nov  7 01:59:59 PST 1999")
	["World (Auckland)"]=(zone="Pacific/Auckland" ts="946684800"
	    res="Sat Jan  1 13:00:00 NZDT 2000")
	["World (Belize)"]=(zone="America/Belize" ts="946684800"
	    res="Fri Dec 31 18:00:00 CST 1999")
	["World (Brisbane)"]=(zone="Australia/Brisbane" ts="946684800"
	    res="Sat Jan  1 10:00:00 AEST 2000")
	["World (Brisbane, ':')"]=(zone=":Australia/Brisbane" ts="946684800"
	    res="Sat Jan  1 10:00:00 AEST 2000")
	["World (Casablanca)"]=(zone="Africa/Casablanca" ts="946684800"
	    res="Sat Jan  1 00:00:00 +01 2000")
	["World (Damascus)"]=(zone="Asia/Damascus" ts="946684800"
	    res="Sat Jan  1 02:00:00 +03 2000")
	["World (Egypt)"]=(zone="Egypt" ts="946684800"
	    res="Sat Jan  1 02:00:00 EET 2000")
	["World (GMT)"]=(zone="GMT" ts="946684800"
	    res="Sat Jan  1 00:00:00 GMT 2000")
	["World (Guam)"]=(zone="Pacific/Guam" ts="946684800"
	    res="Sat Jan  1 10:00:00 ChST 2000")
	["World (Hong Kong)"]=(zone="Hongkong" ts="946684800"
	    res="Sat Jan  1 08:00:00 HKT 2000")
	["World (Japan)"]=(zone="Japan" ts="946684800"
	    res="Sat Jan  1 09:00:00 JST 2000")
	["World (Japan/POSIX)"]=(zone="JST-9" ts="946684800"
	    res="Sat Jan  1 09:00:00 JST 2000")
	["World (London)"]=(zone="Europe/London" ts="946684800"
	    res="Sat Jan  1 00:00:00 GMT 2000")
	["World (London/POSIX)"]=(zone="BST0GMT,M3.2.0/2:00:00,M11.1.0/2:00:00"
	    ts="946684800" res="Sat Jan  1 00:00:00 BST 2000")
	["World (Longyearbyen)"]=(zone="Arctic/Longyearbyen" ts="946684800"
	    res="Sat Jan  1 01:00:00 CET 2000")
	["World (Manila)"]=(zone="Asia/Manila" ts="946684800"
	    res="Sat Jan  1 08:00:00 PST 2000")
	["World (McMurdo)"]=(zone="Antarctica/McMurdo" ts="946684800"
	    res="Sat Jan  1 13:00:00 NZDT 2000")
	["World (Rome)"]=(zone="Europe/Rome" ts="946684800"
	    res="Sat Jan  1 01:00:00 CET 2000")
	["World (Singapore)"]=(zone="Singapore" ts="946684800"
	    res="Sat Jan  1 08:00:00 +08 2000")
	["World (St. Thomas)"]=(zone="America/St_Thomas" ts="946684800"
	    res="Fri Dec 31 20:00:00 AST 1999")
	["World (Tunis)"]=(zone="Africa/Tunis" ts="946684800"
	    res="Sat Jan  1 01:00:00 CET 2000")
	["World (Tunis, ':')"]=(zone=":Africa/Tunis" ts="946684800"
	    res="Sat Jan  1 01:00:00 CET 2000")
	["World (UTC)"]=(zone="UTC" ts="946684800"
	    res="Sat Jan  1 00:00:00 UTC 2000")
)

test_one()
{
	typeset key="$1"
	typeset out=
	typeset -n data=btz_tzs[$key]

	out=$(TZ=${data.zone} $DATE -r ${data.ts})
	if [[ "$out" != "${data.res}" ]]; then
		printf "TEST FAILED: %s: expected %s, found %s\n" "$key" \
		    "${data.res}" "$out" >&2
		btz_exit=1
	else
		printf "TEST PASSED: %s: %s\n" "$key" "$out"
	fi
}

for i in "${!btz_tzs[@]}"; do
	test_one "$i"
done

if (( btz_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

exit $btz_exit
