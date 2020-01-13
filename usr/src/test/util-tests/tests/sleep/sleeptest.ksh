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
# Copyright 2019 Robert Mustacchi
#

#
# Basic tests of sleep(1). sleep is a little hard to test, especially
# for longer running cases. Therefore to test it, we basically take
# advantage of our knowledge of how it is implemented. We see that it
# properly is sleeping for the right amount of time by looking at the
# call to nanosleep in libc and make sure that the structures time is
# what we expect.
#

unalias -a
set -o pipefail

#
# Set the locale for the start of the test to be C.UTF-8 to make sure
# that we have a good starting point and correct fractional
# interpretation.
#
export LC_ALL=C.UTF-8

sleep_arg0="$(basename $0)"
sleep_prog=/usr/bin/sleep
sleep_dir="$(dirname $0)"
sleep_dscript=$sleep_dir/sleep.d
sleep_awk=$sleep_dir/sleep.awk
sleep_exit=0

#
# This is the factor by which we're going to basically say that the slp
# microstate has to complete within. Because the system will usually
# have a bit of additional latency, we will usually be greater than that
# as well. This determines how much we should actually do that by.
#
sleep_factor=1.5

warn()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST FAILED: $sleep_arg0: $msg" >&2
}

sleep_bound()
{
	typeset min=$1
	typeset test="sleep $min: bounding"

	ptime -m $sleep_prog $min 2>&1 | nawk -f $sleep_awk min=$min \
	    factor=$sleep_factor
	if [[ $? -ne 42 ]]; then
		warn "$test"
		sleep_exit=1
	else
		printf "TEST PASSED: %s\n" "$test"
	fi
}

sleep_one()
{
	typeset arg=$1
	typeset secs=$2
	typeset nsecs=$3
	typeset test="sleep $arg: $secs secs $nsecs ns"

	if ! dtrace -qws $sleep_dscript -c "$sleep_prog $arg" $secs $nsecs; then
		warn "$test"
		sleep_exit=1
	else
		printf "TEST PASSED: %s\n" "$test"
	fi
}

sleep_err()
{
	typeset test="negative test: sleep $*"

	if $sleep_prog $* 2>/dev/null; then
		warn "$test"
		sleep_exit=1
	else
		printf "TEST PASSED: %s\n" "$test"
	fi
}

if [[ -n $SLEEP ]]; then
	sleep_prog=$SLEEP
fi

#
# First test basic integer values. Both in base 10 and hex.
#
sleep_one 1 1 0
sleep_one 23 23 0
sleep_one 0xff 0xff 0
sleep_one 123456789 123456789 0
sleep_one 1e8 100000000 0

#
# Fractional values.
#
sleep_one 2.5 2 500000000
sleep_one 0.9 0 900000000
sleep_one 34.0051 34 5100000
sleep_one 0x654.100 0x654 62500000

#
# Large values that are basically the same as infinity. The current
# implementation will do a sleep in groups of INT32_MAX at a time. So
# make sure our large values are the same.
#
sleep_one Inf 0x7fffffff 0
sleep_one +Inf 0x7fffffff 0
sleep_one 1e100 0x7fffffff 0
sleep_one 0x123456789abc 0x7fffffff 0

#
# That all of our suffixes for time increments work and make sense.
#
sleep_one 1s 1 0
sleep_one 1m 60 0
sleep_one 1h 3600 0
sleep_one 1d 86400 0
sleep_one 1w 604800 0
sleep_one 1y 31536000 0

sleep_one 3.5s 3 500000000
sleep_one 3.6d 311040 0
sleep_one 2.001y 63103536 0

#
# Now we need to go through and use ptime -m to get the slp time for
# things and make sure it is always greater than what we asked for and
# less than a bound.
#
sleep_bound 0.01
sleep_bound 0.1
sleep_bound 0.25
sleep_bound 0.5
sleep_bound 0.75

#
# The next set of tests are negative tests that make sure that sleep
# does not correctly execute in these cases.
#
sleep_err \"\"
sleep_err 1 2 3
sleep_err 1@23
sleep_err 0,56
sleep_err "hello"
sleep_err s
sleep_err 1z
sleep_err -- -0.3

#
# Test a locale that uses a ',' character (de_DE.UTF-8 is one) as the
# decimal point to make sure that sleep correctly is using LC_NUMERIC.
#
export LANG=de_DE.UTF-8
sleep_err 21.45
sleep_one 2,5 2 500000000
sleep_one 34,0051 34 5100000
sleep_one 3,6d 311040 0
export LANG=C.UTF-8

exit $sleep_exit
