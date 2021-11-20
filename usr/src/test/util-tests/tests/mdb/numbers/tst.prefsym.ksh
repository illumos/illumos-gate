#!/usr/bin/ksh
#
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
# Copyright 2021 Oxide Computer Company
#

#
# This test is trying to ensure that mdb still respects symbols over
# numbers that look similar.
#

set -o pipefail

tst_root="$(dirname $0)/.."
tst_prog="$tst_root/progs/number_symbol"
tst_sym0="ffffabcde00"
tst_sym1="ffffab_cde00"
tst_sym2="_007"
tst_out=
tst_err=0

$MDB -e "$tst_sym0=K" $tst_prog | grep -q "$tst_sym0"
if (( $? == 0 )); then
	printf >&2 "%s=K somehow returned itself, did it become a number?\n" \
	    "$tst_sym0"
fi

$MDB -e "$tst_sym0/K | ::eval ./s" $tst_prog | grep -q 'Am I a string?'
if (( $? != 0 )); then
	printf >&2 "Failed to find expected output for %s\n" "$tst_sym0"
	tst_err=1
fi

#
# We grep against tst_sym0 as if mdb does interpret this as a number,
# then it'll show it without the '_' characters.
#
$MDB -e "$tst_sym1=K" $tst_prog | grep -q "$tst_sym0"
if (( $? == 0 )); then
	printf >&2 "%s=K somehow returned itself, did it become a number?\n" \
	    "$tst_sym0"
	tst_err=1
fi

$MDB -e "$tst_sym1/K | ::eval ./s" $tst_prog | grep -q 'I am not a string'
if (( $? != 0 )); then
	printf >&2 "Failed to find expected output for %s\n" "$tst_sym1"
	tst_err=1
fi

$MDB -e "$tst_sym2=K" $tst_prog | grep -q "$tst_sym2"
if (( $? == 0 )); then
	printf >&2 "%s=K somehow returned itself, did it become a number?\n" \
	    "$tst_sym2"
	tst_err=1
fi

$MDB -e "$tst_sym2::dis" $tst_prog | egrep -qi '^_007:'
if (( $? != 0 )); then
	printf >&2 "Failed to find expected output for %s::dis\n" "$tst_sym2"
	tst_err=1
fi

exit $tst_err
