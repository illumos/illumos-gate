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
# Copyright 2016 Joyent, Inc.
#

#
# Test quick_exit(3C). We specifically test the following things:
#    o That we get a requested exit status
#    o That at_quick_exit() functions fire in a registered, reverse order.
#
# These are all done by helper programs
#

set -o errexit
set -o pipefail

qe_root=$(dirname $0)
qe_status32=$qe_root/quick_exit_status.32
qe_status64=$qe_root/quick_exit_status.64
qe_order32=$qe_root/quick_exit_order.32
qe_order64=$qe_root/quick_exit_order.64

function fatal
{
	typeset msg="$*"
	echo "Test Failed: $msg" >&2
	exit 1	
}

function check_status
{
	typeset stat=$1
	$qe_status32 $stat
	if [[ $? -ne $stat ]]; then
		fatal "Test failed: Expected $qestatus32 to exit $stat " \
		    "got $?"
	fi

	$qe_status64 $stat
	if [[ $? -ne $stat ]]; then
		fatal "Test failed: Expected $qestatus64 to exit $stat " \
		    "got $?" >&2
	fi
}

function check_order
{
	$qe_order32 || fatal "$qe_order32 returned $?"
	$qe_order64 || fatal "$qe_order32 returned $?"
}

check_status 0
check_status 23
check_status 42
check_order
exit 0
