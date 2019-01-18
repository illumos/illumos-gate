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
# Copyright 2019 Joyent, Inc.
#

if [[ -z $NET_TESTS ]]; then
	echo "NET_TESTS not set" >&2
	exit 1
fi

. $NET_TESTS/tests/net_common
. $NET_TESTS/config/ip_forwarding.config

if [[ -z "$NT_CLIENT" ]]; then
	fail "NT_CLIENT must be set"
fi

if [[ -z "$NT_ROUTER" ]]; then
	fail "NT_ROUTER must be set"
fi

if [[ -z "$NT_SERVER" ]]; then
	fail "NT_SERVER must be set"
fi

export NT_TNAME=$(basename $0)
$NET_TESTS/tests/forwarding/ip_forwarding -fuv $NT_CLIENT $NT_ROUTER $NT_SERVER
exit $?
