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
# Copyright 2020 Tintri by DDN, Inc. All rights reserved.
#

if [[ -z $MLRPC_TESTS ]]; then
	echo "MLRPC_TESTS not set" >&2
	exit 1
fi

. $MLRPC_TESTS/cfg/samlogon.config

$MLRPC_TESTS/tests/netrlogon/samlogon_tests/samlogon $NETBIOS_DOMAIN $DC_FQDN \
    $USERNAME $CLIENT_COMPUTER $CHALLENGE_FILE $NT_RESPONSE_FILE \
    $LM_RESPONSE_FILE
exit $?
