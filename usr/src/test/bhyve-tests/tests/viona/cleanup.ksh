#! /usr/bin/ksh
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
# Copyright 2024 Oxide Computer Company
#

STF_TOOLS="/opt/test-runner/stf"
. ${STF_TOOLS}/contrib/include/logapi.shlib

TEST_NIC="bhyvetest_viona0"

if dladm show-simnet ${TEST_NIC} > /dev/null 2>&1; then
	log_must dladm delete-simnet ${TEST_NIC}
	exit ${STF_PASS}
else
	log_pass "simnet link ${TEST_NIC} already absent"
fi
