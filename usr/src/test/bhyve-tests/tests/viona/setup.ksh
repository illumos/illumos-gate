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
# Copyright 2026 Oxide Computer Company
#

STF_TOOLS="/opt/test-runner/stf"
. ${STF_TOOLS}/contrib/include/logapi.shlib

TEST_NIC="bhyvetest_viona0"
TEST_NIC_PEER="bhyvetest_viona1"
TEST_IPTUN="bhyvetest_viona4"

if ! dladm show-simnet ${TEST_NIC} > /dev/null 2>&1; then
	log_must dladm create-simnet ${TEST_NIC}
fi

if ! dladm show-simnet ${TEST_NIC_PEER} > /dev/null 2>&1; then
	log_must dladm create-simnet ${TEST_NIC_PEER}
fi

# Peer the simnets unconditionally, in case they pre-existed unpeered
log_must dladm modify-simnet -p ${TEST_NIC} ${TEST_NIC_PEER}

# An addressless IP tunnel supplies non-Ethernet media for create_delete.
if ! dladm show-iptun ${TEST_IPTUN} > /dev/null 2>&1; then
	log_must dladm create-iptun -t -T ipv4 ${TEST_IPTUN}
fi

exit ${STF_PASS}
