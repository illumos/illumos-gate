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
TEST_VNIC="bhyvetest_viona2"
TEST_VNIC2="bhyvetest_viona3"
TEST_IPTUN="bhyvetest_viona4"

# The mac_addr and rx_delivery tests create temporary VNICs atop ${TEST_NIC}
# for the duration of their runs.  Sweep any leftovers from an aborted run
# before the simnets themselves can be deleted.
for vnic in ${TEST_VNIC2} ${TEST_VNIC}; do
	if dladm show-vnic ${vnic} > /dev/null 2>&1; then
		log_must dladm delete-vnic ${vnic}
	else
		log_note "vnic ${vnic} already absent"
	fi
done

if dladm show-iptun ${TEST_IPTUN} > /dev/null 2>&1; then
	log_must dladm delete-iptun -t ${TEST_IPTUN}
else
	log_note "iptun ${TEST_IPTUN} already absent"
fi

for nic in ${TEST_NIC_PEER} ${TEST_NIC}; do
	if dladm show-simnet ${nic} > /dev/null 2>&1; then
		log_must dladm delete-simnet ${nic}
	else
		log_note "simnet link ${nic} already absent"
	fi
done

exit ${STF_PASS}
