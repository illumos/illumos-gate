#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
#

#
# ID: smbutil_004
#
# DESCRIPTION:
#        Verify smbutil status can handle invalid hostname
#
# STRATEGY:
#	1. run "smbutil status  invalid"
#	2. get correct help message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil004"
tc_desc="Verify smbutil status can handle error arg"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

cti_execute_cmd "smbutil status bad"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil status bad succeeded"
	return
else
	cti_report "PASS: smbutil status bad failed"
fi

cti_pass "${tc_id}: PASS"
