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
# ID: smbutil_001
#
# DESCRIPTION:
#        Verify smbutil can handle invalid arguments
#
# STRATEGY:
#        1. run "smbutil" ...
#        2. smbutil can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil001"
tc_desc="Verify smbutil can handle error arg"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

cti_execute_cmd "rm -f core"

cti_execute_cmd "smbutil lookup"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil lookup succeeded"
	return
else
	cti_report "PASS: smbutil lookup failed"
fi

cti_execute_cmd "smbutil"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil succeeded"
	return
else
	cti_report "PASS: smbutil failed"
fi

cti_execute_cmd "smbutil status"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil status succeeded"
	return
else
	cti_report "PASS: smbutil status failed"
fi

cti_execute_cmd "smbutil -a"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil -a suceeded"
	return
else
	cti_report "PASS: smbutil status failed"
fi

if [[ -f core ]]; then
	cti_fail "FAIL: smbutil coredump"
	return
fi

cti_pass "${tc_id}: PASS"
