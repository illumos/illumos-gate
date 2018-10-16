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
# ID: smbutil_006
#
# DESCRIPTION:
#        Verify smbutil view can handle invalid NETBIOS name
#
# STRATEGY:
#	1. run "smbutil view invalid", "smbutil view //invalid"
#	2. smbutil can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil006"
tc_desc="Verify smbutil view can handle invald server syntax"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

# this should fail
cmd="smbutil view //bad"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil view //bad succeeded"
	return
else
	cti_report "PASS: smbutil view //bad failed"
fi

# this should fail
cmd="smbutil view bad_bad"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil view bad_bad succeeded"
else
	cti_report "PASS: smbutil view bad_bad failed"
fi

# this should fail
cmd="smbutil view $server"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil view $server succeeded"
	return
else
	cti_report "PASS: smbutil view $server failed"
fi

cti_pass "${tc_id}: PASS"
