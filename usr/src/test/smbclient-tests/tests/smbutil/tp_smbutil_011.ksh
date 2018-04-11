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
# ID: smbutil_011
#
# DESCRIPTION:
#        Verify smbutil view failed with incorrect password
#
# STRATEGY:
#	1. smbutil failed with incorrect password
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil011"
tc_desc=" Verify smbutil  can failed with wrong passwd"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

# get rid of our connection first
cti_execute_cmd "smbutil discon //$AUSER:a@$server"
sleep 1

cti_report "expect failure next"
cmd="smbutil view -N //$AUSER:a@$server"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil can view private $AUSER with incorrect password"
	return
else
	cti_report "PASS: smbutil can't view private $AUSER with incorrect password"
fi

cti_pass "${tc_id}: PASS"
