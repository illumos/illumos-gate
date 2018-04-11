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
# ID: smbutil_005
#
# DESCRIPTION:
#        Verify smbutil logoutall could work
#
# STRATEGY:
#	1. set up smb server on a test machine
#	2. run "smbutil logoutall"
#	3. smbutil logout and smbutil login can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil005"
tc_desc="Verify smbutil logout could work"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

# initialize
sudo -n smbutil logoutall

cmd="$EXPECT $SMBUTILEXP $TUSER $TPASS"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set passwd"
	return
else
	cti_report "PASS: smbutil login succeeded to set passwd"
fi

cmd="smbutil login -c $TUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: keychain doesn't exist"
	return
else
	cti_report "PASS: keychain exists"
fi

cmd="smbutil view //$TUSER@$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil can't view shares"
	return
else
	cti_report "PASS: smbutil can view shares"
fi

parse_view_output public cti_stdout
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil view can't get the public share"
	return
else
	cti_report "PASS: smbutil view can get the public share"
fi

cmd="smbutil logout $TUSER"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil logout failed"
	return
else
	cti_report "PASS: smbutil logout succeeded"
fi

cmd="smbutil login -c $TUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: keychain exists"
	return
else
	cti_report "PASS: keychain doesn't exist"
fi

# get rid of our connection first
cti_execute_cmd "smbutil discon //$TUSER@$server"
sleep 1

cti_report "expect failure next"
cmd="smbutil view -N //$TUSER@$server"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_execute_cmd "echo ::nsmb_vc|mdb -k"
	cti_fail "FAIL: smbutil can view shares"
	return
else
	cti_report "PASS: smbutil can't view shares"
fi

cti_pass "${tc_id}: PASS"
