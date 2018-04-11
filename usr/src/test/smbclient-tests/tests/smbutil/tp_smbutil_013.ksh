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
# ID: smbutil_013
#
# DESCRIPTION:
#        Verify smbutil logout -a can works
#
# STRATEGY:
#	1. run "smbutil login -c $TUSER"
#	2. smbutil login and smbutil view can get right message
#	3. smbutil logout -a can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil013"
tc_desc="Verify smbutil login -a works"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

# initialize
sudo -n smbutil logoutall

cmd="$EXPECT $SMBUTILEXP $TUSER \$TPASS"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set password for user '$TUSER'"
	return
else
	cti_report "PASS: smbutil login successfully set password for user '$TUSER'"
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
	cti_fail "FAIL: smbutil can view the shares"
	return
else
	cti_report "PASS: smbutil can't view the shares"
fi

parse_view_output public cti_stdout
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil view can't get the public share"
	return
else
	cti_report "PASS: smbutil view can get the public share"
fi

cmd="$EXPECT $SMBUTILEXP $AUSER $APASS"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set passwd to $AUSER"
	return
else
	cti_report "PASS: smbutil login succeeded to set passwd to $AUSER"
fi

cmd="smbutil login -c $AUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: '$AUSER' keychain doesn't exist"
	return
else
	cti_report "PASS: '$AUSER' keychain exists"
fi

cmd="smbutil view //$AUSER@$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil can't view shares"
	return
else
	cti_report "PASS: smbutil can view shares"
fi

parse_view_output public cti_stdout
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil can't get the public share"
	return
else
	cti_report "PASS: smbutil can get the public share"
fi

cti_execute_cmd "smbutil logout -a"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil logout -a doesn't work"
	return
else
	cti_report "smbutil logout -a works"
fi

cmd="smbutil login -c $TUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: '$TUSER' keychain exists"
	return
else
	cti_report "PASS: '$TUSER' keychain doesn't exist"
fi

cmd="smbutil login -c $AUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: '$AUSER' keychain exists"
	return
else
	cti_report "PASS: '$AUSER' keychain doesn't exist"
fi

cti_pass "${tc_id}: PASS"
