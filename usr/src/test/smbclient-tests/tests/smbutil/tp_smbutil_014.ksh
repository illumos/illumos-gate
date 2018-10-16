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
# ID: smbutil_014
#
# DESCRIPTION:
#        Verify smbutil logoutall can work
#
# STRATEGY:
#	1. run "smbutil logoutall"
#	2. smbutil logoutall and smbutil login -c can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil014"
tc_desc="Verify smbutil logoutall can work"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

# initialize
sudo -n smbutil logoutall

cmd="$EXPECT $SMBUTILEXP $TUSER \$TPASS"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set passwd to $TUSER"
	return
else
	cti_report "PASS: smbutil login failed to set passwd to $TUSER"
fi

cmd="smbutil login -c $TUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: '$TUSER' keychain doesn't exist"
	return
else
	cti_report "PASS: '$TUSER' keychain exists"
fi

cmd="$EXPECT $SMBUTILEXP $AUSER \$APASS"
cti_execute_cmd sudo -n -u $AUSER $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set passwd to $TUSER"
	return
else
	cti_report "PASS: smbutil login failed to set passwd to $TUSER"
fi

cmd="smbutil login -c $AUSER | grep exists"
cti_execute_cmd sudo -n -u $AUSER $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the keychain doesn't exist"
	return
else
	cti_report "PASS: the keychain exists"
fi

cmd="sudo -n smbutil logoutall"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil logoutut can't work"
	return
else
	cti_report "PASS: smbutil logoutut can work"
fi

cmd="smbutil login -c $TUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: the $TUSER keychain exists"
	return
else
	cti_report "PASS: the $TUSER keychain doesn't exist"
fi

cmd="smbutil login -c $AUSER | grep exists"
cti_execute_cmd sudo -n -u $AUSER $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: the $AUSER keychain exists"
	return
else
	cti_report "PASS: the $AUSER keychain doesn't exist"
fi

cti_pass "${tc_id}: PASS"
