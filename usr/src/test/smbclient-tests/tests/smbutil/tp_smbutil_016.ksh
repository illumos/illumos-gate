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
# ID: smbutil_016
#
# DESCRIPTION:
#        Verify smbutil login works
#
# STRATEGY:
#	1. run "smbutil login -c" command
#	2. run "smbutil logout" command
#	3. smbutil commands can get right messages
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil016"
tc_desc="Verify smbutil login can work"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

# cleanup the keychains
smbutil logout -a
cmd="$EXPECT $SMBUTILEXP ${TUSER}@mygroup \$TPASS"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set passwd"
	return
else
	cti_report "PASS: smbutil login succeeded to set passwd"
fi

cmd="smbutil login -c mygroup/$TUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the keychain doesn't exist"
	return
else
	cti_report "PASS: the keychain exists"
fi

cmd="smbutil logout mygroup/$TUSER"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the smbutil logout failed"
	return
else
	cti_report "PASS: the smbutil logout succeeded"
fi

cmd="smbutil login -c mygroup/$TUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: the keychain exists"
	return
else
	cti_report "PASS: the keychain doesn't exists"
fi

cmd="$EXPECT $SMBUTILEXP mygroup/${TUSER} \$TPASS"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set passwd"
	return
else
	cti_report "PASS: smbutil login succeeded to set passwd"
fi

cmd="smbutil login -c ${TUSER}@mygroup | grep exists"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the keychain doesn't exist"
	return
else
	cti_report "PASS: the keychain exists"
fi

cmd="smbutil logout mygroup/$TUSER"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the smbutil logout fail"
	return
else
	cti_report "PASS: the smbutil logout successfully"
fi

cmd="smbutil login -c ${TUSER}@mygroup | grep exists"
cti_execute_cmd $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: the keychain exists"
	return
else
	cti_report "PASS: the keychain doestn't exist"
fi

cti_pass "${tc_id}: PASS"
