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
# ID: smbutil_015
#
# DESCRIPTION:
#        1. Do stress testing on smbutil
#	 2. Verify smbutil logout -a work well
#
# STRATEGY:
#	1. run "smbutil logout -a" and "smbutil login -c"
#	2. the smbutil commands can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil015"
tc_desc="Verify smbutil logout -a works"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

sleep 3

smbutil logout -a

i=0
while ((i<20));do
	cmd="$EXPECT $SMBUTILEXP $TUSER$i \$TPASS\$i"
	cti_execute_cmd $cmd
	if [[ $? != 0 ]]; then
		cti_fail "FAIL: smbutil login failed to set passwd to $TUSER$i"
		return
	else
		cti_report "PASS: smbutil login failed to set passwd to $TUSER$i"
	fi

	cmd="smbutil login -c $TUSER$i | grep exists"
	cti_execute_cmd $cmd
	if [[ $? != 0 ]]; then
		cti_fail "FAIL: '$TUSER$i' keychain doesn't exist"
		return
	else
		cti_report "PASS: '$TUSER$i' keychain exists"
	fi
	((i=i+1))
done

i=0
while ((i<20));do
	cmd="smbutil logout $TUSER$i"
	cti_execute_cmd $cmd
	if [[ $? != 0 ]]; then
		cti_fail "FAIL: smbutil logout $TUSER$i failed"
	        return
	else
		cti_report "PASS: smbutil logout $TUSER$i succeeded"
	fi
	cmd="smbutil login -c $TUSER$i | grep exists"
	cti_execute_cmd $cmd
	if [[ $? == 0 ]]; then
		cti_fail "FAIL: '$TUSER$i' keychain exists"
		return
	else
		cti_report "PASS: '$TUSER$i' keychain doesn't exist"
	fi
	((i=i+1))
done

cti_execute_cmd "smbutil logout -a"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil logout -a doesn't work"
	return
else
	cti_report "PASS: smbutil logout -a works"
fi

while ((i<20)); do
	cmd="smbutil login -c $TUSER$i|grep exists"
	cti_execute_cmd $cmd
	if [[ $? == 0 ]]; then
		cti_fail "FAIL: '$TUSER$i' keychain exists"
	        return
	else
		cti_report "PASS: '$TUSER$i' keychain doesn't exist"
	fi
	((i=i+1))
done

cti_pass "${tc_id}: PASS"
