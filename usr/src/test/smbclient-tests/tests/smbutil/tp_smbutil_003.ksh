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
# ID: smbutil_003
#
# DESCRIPTION:
#        Verify smbutil login can work.
#
# STRATEGY:
#	1. run "smbutil login ..."
#	2. Verify with "smbutil login -c ..."
#	3. Verify smbutil view can authenticate
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil003"
tc_desc="Verify smbutil login works"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

# clean up all the password
smbutil logout -a
cmd="$EXPECT $SMBUTILEXP $TUSER $TPASS"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set passwd"
	return
else
	cti_report "PASS: smbutil login succeed to set passwd"
fi

cmd="smbutil login -c $TUSER | grep exists"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: keychain doesn't exist"
	return
else
	cti_report "PASS: the keychain doesn't exist"
fi

cmd="smbutil view //$TUSER@$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil can't view shares"
	return
else
	cti_report "PASS: smbutil  can view shares"
fi

parse_view_output public cti_stdout
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil view can't get the public share"
	return
else
	cti_report "PASS: smbutil view can get the public share"
fi

smbutil logout -a

cti_pass "${tc_id}: PASS"
