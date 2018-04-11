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
# ID: create_002
#
# DESCRIPTION:
#        Verify can create files on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. cp, diff and rm can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="create002"
tc_desc=" Verify can create files on the smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name)|| return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the public share"
	return
else
	cti_report "PASS: smbmount can mount the public share"
fi

cmd="cp /usr/bin/ls $TMNT/ls_file"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to cp the /usr/bin/ls file"
	return
else
	cti_report "PASS: cp the /usr/bin/ls file successfully"
fi

cmd="cmp -s /usr/bin/ls $TMNT/ls_file"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the /usr/bin/ls file is different with the ls_file file"
	return
else
	cti_report "PASS: the /usr/bin/ls file is same to the ls_file file"
fi

cmd="rm -f $TMNT/ls_file"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to rm the ls_file file"
	return
else
	cti_report "PASS: rm the ls_file file successfully"
fi

if [[  -f "$TMNT/ls_file" ]]; then
	cti_fail "FAIL: the ls_file file shouldn't exist, but it exits"
	return
else
	cti_report "PASS: the ls_file file doesn't exist, it's right"
fi

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
