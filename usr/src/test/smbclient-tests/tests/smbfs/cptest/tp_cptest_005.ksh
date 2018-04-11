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
# ID: cptest_005
#
# DESCRIPTION:
#        Verify can cp dir between server and client side
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. cp -r can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="cptest005"
tc_desc="Verify can cp dir between server and client side"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) ||return

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

# mkdir on the local
cti_execute_cmd "rm -rf $TDIR/*"
cti_execute_cmd "mkdir $TDIR/test_dir"

# make sure no left over dir in the way, or the cp -r
# will make a subdir, and fail our later rmdir
cti_execute_cmd "rm -rf $TMNT/test_dir"

# cp to server
cti_execute_cmd "cp -r $TDIR/test_dir $TMNT/test_dir"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: cp $TDIR/test_dir to server failed"
	return
else
	cti_report "PASS: cp $TDIR/test_dir to server succeeded"
fi

if [[ ! -d "$TMNT/test_dir" ]]; then
	cti_fail "FAIL: test_dir doesn't exist on server"
	return
else
	cti_report "PASS: test_dir exists on server"
fi

# cp dir from the server to local
cti_execute_cmd "cp -r $TMNT/test_dir $TDIR/test_dir_cp"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: cp test_dir to $TDIR/test_dir_cp failed"
	return
else
	cti_report "PASS: cp test_dir to $TDIR/test_dir_cp succeeded"
fi

if [[ ! -d "$TDIR/test_dir_cp" ]]; then
	cti_fail "FAIL: $TDIR/test_dir_cp doesn't exist"
	return
else
	cti_report "PASS: $TDIR/test_dir_cp  exists"
fi

cti_execute_cmd "rmdir $TMNT/test_dir"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: rm test_dir failed"
	return
else
	cti_report "PASS: rm test_dir succeeded"
fi

cti_execute_cmd "rm -f $TDIR/*"
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
