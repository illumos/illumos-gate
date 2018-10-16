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
# ID: cptest_002
#
# DESCRIPTION:
#        Verify cifs client can create and cp 300M file on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. cp and diff can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="cptest002"
tc_desc="Verify can cp files on the smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

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

cti_execute_cmd "cp $REFFILE $TDIR/test_file"
cti_execute_cmd "cp $TDIR/test_file $TMNT/test_file"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: cp $TDIR/test_file to test_file failed"
	return
else
	cti_report "PASS: cp $TDIR/test_file to test_file succeeded"
fi

cti_execute_cmd "cmp -s $TMNT/test_file $TDIR/test_file"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: diff test_file $TDIR/test_file failed"
	return
else
	cti_report "PASS: diff test_file $TDIR/test_file succeed"
fi

cti_execute_cmd "cp $TMNT/test_file $TDIR/test_file_cp "
if [[ $? != 0 ]]; then
	cti_fail "FAIL: cp test_file $TDIR/test_file_cp failed"
	return
else
	cti_report "PASS: cp test_file $TDIR/test_file_cp succeeded"
fi

cmd="cmp -s $TDIR/test_file $TDIR/test_file_cp"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: diff $TDIR/test_file $TDIR/test_file_cp failed"
	return
else
	cti_report "PASS: diff $TDIR/test_file $TDIR/test_file_cp" \
	    "succeeded"
fi

cti_execute_cmd "rm -rf $TMNT/test_file $TDIR/*"
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
