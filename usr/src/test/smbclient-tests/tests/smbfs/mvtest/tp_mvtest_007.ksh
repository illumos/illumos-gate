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
# ID: mvtest_007
#
# DESCRIPTION:
#        Verify can mv muti dir/files between server and local
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. mv and diff can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="mvtest007"
tc_desc=" Verify can mv muti dir/files between server and local"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

srcdir=/usr/lib/locale/C
server=$(server_name)|| return

if [[ $? != 0 ]]; then
      tet_result UNRESOLVED
      return
fi

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

cti_execute_cmd "rm -rf $TMNT/*"

# create mutil file/dirs on the server
cti_execute_cmd "cp -rf $srcdir $TMNT/test_dir"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: cp $srcdir to test_dir failed"
	return
else
	cti_report "PASS: cp $srcdir to test_dir succeeded"
fi

# create mutil file/dirs on the server
cti_execute_cmd "cp -rf $srcdir $TMNT/test_dir_org"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: cp $srcdir to test_dir_org failed"
	return
else
	cti_report "PASS: cp $srcdir to test_dir_org succeeded"
fi

# find .
cti_execute FAIL "(cd $TMNT; find .)"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: find failed on smbfs"
	return
else
	cti_report "PASS: find succeeded on smbfs"
fi

# mv to local
cti_execute_cmd "mv $TMNT/test_dir $TDIR/test_dir"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: mv test_dir $TDIR/test_dir failed"
	return
else
	cti_report "PASS: mv test_dir $TDIR/test_dir succeeded"
fi

# diff the local and  org's
cti_execute_cmd "diff -r $TMNT/test_dir_org $TDIR/test_dir"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: diff -r test_dir_org $TDIR/test_dir failed"
	return
else
	cti_report "PASS: diff -r test_dir_org $TDIR/test_dir succeeded"
fi

# mv muti dir/files from the local to server
cti_execute_cmd "mv $TDIR/test_dir $TMNT/test_dir_mv"
if [[ $? != 0 ]]; then
	# This test has errors until we do sysattrs
	noise=' preserve extended system attribute'
	grep -v "$noise" < cti_stderr > other_stderr
	if [[ -s other_stderr ]] ; then
		cti_fail "FAIL: $cmd"
		return
	fi
	cti_report "Partial failure from mv local to mount"
else
	cti_report "PASS: mv $TDIR/test_dir to test_dir_mv succeeded"
fi

# diff the server to local
cti_execute_cmd  "diff -r $TMNT/test_dir_org $TMNT/test_dir_mv"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: diff -r test_dir_org test_dir_mv failed"
	return
else
	cti_report "PASS: diff -r test_dir_org test_dir_mv succeeded"
fi

cti_execute_cmd "rm -rf $TDIR/*"
cti_execute_cmd "rm -rf $TMNT/*"

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
