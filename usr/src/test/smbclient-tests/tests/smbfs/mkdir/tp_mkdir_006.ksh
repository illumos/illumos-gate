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
# ID: mkdir_006
#
# DESCRIPTION:
#        Verify can muti dir operation and create tar file on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. mkdir and rmdir can get the right message
#       3. tar can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="mkdir006"
tc_desc=" Verify can muti dir operation on the smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name)||return

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

# mkdir
cti_execute_cmd "mkdir -p $TMNT/testdir01/dir002"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: mkdir testdir01/dir02 failed"
	return
else
	cti_report "PASS: mkdir testdir01/dir02 succeeded"
fi

# create tar file
cti_execute_cmd "(cd $TMNT; tar cvf test.tar testdir01)"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: create tar file failed"
	return
else
	cti_report "PASS: create tar file succeeded"
fi

# delete the tar file and directory
cti_execute_cmd "rm -rf $TMNT/*"

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
