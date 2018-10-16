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
# ID: create_007
#
# DESCRIPTION:
#        Verify can create 200M files on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. create and rm can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="create007"
tc_desc="Verify can create files on the smbfs"
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

cti_execute_cmd "rm -rf $TMNT/*"

cti_execute_cmd "mkfile 2m $TDIR/file"
# create file
cti_execute_cmd "mkfile 2m $TMNT/file"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to create the 20m file"
	return
else
	cti_report "PASS: create the 20m file successfully"
fi

cti_execute_cmd "cmp -s $TMNT/file $TDIR/file"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the files are different"
	return
else
	cti_report "PASS: the files are same"
fi

cti_execute_cmd "rm $TMNT/file"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to delete the file"
	return
else
	cti_report "PASS: delete the file successfully"
fi

if [[  -f "$TMNT/file" ]]; then
	cti_fail "FAIL: the file should not exist, but it exits"
	return
else
	cti_report "PASS: the file exists, it is right"
fi

cti_execute_cmd "rm  $TDIR/file"

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
