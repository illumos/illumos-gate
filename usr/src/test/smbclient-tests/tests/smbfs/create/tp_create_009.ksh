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
# ID: create_009
#
# DESCRIPTION:
#        Verify can create 3G file on the smbfs
#	 (can go beyond 31-bit offsets)
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. create and rm can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="create009"
tc_desc="Verify can create 3g files on the smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

size=3g
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

# create file on the server
cmd="dd if=/dev/zero of=$TMNT/file oseek=3071 bs=1024k count=1"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: create $TDIR/test_file to test_file failed"
	return
else
	cti_report "PASS: create $TDIR/test_file to test_file succeeded"
fi

size=$(file_size $TMNT/file)
if [[ $size != 3221225472 ]] ; then
	cti_fail "FAIL: file size is not 3G"
	return
else
	cti_report "PASS: file size if 3G"
fi

cti_execute_cmd "rm $TMNT/file"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to delete the file"
	return
else
	cti_report "PASS: delete the file successfully"
fi

if [[  -f "$TMNT/file" ]]; then
	cti_fail "FAIL: the file should not exist, but it exists"
	return
else
	cti_report "PASS: the file exists, it is right"
fi

cti_execute_cmd "rm  $TDIR/file "

smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
