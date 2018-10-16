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
# ID: create_003
#
# DESCRIPTION:
#        Verify can create 30 byte file on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. dd can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="create003"
tc_desc="Verify can create files on the smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || rerurn

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

# create 30 byte file
cmd="dd if=/dev/zero of=$TMNT/file30 bs=30 count=1"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to dd a 30b file"
	return
else
	cti_report "PASS: dd a 30b file successfully"
fi

if [[ ! -f "$TMNT/file30" ]]; then
	cti_fail "FAIL: the file file30 shouldn't exist, but it exits"
	return
else
	cti_report "PASS: the file file30 doesn't exist, it's right"
fi

size=$(file_size $TMNT/file30)

if ((size != 30)); then
	cti_fail " file size($size) is != 30"
	return
fi

# remove file
cmd="rm $TMNT/file30"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to rm the file30 file"
	return
else
	cti_report "PASS: rm the file30 file successfully"
fi

if [[  -f "$TMNT/file30" ]]; then
	cti_fail "FAIL: the file30 file shouldn't exist, but it exits"
	return
else
	cti_report "PASS: the file30 file does not exist, it's right"
fi

smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
