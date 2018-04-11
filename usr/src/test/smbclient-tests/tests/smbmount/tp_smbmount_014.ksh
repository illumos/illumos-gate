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
# ID: smbmount_014
#
# DESCRIPTION:
#         Verify readonly worked on smbfs
# STRATEGY:
#	1. create a smb public share for user "$AUSER" on sever
#	2. run "mount -F smbfs //$AUSER:$APASS@$server/$AUSER $TMNT"
#	3. df and cp can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount014"
tc_desc="Verify readonly worked on smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

# SKIP for now (mount priv issues)
no_tested || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs -o noprompt //$AUSER:$APASS@$server/a_share $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the share a_share"
	return
else
	cti_report "PASS: smbmount can mount the share a_share"
fi

smbmount_check $TMNT || return

cmd="cp /usr/bin/ls $TMNT"
cti_execute_cmd sudo -n -u $BUSER $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: cp to the smbfs should fail, but it's successful"
	return
else
	cti_report "PASS: cp to the smbfs is failed, it's right"
fi


cmd="umount $TMNT"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to umount the $TMNT"
	return
else
	cti_report "PASS: umount the $TMNT succssfully"
fi

smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
