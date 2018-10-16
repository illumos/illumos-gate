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
# ID: smbmount_007
#
# DESCRIPTION:
#        Verify mutil user mount success with -O
#
# STRATEGY:
#	1. create users "$AUSER", "$BUSER" and their passwords
#	2. create $AUSER smb private share for user "$AUSER"
#	3. run "mount -F smbfs //$AUSER:$APASS@server/public /export/mnt"
#	4. mount successfully
#	5. run "mount -F smbfs -O //$BUSER:$BPASS@server/public /export/mnt"
#	6. mount successfully
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount007"
tc_desc=" Verify mutil user mount success with -o O"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

# SKIP for now (mount -O needs privs)
no_tested || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs -o noprompt //$AUSER:$APASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the public share"
	return
else
	cti_report "PASS: smbmount mount the public share successfully"
fi

smbmount_check $TMNT || return

cmd="cp /usr/bin/ls $TMNT/$AUSER"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to create the file by $AUSER"
	return
else
	cti_report "PASS: create the file by $AUSER successfully"
fi

cmd="rm -rf $TMNT/$AUSER"
cti_execute_cmd $cmd

cmd="mount -F smbfs -O -o noprompt //$BUSER:$BPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the second mount with $BUSER failed"
	return
else
	cti_report "PASS: the second mount with $BUSER successfully"
fi

smbmount_check $TMNT || return

cmd="cp /usr/bin/ls  $TMNT/$BUSER"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to create the file by the $BUSER"
	return
else
	cti_report "PASS: create the file by the $BUSER successfully"
fi

cmd="rm -rf $TMNT/$BUSER"
cti_execute_cmd $cmd

cmd="umount $TMNT"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to umount the $TMNT"
	return
else
	cti_report "PASS: umount the $TMNT successfully"
fi

cmd="umount $TMNT"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the second umount the $TMNT failed"
	return
else
	cti_report "PASS: the second umount the $TMNT successfully"
fi

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
