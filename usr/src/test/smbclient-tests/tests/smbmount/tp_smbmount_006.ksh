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
# ID: smbmount_006
#
# DESCRIPTION:
#        Verify mutil user can't mount on the same mount point"
#
# STRATEGY:
#	1. create user "$AUSER" and "$BUSER"
#	2. run "mount -F smbfs //$AUSER:$APASS@$server/public $TMNT"
#	3. mount successfully
#	4. run "mount -F smbfs //$BUSER:$BPASS@$server/public $TMNT"
#	5. mount failed
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount006"
tc_desc=" Verify mutil user mount failed on the same plan"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs -o noprompt //$AUSER:$APASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the public share"
	return
else
	cti_report "PASS: smbmount can mount the public share"
fi

smbmount_check $TMNT || return

# this should fail
cmd="mount -F smbfs -o noprompt //$BUSER:$BPASS@$server/public $TMNT"
cti_execute -i '' PASS sudo -n -u $BUSER $cmd
if [[ $? == 0 ]]; then
	cti_execute_cmd "echo '::nsmb_vc' |sudo -n mdb -k"
	cti_fail "FAIL: smbmount - second mount should have failed"
	return
else
	cti_report "PASS: smbmount - second mount failed as expected"
fi

cmd="umount $TMNT"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to umount the $TMNT"
	return
else
	cti_report "PASS: umount the $TMNT successfully"
fi

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
