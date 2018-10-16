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
# ID: smbmount_012
#
# DESCRIPTION:
#         -o fileperms work well
#
# STRATEGY:
#        1. create a smb public share for user "$AUSER" on sever
#        2. run "mount -F smbfs -o dirperms=540 //a@server/share
#        /mnt" on client
#        3. ls -ld /mnt get 540 permisson
#        4. smbutil login //a@server
#        5. cd /PUBLIC get permisson deny
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount012"
tc_desc="dirperms=xxx worked well "
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs -o noprompt,noacl,dirperms=540
 //$AUSER:$APASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the public share"
	return
else
	cti_report "PASS: smbmount can mount the public share"
fi

perm=$(ls -ld $TMNT |awk '{ print $1}')
if [[ $perm != "dr-xr-----" && $perm != "dr-xr-----+" ]]; then
	cti_fail "FAIL: the expect result is get 540 permission, but get $perm"
	return
else
	cti_report "PASS: the expect result is right"
fi
cti_execute_cmd "rm -rf $TMNT/a"

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
