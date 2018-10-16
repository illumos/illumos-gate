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
# ID: smbmount_016
#
# DESCRIPTION:
#         -o gid work well
#
# STRATEGY:
#        1. run "mount -F smbfs -o gid=xxx //$TUSER:$TPASS@...
#        2. ls -ld /mnt get gid xxx
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount016"
tc_desc="gid=xxx worked well"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

# XXX: Should get this group from config
tc_gid="gdm"

cmd="mount -F smbfs -o noprompt,noacl,gid=$tc_gid \
 //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
fi

grp=$(ls -ld $TMNT|awk '{ print $4}')
if [[ $grp != "$tc_gid" ]]; then
	cti_fail "FAIL: ls -ld, expected $tc_gid, got $grp"
	smbmount_clean $TMNT
	return
fi

cti_execute_cmd "touch $TMNT/a"
grp=$(cd $TMNT; ls -l a|awk '{ print $4}')
if [[ $grp != "$tc_gid" ]]; then
	cti_fail "FAIL: touch a, expected $tc_gid usr, got $grp"
	smbmount_clean $TMNT
	return
fi

cti_execute_cmd "rm -rf $TMNT/b"
cti_execute_cmd "mkdir $TMNT/b"
grp=$(cd $TMNT; ls -ld b|awk '{ print $4}')
if [[ $grp != "$tc_gid" ]]; then
	cti_fail "FAIL: mkdir b, expected $tc_gid usr, got $grp"
	smbmount_clean $TMNT
	return
fi

cti_execute_cmd "rm -rf $TMNT/*"

cmd="umount $TMNT"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to umount the $TMNT"
	return
fi

smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
