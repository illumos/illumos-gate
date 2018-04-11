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
# ID: smbmount_011
#
# DESCRIPTION:
#         -o fileperms affects both file and dir permissions
#
# STRATEGY:
#	1. create a smb public share on sever
#	2. run "mount -F smbfs -o fileperms=744 //server/share
#	/mnt" on client
#	3. cd /mnt; touch a; ls -l a get 744 permisson
#	4. cd /mnt; mkdir d; ls -l a get 755 permisson
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount011"
tc_desc="fileperm=xxx worked well "
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs -o noprompt,noacl,fileperms=744
 //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd

cti_execute_cmd "touch $TMNT/a"
perm=$(cd $TMNT; ls -l a|awk '{ print $1}')
if [[ $perm != "-rwxr--r--" && $perm != "-rwxr--r--+" ]]; then
	tet_infoline "ls expect get 744 permission, but get $perm"
	smbmount_clean $TMNT
	tet_result FAIL
	return
fi

cti_execute_cmd "rm -f $TMNT/a"
cti_execute_cmd "mkdir $TMNT/d"

perm=$(cd $TMNT; ls -ld d|awk '{ print $1}')
if [[ $perm != "drwxr-xr-x" && $perm != "drwxr-xr-x+" ]]; then
	tet_infoline "ls expect get 755 permission, but get $perm"
	smbmount_clean $TMNT
	tet_result FAIL
	return
fi
cti_execute_cmd "rm -rf $TMNT/d"

cmd="umount $TMNT"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to umount the $TMNT"
	return
else
	cti_report "PASS: failed to umount the $TMNT"
fi

smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
