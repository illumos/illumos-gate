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
# ID: smbmount_010
#
# DESCRIPTION:
#         Verify smbmount can work well with smbutil login
#
# STRATEGY:
#	1. run "mount -F smbfs "//aaa;$TUSER:$TPASS@$server/public" $TMNT"
#	2. mount successfully
#	3. cp and diff can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount010"
tc_desc="smbmount can work well with smbutil login"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

smbutil logout -a
cmd="$EXPECT $SMBUTILEXP $TUSER $TPASS@aaa"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil login failed to set passwd"
	return
else
	cti_report "PASS: smbutil login set the passwd successfully"
fi

cmd="mount -F smbfs -o noprompt //aaa;$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the normal user can't mount the public share"
	smbutil logout -a
	return
else
	cti_report "PASS: the normal user can mount the public share"
fi

smbmount_check $TMNT
if [[ $? != 0 ]]; then
	smbutil logout -a
	return
fi

cmd="cp /usr/bin/ls $TMNT/ls_file"
cti_execute FAIL $cmd

cmd="cmp -s /usr/bin/ls $TMNT/ls_file"
cti_execute FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the file /usr/bin/ls is different with the file ls_file"
	smbutil logout -a
	return
else
	cti_report "PASS: the file /usr/bin/ls is same to with the file ls_file"
fi

cmd="umount $TMNT"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the normal user can't umount the public share"
	smbutil logout -a
	return
else
	cti_report "PASS: the normal user can umount the public share"
fi

smbmount_clean $TMNT
smbutil logout -a

cti_pass "${tc_id}: PASS"
