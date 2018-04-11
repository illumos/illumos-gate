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
# ID: smbmount_009
#
# DESCRIPTION:
#         Verify normal smbmount can mount private shares
#
# STRATEGY:
#	1. run "mount -F smbfs //$AUSER:$APASS@$server/$AUSER $TMNT"
#	2. mount successfully
#	3. rm and cp can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount009"
tc_desc="Verify normal smbmount can mount private shares"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

sudo -n chown $AUSER $TMNT

cmd="mount -F smbfs -o noprompt //$AUSER:$APASS@$server/a_share $TMNT"
cti_execute -i '' FAIL sudo -n -u $AUSER "$cmd"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the normal user can't mount the share a_share"
	return
else
	cti_report "PASS: the normal user can mount the share a_share"
fi

smbmount_check $TMNT || return

cti_execute_cmd "rm -rf $TMNT/*"

cmd="cp /usr/bin/ls $TMNT/ls_file"
cti_execute FAIL sudo -n -u $AUSER $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: cp the file /usr/bin/ls is failed"
	return
else
	cti_report "PASS: cp the file /usr/bin/ls successfully"
fi

cmd="diff /usr/bin/ls $TMNT/ls_file"
cti_execute_cmd sudo -n -u $AUSER $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the file /usr/bin/ls is different with the file ls_file"
	return
else
	cti_report "PASS: the file /usr/bin/ls is same to the file ls_file"
fi

cti_execute_cmd "rm ls_file"

cmd="umount $TMNT"
cti_execute_cmd sudo -n -u $AUSER $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the normal user failed to umount the $TMNT"
	return
else
	cti_report "PASS: the normal user umount the $TMNT successfully"
fi

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
