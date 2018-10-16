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
# ID: smbmount_015
#
# DESCRIPTION:
#         Verify smbmount can mount 2 private shares
#
# STRATEGY:
#	1. run "mount -F smbfs -o dirperms=777,fileperms=666
#	//$AUSER:$APASS@$server/$AUSER $TMNT"
#	2 mount successfully
#	3. run "mount -F smbfs -o dirperms=777,fileperms=666
#	//$BUSER:$BPASS@$server/$BUSER $TMNT2"
#	4 mount successfully
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount015"
tc_desc="Verify smbmount can mount 2 private shares"
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
smbmount_clean $TMNT2
smbmount_init $TMNT2

cmd="mount -F smbfs -o noprompt,dirperms=777,fileperms=666
 //$AUSER:$APASS@$server/a_share $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the share a_share"
	return
else
	cti_report "PASS: smbmount can mount the share a_share"
fi

smbmount_check $TMNT || return

cmd="cp /usr/bin/ls $TMNT/ls_file"
cti_execute FAIL sudo -n -u $AUSER $cmd

cmd="diff /usr/bin/ls $TMNT/ls_file"
cti_execute FAIL sudo -n -u $AUSER $cmd

cmd="mount -F smbfs -o noprompt,dirperms=777,fileperms=666
 //$BUSER:$BPASS@$server/$BUSER $TMNT2"
cti_execute -i '' FAIL $cmd

smbmount_check $TMNT || return

cmd="cp /usr/bin/ls $TMNT/ls_file"
cti_execute FAIL sudo -n -u $AUSER $cmd

cmd="diff /usr/bin/ls $TMNT/ls_file"
cti_execute FAIL sudo -n -u $AUSER $cmd

cmd="umount $TMNT"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to umount the $TMNT"
	return
else
	cti_report "PASS: umount the $TMNT successfully"
fi

cmd="umount $TMNT2"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to umount the $TMNT2"
	return
	cti_report "PASS: umount the $TMNT2 successfully"
fi

smbmount_clean $TMNT
smbmount_clean $TMNT2

cti_pass "${tc_id}: PASS"
