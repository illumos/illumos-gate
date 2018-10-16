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
# ID: smbmount_003
#
# DESCRIPTION:
#        Verify smbmount can't mount private share with wrong passwd
#
# STRATEGY:
#	1. run ""mount -F smbfs //$AUSER:$BPASS@$server/$AUSER"
#	2. mount can get the failed message
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbmount003"
tc_desc=" Verify smbmount can't mount private share with wrong passwd"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

# get rid of our connection first
cti_execute_cmd "smbutil discon //$AUSER@$server"
sleep 1

cti_report "expect failure next"
cmd="mount -F smbfs -o noprompt //$AUSER:badpass@$server/a_share $TMNT"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_execute_cmd "echo '::nsmb_vc' |sudo -n mdb -k"
	cti_fail "FAIL: smbmount can mount the share a_share with wrong passwd"
	return
else
	cti_report "PASS: smbmount can't mount the share a_share with wrong passwd"
fi

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
