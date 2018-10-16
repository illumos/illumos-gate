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
# ID: misc_003
#
# DESCRIPTION:
#	Verify reconnect after connection to server is lost.
#
# STRATEGY:
#	1. run "mount -F smbfs //server/public /export/mnt"
#	2. create a file
#	3. force the connection to drop
#	4. read the file (from step 2)
#

. $STF_SUITE/include/libtest.ksh

tc_id="misc003"
tc_desc=" Verify reconnect after connection loss."
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name)||return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

#	1. run "mount -F smbfs //server/public /export/mnt"

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

#	2. create a file

cmd="touch $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
fi

#	3. force the connection to drop
#	(SMB uses port: 445)

cmd="abort_conn -p 445 $server "
cti_execute_cmd sudo -n $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
fi
sleep 2

#	Would be nice to verify the connections are IDLE,
#	but it can be tricky to identify which is ours.
#	For now, just log the connection states here.
#	Our connetion will show state "IDLE".

cmd="echo '::nsmb_vc' |sudo -n mdb -k"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
fi

#	4. read the file (from step 2)
#	This will initiate a reconnect.

cmd="ls -l $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
fi

cti_execute_cmd "rm -rf $TMNT/*"

smbmount_clean $TMNT
cti_pass "$tc_id: PASS"
