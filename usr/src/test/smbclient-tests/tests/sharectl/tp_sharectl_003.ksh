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
# ID: sharectl_003
#
# DESCRIPTION:
#        Verify password can work
#
# STRATEGY:
#       1. run "sharectl set -p section=$SERVER:$TUSER -p password=$pass smbfs"
#       2. run "sharectl set -p section=$SERVER:$TUSER -p addr=$server smbfs"
#       3. run "smbutil view //$TUSER1@$server"
#       4. run "mount -F smbfs //$TUSER@$server/public $TMNT"
#       3. sharectl, smbutil and mount can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="sharectl003"
tc_desc="Verify password can work"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

smbmount_clean $TMNT
smbmount_init $TMNT

rm -rf ~root/.nsmbrc

server=$(server_name) || return

pass=$(smbutil crypt $TPASS)
SERVER=$(echo $server|tr "[:lower:]" "[:upper:]")

cmd="sharectl set -p section=$SERVER:$TUSER -p password=\$pass smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl set password in $SERVER section failed"
	return
else
	cti_report "PASS: sharectl set password in $SERVER section succeeded"
fi

cmd="sharectl set -p section=$SERVER:$TUSER -p addr=$server smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl set addr in $SERVER section failed"
	sharectl delsect  $SERVER:$TUSER smbfs
	return
else
	cti_report "PASS: sharectl set addr in $SERVER section succeeded"
fi

smbutil logout -a

# get rid of our connection first
cti_execute_cmd "smbutil discon //$TUSER1@$server"
sleep 1

cti_report "expect failure next"
cmd="smbutil view -N //$TUSER1@$server"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil view succeeded for SERVER password by $TUSER1"
	sharectl delsect  $SERVER:$TUSER smbfs
	return
else
	cti_report "PASS: smbutil view ffailed for SERVER password by $TUSER1"
fi

cmd="mount -F smbfs //$TUSER@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the public share by $TUSER"
	sharectl delsect  $SERVER:$TUSER smbfs
	return
else
	cti_report "PASS: smbmount can mount the public share by $TUSER"
fi

smbmount_check $TMNT
if [[ $? != 0 ]]; then
	smbmount_clean $TMNT
	sharectl delsect  $SERVER:$TUSER smbfs
	return
fi

smbmount_clean $TMNT
sharectl delsect  $SERVER:$TUSER smbfs

cti_pass "${tc_id}: PASS"
