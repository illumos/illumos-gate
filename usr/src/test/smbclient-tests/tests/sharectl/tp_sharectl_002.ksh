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
# ID: sharectl_002
#
# DESCRIPTION:
#        Verify password can work
#
# STRATEGY:
#       1. run "sharectl set -p section=default -p password=$pass smbfs"
#       2. run "smbutil view //$TUSER@$server"
#       3. sharectl and smbutil can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="sharectl002"
tc_desc=" Verify password can work"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

SERVER=$(echo $server|tr "[:lower:]" "[:upper:]")
pass=$(smbutil crypt $TPASS)

cmd="sharectl set -p section=default -p password=\$pass smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl set password in default section failed"
	return
else
	cti_report "PASS: sharectl set password in default section succeeded"
fi

cmd="smbutil view //$TUSER@$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil view failed for default password"
	return
else
	cti_report "PASS: smbutil view succeeded for default password"
fi

sharectl delsect  default smbfs

cmd="sharectl set -p section=$SERVER -p password=\$pass smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl set password in $SERVER section failed"
	return
else
	cti_report "PASS: sharectl set password in $SERVER section succeed"
fi

cmd="sharectl set -p section=$SERVER -p addr=$server smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl set addr in $SERVER section failed"
	sharectl delsect  $SERVER smbfs
	return
else
	cti_report "PASS: sharectl set addr in $SERVER section succeeded"
fi

cmd="smbutil view //$TUSER@$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil view failed for SERVER password"
	sharectl delsect  $SERVER smbfs
	return
else
	cti_report "PASS: smbutil view succeeded for SERVER password"
fi

cmd="smbutil view //$TUSER1@$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil view failed by $TUSER1 for SERVER password"
	sharectl delsect  $SERVER smbfs
	return
else
	cti_report "PASS: smbutil view succeeded by $TUSER1 for SERVER password"
fi

sharectl delsect  $SERVER smbfs

cti_pass "${tc_id}: PASS"
