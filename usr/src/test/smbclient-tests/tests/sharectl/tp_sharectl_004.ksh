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
# ID: sharectl_004
#
# DESCRIPTION:
#        Verify minauth can work on user section
#
# STRATEGY:
#       1. run "sharectl set -p section=default -p minauth=kerberos smbfs"
#       2. run "smbutil view //$TUSER:$TPASS@$server"
#       3. sharectl and smbutil can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="sharectl004"
tc_desc="Verify minauth can work on user section"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

SERVER=$(echo $server|tr "[:lower:]" "[:upper:]")

cmd="sharectl set -p section=$SERVER -p minauth=kerberos smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl set password in SERVER section failed"
	sharectl delsect $SERVER smbfs
	return
else
	cti_report "PASS: sharectl set password in SERVER section succeeded"
fi

# get rid of our connection first
cti_execute_cmd "smbutil discon //$TUSER:$TPASS@$server"
sleep 1

cti_report "expect failure next"
cmd="smbutil view //$TUSER:$TPASS@$server"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil view succeeded for the minauth=kerberos"
	sharectl delsect $SERVER smbfs
	return
else
	cti_report "PASS: smbutil view failed for the minauth=kerberos"
fi

sharectl delsect $SERVER smbfs

cti_pass "${tc_id}: PASS"
