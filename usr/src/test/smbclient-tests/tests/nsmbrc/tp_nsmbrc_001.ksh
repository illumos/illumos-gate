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
# Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
#

#
# ID:nsmbrc001
#
# DESCRIPTION:
#        Verify minauth can work in default
#
# STRATEGY:
#	1. create a .nsmbrc file include default section
#	   minauth=kerberos
#	2. run "smbutil view user@server and get the failure"
#	3. create a .nsmbrc file include server section minauth=kerberos
#	4. run "smbutil view user@server and get the failure"
#

. $STF_SUITE/include/libtest.ksh

set -x

tc_id="nsmbrc001"
tc_desc="Verify minauth can work in default"
print_test_case $tc_id" - "$tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

cti_execute_cmd "rm -f ~/.nsmbrc"
echo "[default]
minauth=kerberos" > ~/.nsmbrc

# kill any existing session first
cti_execute_cmd "smbutil discon //$TUSER@$server"
sleep 1

# this should fail
cmd="smbutil view -N //$TUSER:$TPASS@$server"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_execute_cmd "echo '::nsmb_vc' |sudo -n mdb -k"
	cti_fail "FAIL: can pass authentication by minauth=kerberos"
	return
else
	cti_report "PASS: can't pass authentication by minauth=kerberos"
fi

cti_execute_cmd "rm -f ~/.nsmbrc"

cti_pass "${tc_id}: PASS"
