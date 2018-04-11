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
# ID: sharectl_001
#
# DESCRIPTION:
#        Verify minauth can work in default
#
# STRATEGY:
#	1. run "sharectl set -p section=default -p minauth=kerberos smbfs"
#	2. run "smbutil view //$TUSER:$TPASS@$server"
#	3. sharectl and smbutil can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="sharectl001"
tc_desc=" Verify minauth can work in default"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

cmd="sharectl set -p section=default -p minauth=kerberos smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl set minauth in default section failed"
	return
else
	cti_report "succeed: sharectl set minauth in default section succeeded"
fi

# this should fail
cmd="smbutil view //$TUSER:$TPASS@$server"
cti_execute -i '' PASS $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: smbutil view succeeded for the minauth=kerberos"
	sharectl delsect default smbfs
	return
else
	cti_report "PASS: smbutil view failed for the minath=kerberos"
fi

cmd="sharectl delsect default smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl delsect default smbfs failed"
	sharectl delsect default smbfs
	return
else
	cti_report "PASS: sharectl delsect default smbfs succeeded"
fi

cti_pass "${tc_id}: PASS"
