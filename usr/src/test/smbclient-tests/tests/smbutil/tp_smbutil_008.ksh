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
# ID: smbutil_008
#
# DESCRIPTION:
#        Verify smbutil view get private share
#
# STRATEGY:
#	1. create user "$AUSER" and "$BUSER"
#	2. create a smb user "$AUSER" private share
#	3. run "smbutil view //$AUSER:$APASS@netbiosname"
#	4. smbutil can get share information
#	5. run "smbutil view //$BUSER:$BPASS@netbiosname"
#	6. smbutil can't get share information.
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil008"
tc_desc="Verify smbutil can view private share"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

cmd="smbutil view //$AUSER:$APASS@$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "smbutil can't view shares"
	return
else
	cti_report "smbutil can view shares"
fi

parse_view_output a_share cti_stdout
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil view did not find a_share"
	return
else
	cti_report "PASS: smbutil view found a_share"
fi

cti_pass "${tc_id}: PASS"
