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
# ID: smbutil_002
#
# DESCRIPTION:
#        Verify smbutil lookup can resolve NETBIOS name.
#
# STRATEGY:
#        1. run "smbutil lookup" on  he smb NETBIOS name
#        2. smbutil can resolve the smb NETBIOS name
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil002"
tc_desc="Test smbutil status, smbutil lookup"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

# Try "status" first, which basically tells us if the
# server supports NetBIOS.  If not, UNSUPPORTED.
cmd="smbutil status $server"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_unsupported "SKIP: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

# Get the server name from the status output.
grep '^Server' cti_stdout | read junk nbname
if [[ "x$nbname" == x ]] ; then
	cti_unsupported "SKIP: Can't get NetBIOS name."
	return
else
	cti_report "Server NetBIOS name: $nbname"
fi

# Now try lookup of the NetBIOS name.
cmd="smbutil lookup $nbname"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

cti_pass "${tc_id}: PASS"
