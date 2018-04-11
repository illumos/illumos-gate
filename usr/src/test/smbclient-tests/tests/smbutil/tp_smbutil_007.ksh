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
# ID: smbutil_007
#
# DESCRIPTION:
#        Verify smbutil can view the public share
#
# STRATEGY:
#	1. create a smb public share
#	2. run "smbutil view //netbiosname"
#	3. smbutil can get share information
#

. $STF_SUITE/include/libtest.ksh

tc_id="smbutil007"
tc_desc="Verify smbutil can view public share"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

cmd="smbutil view //$TUSER:$TPASS@$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "smbutil can't view shares"
	return
else
	cti_report "smbutil can view shares"
fi

parse_view_output public cti_stdout
if [[ $? != 0 ]]; then
	cti_fail "smbutil view can't get the public share"
	return
else
	cti_report "smbutil view can get the public share"
fi

cti_pass "${tc_id}: PASS"
