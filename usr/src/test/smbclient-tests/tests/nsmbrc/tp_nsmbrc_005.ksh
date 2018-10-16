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
#        Verify user and domain can work
#
# STRATEGY:
#       1. create a .nsmbrc file
#       2. run "smbutil view //$server"
#       3. run "mount -F smbfs //$server/public $TMNT"
#       4. smbutil and mount can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="nsmbrc005"
tc_desc=" Verify user and domain in user section can work"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

cti_execute_cmd "rm -f ~/.nsmbrc"
smbmount_clean $TMNT
smbmount_init $TMNT

pass=$(smbutil crypt $TPASS)
echo "[default]" > ~/.nsmbrc
echo "password=$pass" >> ~/.nsmbrc
echo "user=$TUSER" >> ~/.nsmbrc
echo "domain=mydomain" >> ~/.nsmbrc
cti_execute_cmd chmod 600 ~/.nsmbrc

cmd="smbutil view //$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: user and domain property in default section doesn't work"
	return
else
	cti_report "PASS: user and domain property in default section works"

fi

cmd="mount -F smbfs //$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: user and domain property in default section doesn't work" \
	    "for smb mount"
	return
else
	cti_report "PASS: user and domain properity in default section works for" \
	   "smbmount"
fi

smbmount_check $TMNT
if [[ $? != 0 ]]; then
	smbmount_clean $TMNT
	return
fi

cti_execute_cmd "rm -f ~/.nsmbrc"
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
