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
# ID: sharectl_005
#
# DESCRIPTION:
#        Verify user and domain work in sharctl "default" section
#
# STRATEGY:
#       1. run "sharectl set -p section=default -p password=$pass smbfs"
#       2. run "sharectl set -p section=default -p user=$TUSER smbfs"
#       3. run "sharectl set -p section=default -p domain=mydomain smbf"
#       2. run "mount -F smbfs //$server/public $TMNT"
#       3. sharectl and mount can get right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="sharectl005"
tc_desc="Test user and domain in sharctl [default] section."
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

smbmount_clean $TMNT
smbmount_init $TMNT

pass=$(smbutil crypt $TPASS)
cmd="sharectl set -p section=default -p password=\$pass smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: sharectl set password in default section failed"
	return
else
	cti_report "PASS: sharectl set password in default section succeeded"
fi
cmd="sharectl set -p section=default -p user=$TUSER smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "sharectl set user in default section failed"
	sharectl delsect default smbfs
	return
else
	cti_report "PASS: sharectl set user in default section succeeded"
fi
cmd="sharectl set -p section=default -p domain=mydomain smbfs"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "sharectl set domain in default section failed"
	sharectl delsect default smbfs
	return
else
	cti_report "PASS sharectl set domain in default section succeeded"
fi

cmd="smbutil view //$server"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbutil view failed for user and domain properity"
	sharectl delsect default smbfs
	return
else
	cti_report "PASS: smbutil view suceeded for user and domain properity"
fi

cmd="mount -F smbfs //$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the public share"
	sharectl delsect default smbfs
	return
else
	cti_report "PASS: smbmount can mount the public share"
fi

smbmount_check $TMNT
if [[ $? != 0 ]]; then
	sharectl delsect default smbfs
	smbmount_clean $TMNT
	return
fi

smbmount_clean $TMNT
sharectl delsect default smbfs

cti_pass "${tc_id}: PASS"
