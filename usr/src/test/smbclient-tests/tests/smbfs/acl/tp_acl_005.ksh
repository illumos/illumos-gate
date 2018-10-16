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
# ID: acl_005
#
# DESCRIPTION:
#	Verify we can take ownership (chown)
#
# STRATEGY:
#       1. run "mount -F smbfs //$TUSER@..." $TMNT
#       2. run "mount -F smbfs //$TUSER1@..." $TMNT2
#       3. create file2, as $TUSER1 and get owner UID
#       4. create a file as $TUSER
#	5. give $TUSER1 full control
#       6. chown UID $TMNT2/file
#	7. verify $TUSER1 owns it
#

. $STF_SUITE/include/libtest.ksh

tc_id="acl005"
tc_desc="Verify we can take ownership (chown)"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

smbmount_clean $TMNT
smbmount_clean $TMNT2

smbmount_init $TMNT
smbmount_init $TMNT2

#       1. run "mount -F smbfs //$TUSER@..." $TMNT

cmd="mount -F smbfs -oacl //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

# Require that the mount supports ACLs
smbmount_getmntopts $TMNT |grep /acl/ >/dev/null
if [[ $? != 0 ]]; then
	smbmount_clean $TMNT
	cti_unsupported "UNSUPPORTED (no ACLs in this mount)"
	return
fi

#       2. run "mount -F smbfs //$TUSER1@..." $TMNT2

cmd="mount -F smbfs -oacl //$TUSER1:$TPASS@$server/public $TMNT2"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
else
	cti_report "PASS: $cmd"
fi

#       3. create a file2 as $TUSER1 and get owner UID

cmd="touch $TMNT2/${tc_id}B"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi
cmd="ls -l $TMNT/${tc_id}B"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi
# Get the ephemereal UID and GID for $TUSER1
read mode cnt uid gid junk < cti_stdout
cti_execute_cmd "rm $TMNT2/${tc_id}B"

#       4. create a file, as $TUSER

cmd="cp /etc/passwd $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi
cmd="ls -l $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi
cp cti_stdout out_save

#	5. give $TUSER1 full control
cmd="chmod A+user:${uid}:rwxpdDaARWcCos::allow $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi

#       6. chown UID $TMNT2/file

cmd="sudo -n chown ${uid} $TMNT2/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi

#	6. verify $TUSER1 owns it

cmd="ls -l $TMNT2/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi
cp cti_stdout out_test

# The new owner should be different...
cmd="diff out_save out_test"
cti_execute_cmd $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: owner should have changed"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi

# The new owner should contain $uid
grep " $uid " out_test >/dev/null
if [[ $? != 0 ]]; then
	cti_fail "FAIL: did not find $uid"
	smbmount_clean $TMNT
	smbmount_clean $TMNT2
	return
fi

cti_execute_cmd "rm $TMNT/$tc_id"
smbmount_clean $TMNT
smbmount_clean $TMNT2

cti_pass "${tc_id}: PASS"
