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
# ID:  xattr_009
#
# DESCRIPTION:
# Verify can create many xattrs on a file
#
# STRATEGY:
#	1. Create a file on a filesystem and add 100 xattrs to it
#	2. Verify that the xattrs should be right
#	4. Delete those xattrs
#	5. Verify that xattrs should not be have
#

. $STF_SUITE/include/libtest.ksh

tc_id=xattr_009
tc_desc="Verify can create many xattrs on a file"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	 cti_fail "FAIL: smbmount can't mount the public share unexpectedly"
	 return
else
	 cti_report "PASS: smbmount can mount the public share as expected"
fi

smbmount_getmntopts $TMNT |grep /xattr/ >/dev/null
if [[ $? != 0 ]]; then
	smbmount_clean $TMNT
	cti_unsupported "UNSUPPORTED (no xattr in this mount)"
	return
fi

# Create a file, and set 100 xattrs on it.

cti_execute_cmd "rm -f $TMNT/test_file"
cti_execute_cmd "touch $TMNT/test_file"
typeset -i i=0
typeset -i j=100
while [[ $i -lt $j ]]; do
  create_xattr $TMNT/test_file passwd$i /etc/passwd
  i=$((i+1))
done

#create the expected output then compare them with xattrs in the test_file

i=0
cp /dev/null temp_file
echo SUNWattr_ro >> temp_file
echo SUNWattr_rw >> temp_file
while [[ $i -lt $j ]]; do
  echo passwd$i >> temp_file
  i=$((i+1))
done
cti_execute_cmd "sort temp_file > expected_file"

#listing the directory passwd*

cti_execute_cmd "runat $TMNT/test_file ls > output"
cti_execute_cmd "sort output | diff expected_file -"
if [[ $? != 0 ]]; then
cti_fail "FAIL: do not work as expected for xattrs"
return
else
cti_report "PASS: work as expected for xattrs"
fi

#delete xattrs in test_file verify these are no passwd* in test_file

cti_execute_cmd "runat $TMNT/test_file rm -f passwd*"
cti_execute_cmd "runat $TMNT/test_file ls passwd*"
if [[ $? == 0 ]]; then
cti_fail "FAIL: have passwd* xattrs in test_file unexpectedly"
return
else
cti_report "PASS: should not have passwd* xattrs in test_file as expected"
fi

cti_execute_cmd "rm -f temp_file expected_file output"

smbmount_clean $TMNT
cti_pass "$tc_id: PASS"
