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
# ID:  xattr_008
#
# DESCRIPTION:
# Verify basic applications work with xattrs: cpio cp find mv pax tar
#
# STRATEGY:
#	1. For each application
#       2. Create an xattr and archive/move/copy/find files with xattr support
#	3. Also check that when appropriate flag is not used, the xattr
#	   doesn't get copied
#

. $STF_SUITE/include/libtest.ksh

tc_id=xattr_008
tc_desc="Verify basic applications work with xattrs: cpio cp find mv pax tar"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

CDIR=$(pwd)
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

# Create a file, and set an xattr on it. This file is used in several of the
# test scenarios below.

cti_execute_cmd "touch $TMNT/test_file"
create_xattr $TMNT/test_file passwd /etc/passwd

# For the archive applications below (tar, cpio, pax)
# we create two archives, one with xattrs, one without
# and try various cpio options extracting the archives
# with and without xattr support, checking for correct behaviour

cpio_xattr=$CDIR/xattr.cpio
cpio_noxattr=$CDIR/noxattr.cpio

cti_report "Checking cpio"
cti_execute_cmd "touch $TMNT/cpio_test"
create_xattr $TMNT/cpio_test passwd /etc/passwd

cti_execute_cmd "echo cpio_test| (cd $TMNT; cpio -oc@ -O $cpio_xattr)"
cti_execute_cmd "echo cpio_test| (cd $TMNT; cpio -oc -O $cpio_noxattr)"
cti_execute_cmd "rm -rf $TMNT/cpio_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; cpio -iu -I $cpio_xattr)"
cti_execute_cmd "runat $TMNT/cpio_test cat passwd"
if [[ $? == 0 ]]
then
	cti_fail "Fail: we have xattr here unexpectedly"
	return
fi
cti_execute_cmd "rm -rf $TMNT/cpio_test"

# we should have an xattr here

cti_execute_cmd "(cd $TMNT; cpio -iu@ -I $cpio_xattr)"
verify_xattr $TMNT/cpio_test passwd /etc/passwd
cti_execute_cmd "rm -rf $TMNT/cpio_test"

#do the same for the second time

cti_execute_cmd "(cd $TMNT; cpio -iu@ -I $cpio_xattr)"
verify_xattr $TMNT/cpio_test passwd /etc/passwd
cti_execute_cmd "rm -rf $TMNT/cpio_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; cpio -iu -I $cpio_noxattr)"
cti_execute_cmd "runat $TMNT/cpio_test cat passwd"
if [[ $? == 0 ]]
then
	cti_fail "Fail: we have xattr here unexpectedly"
	return
fi
cti_execute_cmd "rm -rf $TMNT/cpio_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; cpio -iu@ -I $cpio_noxattr)"
cti_execute_cmd "runat $TMNT/cpio_test cat passwd"
if [[ $? == 0 ]]
then
	cti_fail "Fail: we have xattr here unexpectedly"
	return
fi

cti_execute_cmd "rm -rf $TMNT/cpio_test"
cti_execute_cmd "rm -rf $cpio_xattr"
cti_execute_cmd "rm -rf $cpio_noxattr"

cti_report "Checking cp"
# check that with the right flag, the xattr is preserved

cti_execute_cmd "(cd $TMNT; cp -@ test_file test_file1)"
compare_xattrs $TMNT/test_file $TMNT/test_file1 passwd
cti_execute_cmd "rm -rf $TMNT/test_file1"

# without the right flag, there should be no xattr (ls should fail)

cti_execute_cmd "(cd $TMNT; cp test_file test_file1)"
cti_execute_cmd "runat $TMNT/cpio_test ls passwd"
if [[ $? == 0 ]]
then
	cti_fail "Fail: we have xattr here unexpectedly"
	return
fi
cti_execute_cmd "rm -rf $TMNT/test_file1"

# create a file without xattrs, and check that find -xattr only finds
# our test file that has an xattr.

cti_report "Checking find"
cti_execute_cmd "mkdir $TMNT/noxattrs"
cti_execute_cmd "touch $TMNT/noxattrs/no-xattr"

cti_execute_cmd "find $TMNT -xattr | grep test_file"
if [ $? -ne 0 ]
then
	cti_fail "find -xattr didn't find our file that had an xattr unexpectedly"
fi
cti_execute_cmd "find $TMNT -xattr | grep no-xattr"
if [ $? -eq 0 ]
then
	cti_fail "find -xattr found a file that didn't have an xattr unexpectedly"
fi
cti_execute_cmd "rm -rf $TMNT/noxattrs"

# mv doesn't have any flags to preserve/ommit xattrs - they're
# always moved.

cti_report "Checking mv"
cti_execute_cmd "touch $TMNT/mvtest"
create_xattr $TMNT/mvtest passwd /etc/passwd
cti_execute_cmd "(cd $TMNT; mv mvtest mvtest2)"
verify_xattr $TMNT/mvtest2 passwd /etc/passwd
cti_execute_cmd "rm $TMNT/mvtest"
cti_execute_cmd "rm $TMNT/mvtest2"

pax_xattr=$CDIR/xattr.pax
pax_noxattr=$CDIR/noxattr.pax

cti_report "Checking pax"
cti_execute_cmd "touch $TMNT/pax_test"
create_xattr $TMNT/pax_test passwd /etc/passwd
cti_execute_cmd "(cd $TMNT; pax -w -f $pax_noxattr pax_test)"
cti_execute_cmd "(cd $TMNT; pax -w@ -f $pax_xattr pax_test)"
cti_execute_cmd "rm $TMNT/pax_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; pax -r -f $pax_noxattr)"
cti_execute_cmd "runat $TMNT/pax_test cat passwd"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: we have xattr here unexpectedly"
	return
else
	cti_report "PASS: we should have no xattr here as expected"
fi
cti_execute_cmd "rm $TMNT/pax_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; pax -r@ -f $pax_noxattr)"
cti_execute_cmd "runat $TMNT/pax_test cat passwd"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: we have xattr here unexpectedly"
	return
else
	cti_report "PASS: we should have no xattr here as expected"
fi
cti_execute_cmd "rm $TMNT/pax_test"

# we should have an xattr here

cti_execute_cmd "(cd $TMNT; pax -r@ -f $pax_xattr)"
verify_xattr $TMNT/pax_test passwd /etc/passwd
cti_execute_cmd "rm $TMNT/pax_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; pax -r -f $pax_xattr)"
cti_execute_cmd "runat $TMNT/pax_test cat passwd"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: we have xattr here unexpectedly"
	return
else
	cti_report "PASS: we should have no xattr here as expected"
fi
cti_execute_cmd "rm $TMNT/pax_test"
cti_execute_cmd "rm $pax_noxattr"
cti_execute_cmd "rm $pax_xattr"

tar_xattr=$CDIR/xattr.tar
tar_noxattr=$CDIR/noxattr.tar

cti_report "Checking tar"
cti_execute_cmd "touch $TMNT/tar_test"
create_xattr $TMNT/tar_test passwd /etc/passwd
cti_execute_cmd "(cd $TMNT; tar cf $tar_noxattr tar_test)"
cti_execute_cmd "(cd $TMNT; tar c@f $tar_xattr tar_test)"
cti_execute_cmd "rm $TMNT/tar_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; tar xf $tar_xattr)"
cti_execute_cmd "runat $TMNT/tar_test cat passwd"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: we have xattr here unexpectedly"
	return
else
	cti_report "PASS: we should have no xattr here as expected"
fi
cti_execute_cmd "rm $TMNT/tar_test"

# we should have an xattr here

cti_execute_cmd "(cd $TMNT; tar x@f $tar_xattr)"
verify_xattr $TMNT/tar_test passwd /etc/passwd
cti_execute_cmd "rm $TMNT/tar_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; tar xf $tar_noxattr)"
cti_execute_cmd "runat $TMNT/tar_test cat passwd"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: we have xattr here unexpectedly"
	return
else
	cti_report "PASS: we should have no xattr here as expected"
fi
cti_execute_cmd "rm $TMNT/tar_test"

# we should have no xattr here

cti_execute_cmd "(cd $TMNT; tar x@f $tar_noxattr)"
cti_execute_cmd "runat $TMNT/tar_test cat passwd"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: we have xattr here unexpectedly"
	return
else
	cti_report "PASS: we should have no xattr here as expected"
fi
cti_execute_cmd "rm $TMNT/tar_test"
cti_execute_cmd "rm $tar_noxattr"
cti_execute_cmd "rm $tar_xattr"

cti_execute_cmd "rm -rf $TMNT/*"

smbmount_clean $TMNT
cti_pass "$tc_id: PASS"
