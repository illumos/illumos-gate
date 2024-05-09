#!/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2020 Joyent, Inc.
# Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
#

#
# Clearly, grossly incomplete.
#

. "$(dirname $0)/find.kshlib"

mkdir $find_dir
mkdir -p $find_dir/1
mkdir -p $find_dir/.2
touch $find_dir/.2/1
touch $find_dir/.2/c

testfind "$find_dir/.2/1,$find_dir/1," \
    $find_prog $find_dir -name \"1\"
testfind "$find_dir/.2/1,$find_dir/1," \
    $find_prog $find_dir -path \"*1\"

cd $find_dir

testfind "" $find_prog . -name \"*2\"
testfind "./.2," $find_prog_xpg4 . -name \"*2\"
testfind "./.2," $find_prog . -name \".*2\"
testfind "./.2," $find_prog_xpg4 . -name \".*2\"
testfind "./.2/1,./1," $find_prog . -path \"*1\"
testfind "./.2," $find_prog . -path \"*2\"
testfind "./.2,./.2/1,./.2/c," $find_prog . -path \"*2*\"

cd -
rm -rf $find_dir

# Regression test for bug 15353:
#
# For the purposes of this test we need a user and group with the same
# numeric id.
#
# We also check that /var/tmp has ZFS/CIFS/NFS4-equivalent acls.
#
# (A complete test would also exercise ufs's acls)
#
testuser=daemon
testgroup=other

testuid=$(getent passwd ${testuser} | cut -d: -f 3)
testgid=$(getent group ${testgroup} | cut -d: -f 3)

[[ "$testuid" == "$testgid" ]] || {
	echo "TEST FAILED: $cmd" >&2
	echo "expected ${testuser}'s uid $testuid" \
	     "to be equal to ${testgroup}'s gid $testgid" >&2
	find_exit=1
}

find_dir=/var/tmp/findtest.$$.dir
mkdir -p $find_dir

# ACL_ENABLED yields 0 for no acls, 1 for old acls, 2 for NFS acls.

_ACL_ACE_ENABLED=2
_ACL_ACLENT_ENABLED=1

[[ $(getconf ACL_ENABLED $find_dir) == ${_ACL_ACE_ENABLED} ]] || {
    echo "TEST SKIPPED: ACE acls not available in $find_dir"
    find_exit=4			# UNSUPPORTED
    exit $find_exit
}

mkdir -p $find_dir/a
mkdir -p $find_dir/b
chmod A+group:${testgroup}:read_set:allow $find_dir/a
chmod A+user:${testuser}:read_set:allow $find_dir/b

cd $find_dir
testfind "./a", $find_prog . -groupacl ${testgroup}
testfind "./b", $find_prog . -useracl ${testuser}

cd -
rm -rf $find_dir

exit $find_exit
