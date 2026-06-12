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
# Copyright 2026 Oxide Computer Company
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

# Tests for the handling of a failure to run the command given to -exec, or
# the cpio child process backing -cpio.

find_dir=/var/tmp/findtest.$$.dir
mkdir -p $find_dir
touch $find_dir/f

cmd="$find_prog $find_dir -exec /nonexistent/utility {} \;"
echo "TEST: $cmd"
out=$($find_prog $find_dir -exec /nonexistent/utility {} \; 2>&1 >/dev/null)
rv=$?
(( rv == 1 )) && [[ "$out" == *"cannot execute"* ]] || {
	echo "TEST FAILED: $cmd" >&2
	echo "expected exit 1 and a diagnostic, got $rv [$out]" >&2
	find_exit=1
}

cmd="$find_prog $find_dir -exec /nonexistent/utility {} +"
echo "TEST: $cmd"
out=$($find_prog $find_dir -exec /nonexistent/utility {} + 2>&1 >/dev/null)
rv=$?
(( rv == 3 )) && [[ "$out" == *"cannot execute"* ]] || {
	echo "TEST FAILED: $cmd" >&2
	echo "expected exit 3 and a diagnostic, got $rv [$out]" >&2
	find_exit=1
}

cmd="PATH=/nonexistent $find_prog $find_dir -cpio $find_dir/archive"
echo "TEST: $cmd"
out=$(PATH=/nonexistent $find_prog $find_dir -cpio $find_dir/archive \
    2>&1 >/dev/null)
rv=$?
(( rv == 1 )) && [[ "$out" == *"cannot run cpio"* ]] || {
	echo "TEST FAILED: $cmd" >&2
	echo "expected exit 1 and a diagnostic, got $rv [$out]" >&2
	find_exit=1
}

# A script without an interpreter line is executed by the shell, and is
# invoked once regardless of the number of arguments.
mkdir $find_dir/many
i=1
files=
while ((i <= 300)); do
	files="$files $find_dir/many/x$i"
	((i++))
done
touch $files
script=$find_dir/script
count=$find_dir/count
print "echo run >> $count" > $script
chmod 0755 $script

cmd="$find_prog $find_dir/many -type f -exec $script {} +"
echo "TEST: $cmd"
$find_prog $find_dir/many -type f -exec $script {} + >/dev/null 2>&1
rv=$?
runs=$(wc -l < $count)
(( rv == 0 && runs == 1 )) || {
	echo "TEST FAILED: $cmd" >&2
	echo "expected exit 0 and one invocation, got $rv and [$runs]" >&2
	find_exit=1
}

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
