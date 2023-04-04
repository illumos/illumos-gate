#! /bin/ksh
#
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

# Copyright 2023 Richard Lowe

#
# Test that searching for sysroot paths works as we expect.
#

tmpdir=$(mktemp -td test-search.XXXXXX)
if [[ -z $tmpdir ]]; then
	print -u2 "Failed to create temporary directory"
	exit 1
fi

cd $tmpdir

cleanup() {
	cd /
	rm -fr $tmpdir
}

trap 'cleanup' EXIT

misc_fail() {
	print -u2 "$@"
	exit 1
}

if [[ $PWD != $tmpdir ]]; then
	misc_fail "Failed to change to temporary directory: $tmpdir"
fi

# Note we rely on the willingness of the link editor to accept only libraries
# as input files, since we only care about where things are found, not the
# resulting binary
ret=0

ld -Dlibs,detail -64 -lc 2>&1 | grep -q 'find lib=-lc; path=/lib/64/libc.so'
if (( $? != 0 )); then
	ret=1
	print -u2 "FAIL: basic link of -lc"
fi

mkdir -p default/lib/64 || misc_fail "failed to create $PWD/default/lib/64"
cp /lib/64/libc.so default/lib/64 || \
    misc_fail "couldn't copy to $PWD/default/lib/64/libc.so"

ld -Dlibs,detail -64 -z sysroot=$PWD/default -lc 2>&1 | \
    grep -q "find lib=-lc; path=$PWD/default/lib/64/libc.so"
if (( $? != 0 )); then
	ret=1
	print -u2 "FAIL: -zsysroot link of -lc"
fi

mkdir -p non-default || misc_fail "failed to create $PWD/non-default"
cp /lib/64/libc.so non-default || \
    misc_fail "couldn't copy to $PWD/non-default/libc.so"

ld -Dlibs,detail -64 -z sysroot=$PWD/non-default -L'$SYSROOT/' -lc 2>&1 | \
    grep -q "find lib=-lc; path=$PWD/non-default//libc.so"
if (( $? != 0 )); then
	ret=1
	print -u2 "FAIL: SYSROOT/ link of -lc"
fi

ld -Dlibs,detail -64 -z sysroot=$PWD/non-default -L'=/' -lc 2>&1 | \
    grep -q "find lib=-lc; path=$PWD/non-default//libc.so"
if (( $? != 0 )); then
	ret=1
	print -u2 "FAIL: =/ link of -lc"
fi

ld -Dlibs,detail -64 -z assert-deflib -z fatal-warnings \
    -z sysroot=$PWD/default -lc > deflib.out.$$ 2>&1
if (( $? == 0 )); then
	ret=1
	print -u2 "FAIL: -zassert-deflib doesn't respect SYSROOT (exit successfully)"
fi

grep -q "dynamic library found on default search path" deflib.out.$$
if (( $? != 0 )); then
	ret=1
	print -u2 "FAIL: -zassert-deflib doesn't respect SYSROOT (wrong error)"
fi

exit $ret
