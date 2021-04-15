#! /usr/bin/sh
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

# Copyright 2012, Richard Lowe.

TESTDIR=$(dirname $0)

tmpdir=/tmp/test.$$
mkdir $tmpdir
cd $tmpdir

cleanup() {
	cd /
	rm -fr $tmpdir
}

trap 'cleanup' EXIT

if [[ $PWD != $tmpdir ]]; then
	print -u2 "Failed to create temporary directory: $tmpdir"
	exit 1;
fi

if [[ -n $PROTO ]]; then
	export LD_ALTEXEC=$PROTO/bin/ld
fi

ret=0

function should_succeed {
	mapfile=$1
	msg=$2

	if gcc -m32 -shared -Wl,-M,${TESTDIR}/$mapfile ${TESTDIR}/object.c \
	    -o object.so; then
		echo "pass (32): $msg"
	else
		echo "FAIL (32): $msg"
		ret=1
	fi

	if gcc -m64 -shared -Wl,-M,${TESTDIR}/$mapfile ${TESTDIR}/object.c \
	    -o object.so; then
		echo "pass (64): $msg"
	else
		echo "FAIL (64): $msg"
		ret=1
	fi
}

function should_fail {
	mapfile=$1
	msg=$2
	error=$3

	if gcc -m32 -shared -Wl,-M,${TESTDIR}/$mapfile ${TESTDIR}/object.c \
	    -o object.so 2>&1 | /usr/bin/grep -Eq "$error"; then
		echo "pass (32): $msg"
	else
		echo "FAIL (32): $msg"
		ret=1
	fi

	if gcc -m64 -shared -Wl,-M,${TESTDIR}/$mapfile ${TESTDIR}/object.c \
	    -o object.so 2>&1 | /usr/bin/grep -Eq "$error"; then
		echo "pass (64): $msg"
	else
		echo "FAIL (64): $msg"
		ret=1
	fi
}

should_succeed mapfile.sizemult.good "link with integer multiplier syntax"

should_fail mapfile.sizemult.wrong "link with integer multiplier syntax with wrong result" \
    "assertion failed: size of symbol common should be: [0-9]+ is: [0-9]+"
should_fail mapfile.sizemult.noterm "link with integer multiplier syntax with no terminating ]" \
    "expected '.' to terminate multiplier of: 2"

should_fail mapfile.sizemult.twobegin "link with integer multiplier with two [s" \
    "expected integer value following '.': 2..4"

should_fail mapfile.sizemult.overflow "link with integer multiplier that overflows" \
    "multiplication overflow"

should_succeed mapfile.addrsize.good "link with addrsized symbol"

should_succeed mapfile.addrsize.mult "link with addrsized symbol with multiplier"

should_fail mapfile.addrsize.wrong "link with addrsized symbol with wrong value" \
    "assertion failed: size of symbol"

should_fail mapfile.addrsize.substring "link with addrsized symbol with substring of valid name" \
    "expected integer value following SIZE: addrs"

should_fail mapfile.addrsize.superstring "link with addrsized symbol with superstring of valid name" \
    "expected integer value following SIZE: addrsizes"

exit $ret
