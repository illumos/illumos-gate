#! /usr/bin/ksh
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
# Copyright 2012, Richard Lowe.
#

TESTDIR=$(dirname $0)

fail() {
	print -u2 "ERROR: $@"
	exit 1
}

FIFODIR=/tmp/saveargs-test.$$

mkdir ${FIFODIR} || fail "couldn't create temp directory ${TMPDIR}"

cleanup() {
    [[ -n $pid ]] && kill $pid >/dev/null 2>&1
    cd /
    rm -fr ${FIFODIR} || fail "couldn't remote temp directory ${FIFODIR}"
}

trap cleanup EXIT

ret=0
pid=

# Run the program and compare its stack (via pstack(1)) to what we expect.  We
# use a FIFO as a simple condition variable to indicate that the program is
# ready to have its stack examined.
function tester {
	prog=${1}
	pattern=${2}

	mkfifo ${FIFODIR}/${prog}

	${TESTDIR}/$prog >> /tmp/saveargs-test.$$/${prog} &
	pid=$!

	head -n 1 ${FIFODIR}/${prog} > /dev/null 2>&1

	if (/usr/bin/pstack $pid | /usr/bin/grep -q "${pattern}"); then
		echo "pass: ${prog}"
	else
		echo "FAIL: ${prog}"
		ret=1
	fi
	kill $pid
}

tester align "test (1, 2, 3, 4, 5)"
tester basic "test (1, 2, 3, 4)"
tester big-struct-ret "test (1, 2, 3, 4)"
tester big-struct-ret-and-spill "test (1, 2, 3, 4, 5, 6, 7, 8)"
tester small-struct-ret "test (1, 2, 3, 4)"
tester small-struct-ret-and-spill "test (1, 2, 3, 4, 5, 6, 7, 8)"
tester stack-spill "test (1, 2, 3, 4, 5, 6, 7, 8)"

exit $ret
