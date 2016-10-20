#!/usr/bin/ksh
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
# Copyright 2018, Richard Lowe.
#

# Test that a simple use of linker-sets, that is, automatically generated start
# and end symbols for sections can be generated and used.

TESTDIR=$(dirname $0)

tmpdir=/tmp/test.$$
mkdir $tmpdir
cd $tmpdir

cleanup() {
    cd /
    rm -fr $tmpdir
}

trap 'cleanup' EXIT

# We expect any alternate linker to be in LD_ALTEXEC for us already
gcc -o simple ${TESTDIR}/simple-src.c -Wall -Wextra
if (( $? != 0 )); then
    print -u2 "compilation of ${TESTDIR}/simple-src.c failed";
    exit 1;
fi

./simple > simple.$$.out 2>&1

if (( $? != 0 )); then
    print -u2 "execution of ${TESTDIR}/simple-src.c failed";
    exit 1;
fi

diff -u ${TESTDIR}/simple.out simple.$$.out
if (( $? != 0 )); then
    print -u2 "${TESTDIR}/simple-src.c output mismatch"
    exit 1;
fi
