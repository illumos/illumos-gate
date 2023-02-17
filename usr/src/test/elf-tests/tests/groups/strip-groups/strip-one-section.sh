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

# Copyright 2023, Richard Lowe.

TESTDIR=$(dirname $0)

source ${TESTDIR}/../common.sh

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

gas -c ${TESTDIR}/strip-one-section.s -o strip-one-obj1.o
if (( $? != 0 )); then
	print -u2 "Couldn't assemble ${TESTDIR}/strip-one-section.s (obj1)"
	exit 1;
fi

/bin/ld -s strip-one-obj1.o -o strip-one
if (( $? != 0 )); then
	print -u2 "Couldn't link ${TESTDIR}/strip-one"
	exit 1;
fi

if [[ $(elfdump -cN.debug_stuff strip-one) != "" ]]; then
	print -u2 ".debug_stuff section not stripped"
	exit 1
fi

if [[ $(elfdump -cN.test_code strip-one) == "" ||
      $(elfdump -cN.test_data strip-one) == "" ]]; then
	print -u2 ".test section remains"
	exit 1
fi

# Test that the group, which is now smaller, makes it through ld -r
# correctly and that we don't crash
/bin/ld -r -s strip-one-obj1.o -o strip-one.o
if (( $? != 0 )); then
	print -u2 "Couldn't link ${TESTDIR}/strip-one.o"
	exit 1;
fi


if [[ $(elfdump -cN.group strip-one.o) == "" ]]; then
	print -u2 "No group section made it to the output object"
	exit 1
fi

find_in_group .group1 .test_data strip-one.o
find_in_group .group1 .test_code strip-one.o
