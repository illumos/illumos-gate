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

gas -c ${TESTDIR}/strip-all-sections.s -o strip-all-obj1.o
if (( $? != 0 )); then
	print -u2 "Couldn't assemble ${TESTDIR}/strip-all-section.s (obj1)"
	exit 1;
fi

/bin/ld -s strip-all-obj1.o -o strip-all
if (( $? != 0 )); then
	print -u2 "Couldn't link ${TESTDIR}/strip-all"
	exit 1;
fi

if [[ $(elfdump -cN.debug_stuff strip-all) != "" ||
      $(elfdump -cN.debug_data strip-all) != "" ||
      $(elfdump -cN.debug_code strip-all) != "" ]]; then
	print -u2 ".debug sections not stripped"
	exit 1
fi

# Test that the group, which is now empty, doesn't make it through ld -r
# and that we don't crash
/bin/ld -r -s strip-all-obj1.o -o strip-all.o
if (( $? != 0 )); then
	print -u2 "Couldn't link ${TESTDIR}/strip-all.o"
	exit 1;
fi

if [[ $(elfdump -cN.group strip-all.o) != "" ]]; then
	print -u2 "A group section survived despite all members getting stripped"
	exit 1
fi
