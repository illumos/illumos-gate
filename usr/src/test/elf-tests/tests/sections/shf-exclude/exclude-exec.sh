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

# Copyright 2021, Richard Lowe.

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

make -f ${TESTDIR}/Makefile.test SRCDIR=${TESTDIR} test.exec
if (( $? != 0 )); then
	print -u2 "FAIL: Failed to link dynamic executable"
	exit 1;
fi

elfdump -cN.test test.exec | grep -q SHF_EXCLUDE
if (( $? == 0 )); then
	print -u2 "FAIL: SHF_EXCLUDE section was linked into dynamic executable"
	exit 1;
fi
