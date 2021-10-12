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

make -f ${TESTDIR}/Makefile.test SRCDIR=${TESTDIR}
if (( $? != 0 )); then
	print -u2 "FAIL: Failed to link"
	exit 1;
fi

elfdump -sN.symtab libtest.so | awk '$9 ~ /(bss|data)_symbol/ {
	if ($5 != "LOCL") {
		exit 1;
	}
}'

if (( $? != 0 )); then
	print -u2 "FAIL: libtest.so COMDAT symbols not reduced to local"
	exit 1;
fi

elfdump -sN.symtab libothertest.so | awk '$9 ~ /(bss|data)_symbol/ {
	if ($5 != "LOCL") {
		exit 1;
	}
}'

if (( $? != 0 )); then
	print -u2 "FAIL: libothertest.so COMDAT symbols not reduced to local"
	exit 1;
fi

elfdump -s libnoref.so | grep -q _symbol
if (( $? == 0 )); then
	print -u2 "FAIL: unreferenced symbols survive into output object"
	exit 1;
fi

./test
if (( $? != 0 )); then
	print -u2 "FAIL: Failed to execute ./test"
	exit 1;
fi
