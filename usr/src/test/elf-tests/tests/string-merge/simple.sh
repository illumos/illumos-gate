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

assemble() {
	gcc -c -o $2 $1
	if (( $? != 0 )); then
		print -u2 "assembly of ${1} failed";
		exit 1;
	fi
}

# We expect any alternate linker to be in LD_ALTEXEC for us already
assemble ${TESTDIR}/str1.s str1.o
assemble ${TESTDIR}/str2.s str2.o

gcc -shared -o strmerge.so str1.o str2.o
if (( $? != 0 )); then
	print -u2 "link of ${TESTDIR}/str[12].o failed";
	exit 1;
fi

elfdump -N.test -w /dev/stdout strmerge.so | tr '\0' ' ' | grep -q '^ buffalo bills $'
if (( $? != 0 )); then
	print -u2 "Merged section contains unexpected data";
	elfdump -N.test -w /dev/stdout strmerge.so | tr '\0' ' ' >&2
	exit 1;
fi
