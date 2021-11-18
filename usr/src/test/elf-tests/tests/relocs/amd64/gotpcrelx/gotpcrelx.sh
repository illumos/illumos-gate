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

if [[ -n $PROTO ]]; then
	export LD_ALTEXEC=$PROTO/bin/ld
fi

gas -64 --mrelax-relocations=yes -c ${TESTDIR}/gotpcrel.s -o gotpcrel.o
if (( $? != 0 )); then
	print -u2 "Couldn't assemble ${TESTDIR}/gotpcrel.s with relocation relaxation"
	exit 1;
fi

$PROTO/bin/elfdump -rN.rela.text gotpcrel.o | \
	awk '$5 == "foo" {
		if ($1 == "R_AMD64_GOTPCRELX") {
			exit(0)
		} else {
			exit(1)
		}
	     }'
if (( $? != 0 )); then
	print -u2 "Assembled ${TESTDIR}/gotpcrel.s did not result in relaxed relocation"
	exit 1;
fi

gcc -fno-pie -m64 gotpcrel.o -o gotpcrel
if (( $? != 0 )); then
	print -u2 "Couldn't link ${TESTDIR}/gotpcrel.s"
	exit 1;
fi

./gotpcrel | grep -q '^string$'
if (( $? != 0 )); then
	print -u2 "${TESTDIR}/gotpcrel.s ran incorrectly"
	exit 1;
fi

exit 0
