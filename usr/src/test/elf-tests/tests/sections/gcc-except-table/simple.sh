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

# Copyright 2026 Oxide Computer Company

#
# Verify that per-function .gcc_except_table.<sym> input sections are
# merged into a single .gcc_except_table output section, matching the
# behaviour of GNU ld.
#

TESTDIR=$(dirname $0)

tmpdir=/tmp/test.$$
mkdir $tmpdir
cd $tmpdir

function cleanup {
	cd /
	rm -fr $tmpdir
}

trap cleanup EXIT


if [[ $PWD != $tmpdir ]]; then
	print -u2 "Failed to create temporary directory: $tmpdir"
	exit 1
fi

function assemble {
	gcc -c -o $2 $1
	if (( $? != 0 )); then
		print -u2 "assembly of ${1} failed"
		exit 1
	fi
}

assemble ${TESTDIR}/gcct1.s gcct1.o
assemble ${TESTDIR}/gcct2.s gcct2.o

gcc -shared -o gcct.so gcct1.o gcct2.o
if (( $? != 0 )); then
	print -u2 "link of gcct[12].o failed"
	exit 1
fi

#
# There must be exactly one section named .gcc_except_table, and no
# .gcc_except_table.<sym> sections from the per-function inputs.
#
nmerged=$(elfdump -c gcct.so | awk '
	$3 == "sh_name:" && $4 == ".gcc_except_table" { n++ }
	END { print n + 0 }
	')
if (( nmerged != 1 )); then
	print -u2 "FAIL: expected 1 .gcc_except_table section, found ${nmerged}"
	elfdump -c gcct.so | grep gcc_except >&2
	exit 1
fi

nsplit=$(elfdump -c gcct.so | awk '
	$3 == "sh_name:" && $4 ~ /^\.gcc_except_table\./ { n++ }
	END { print n + 0 }
	')
if (( nsplit != 0 )); then
	print -u2 "FAIL: .gcc_except_table.* sections were not merged"
	elfdump -c gcct.so | grep gcc_except >&2
	exit 1
fi

#
# Verify the merged section contains the bytes contributed by both inputs.
#
hex=$(elfdump -N.gcc_except_table -w /dev/stdout gcct.so |
    od -An -tx1 | tr -d ' \n')
case "$hex" in
*11223344*) ;;
*)
	print -u2 "FAIL: merged .gcc_except_table content unexpected: ${hex}"
	exit 1
	;;
esac

exit 0
