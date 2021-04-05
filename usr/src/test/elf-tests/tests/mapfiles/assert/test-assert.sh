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

LDFLAGS="-Wl,-zguidance -Wl,-zfatal-warnings -Wl,-zdirect -Wl,-zlazyload"
ret=0

function should_succeed {
	mapfile=$1
	msg=$2

	if gcc -m32 -shared $LDFLAGS -Wl,-M,${TESTDIR}/$mapfile \
	    ${TESTDIR}/object.c -o object.so; then
		echo "pass (32): $msg"
	else
		echo "FAIL (32): $msg"
		ret=1
	fi

	if gcc -m64 -shared $LDFLAGS -Wl,-M,${TESTDIR}/$mapfile \
	    ${TESTDIR}/object.c -o object.so; then
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

	if gcc -m32 -shared $LDFLAGS -Wl,-M,${TESTDIR}/$mapfile \
	    ${TESTDIR}/object.c -o object.so 2>&1 | \
		   /usr/bin/grep -Eq "$error"; then
		echo "pass (32): $msg"
	else
		echo "FAIL (32): $msg"
		ret=1
	fi

	if gcc -m64 -shared $LDFLAGS -Wl,-M,${TESTDIR}/$mapfile \
	    ${TESTDIR}/object.c -o object.so 2>&1 | \
		   /usr/bin/grep -Eq "$error"; then
		echo "pass (64): $msg"
	else
		echo "FAIL (64): $msg"
		ret=1
	fi
}

should_succeed mapfile.true "link with correct mapfile"

should_fail mapfile.guidance "link without sized data" \
    "guidance:.*size assertion.*data"

should_fail mapfile.wrongtype "link with incorrect type in object (data v. function)" \
    "ld: fatal: .*mapfile.wrongtype: [0-9]+: assertion failed: type of symbol data should be:"

should_fail mapfile.wrongtype2 "link with incorrect type in object (common v. data)" \
    "ld: fatal: .*mapfile.wrongtype2: [0-9]+: assertion failed: type of symbol data should be:"

should_fail mapfile.wrongsize "link with incorrect size in object" \
    "ld: fatal: .*mapfile.wrongsize: [0-9]+: assertion failed: size of symbol data should be:"

should_fail mapfile.wrongscope "link with incorrect scope in object" \
    "ld: fatal: .*mapfile.wrongscope: [0-9]+: assertion failed: scope of symbol function should be:"

should_fail mapfile.wrongbits "link with incorrect shattr in object (nobits when bits)" \
    "ld: fatal: .*mapfile.wrongbits: [0-9]+: assertion failed: symbol [^ ]* is not in an SHT_NOBITS section"

should_fail mapfile.wrongbits2 "link with incorrect shattr in object (bits when nobits)" \
    "ld: fatal: .*mapfile.wrongbits2: [0-9]+: assertion failed: symbol [^ ]* is in an SHT_NOBITS section"

should_fail mapfile.unknown-assert "link with unknown assertion type" \
    "expected attribute name \([^\)]*\), or terminator \([^\)]*\): ICE"

should_fail mapfile.unknown-type "link with unknown type value" \
    "expected symbol type \([^\)]*\): CHEWY"

should_fail mapfile.unknown-bind "link with unknown bind value" \
    "expected binding type \([^\)]*\): HEMPEN"

should_fail mapfile.unknown-shattr "link with unknown shattr value" \
    "expected section attribute \([^)\]*\): WET"

should_fail mapfile.wrongalias "link with incorrect alias" \
    "ld: fatal: .*mapfile.wrongalias: [0-9]+: assertion failed: symbol weak_function is not an alias of common"

should_fail mapfile.alias-with-others "link with alias and other assertions" \
    "ALIAS assertions may only be used with BINDING"

should_fail mapfile.unknown-alias "link with alias to unknown symbol" \
    "ld: fatal: .*mapfile.unknown-alias: [0-9]+: assertion failed: unknown symbol in ALIAS: undefined_symbol"

should_fail mapfile.wrongtype-alias "link with alias to invalid token" \
    "expected string valued ALIAS"

should_fail mapfile.not-alias "link with two non-alias of the same value" \
    "ld: fatal: .*mapfile.not-alias: [0-9]+: weak_data and data (.*mapfile.not-alias: [0-9]+)"

should_fail mapfile.no-extern "link with assertions on an extern symbol" \
    "ld: fatal: .*mapfile.no-extern: [0-9]+: can't assert attributes of extern/parent symbol: extern"

should_fail mapfile.no-parent "link with assertions on a parent symbol" \
    "ld: fatal: .*mapfile.no-parent: [0-9]+: can't assert attributes of extern/parent symbol: parent"

should_fail mapfile.circalias "link with alias of alias" \
    "ld: fatal: .*mapfile.circalias: [0-9]+: weak_function should not be aliased to an alias"

exit $ret
