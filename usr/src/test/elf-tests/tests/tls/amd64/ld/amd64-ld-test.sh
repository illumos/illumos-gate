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

# Copyright 2012, Richard Lowe.

function grep_test {
    name=$1
    pattern=$2

    if /usr/bin/grep -q "${pattern}"; then
	print -u2 "pass: $name"
        else
        print -u2 "FAIL: $name"
        exit 1
    fi
}

function dis_test {
    name=${1}
    func=${2}
    file=${3}
    pattern=${4}

    dis -F${func} ${file} | grep_test "${name}" "${pattern}"
}

TESTDIR=$(dirname $0)

make -f ${TESTDIR}/Makefile.test TESTDIR=${TESTDIR}

# if we fail, the addend won't be applied, the leaq with be -0x10(%rax)
dis_test "addend is preserved" main ld-with-addend \
    'main+0x10: 48 8d b0 f2 ff ff  leaq   -0xe(%rax),%rsi'

# We have an addend of 2, a failure will print 'incorrect'
./ld-with-addend | grep_test 'ld-with-addend execution' \
    '^foo: correct ([a-f0-9]*)$'
