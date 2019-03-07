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

dis_test "call-->nop" main half-ldm \
    'main\+0x9:  0f 1f 44 00 00     nopl   0x0(%eax,%eax)'

./half-ldm | grep_test 'half-ldm execution' \
    '^foo: foo ([a-f0-9]*)$'
