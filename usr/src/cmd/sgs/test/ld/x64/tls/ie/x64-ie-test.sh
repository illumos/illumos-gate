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

    if /usr/bin/fgrep -q "${pattern}"; then
	print -u2 "pass: $name"
    else
        print -u2 "FAIL: $name"
    fi
}        

function dis_test {
    name=${1}
    func=${2}
    file=${3}
    pattern=${4}

    dis -F${func} ${file} | grep_test "${name}" "${pattern}"
}

make PROTO="${1}"

dis_test "addq-->leaq 1" func style1 \
    'func+0x10: 48 8d 92 f8 ff ff  leaq   -0x8(%rdx),%rdx'
dis_test "addq-->leaq 2" func style1 \
    'func+0x17: 48 8d b6 f0 ff ff  leaq   -0x10(%rsi),%rsi'

dis_test "addq-->leaq w/REX 1" func style1-with-r13 \
    'func+0x10: 48 8d 92 f8 ff ff  leaq   -0x8(%rdx),%rdx'
dis_test "addq-->leaq w/REX 2" func style1-with-r13 \
    'func+0x17: 4d 8d ad f0 ff ff  leaq   -0x10(%r13),%r13'

dis_test "addq-->addq for SIB 1" func style1-with-r12 \
    'func+0x10: 48 8d 92 f8 ff ff  leaq   -0x8(%rdx),%rdx'
dis_test "addq-->addq for SIB 2" func style1-with-r12 \
    'func+0x17: 49 81 c4 f0 ff ff  addq   $-0x10,%r12	<0xfffffffffffffff0>'

dis_test "movq-->movq" main style2 \
    'main+0x4:  48 c7 c6 f0 ff ff  movq   $-0x10,%rsi	<0xfffffffffffffff0>'

dis_test "movq-->movq w/REX" main style2-with-r13 \
    'main+0x4:  49 c7 c5 f0 ff ff  movq   $-0x10,%r13	<0xfffffffffffffff0>'

dis_test "movq-->movq incase of SIB" main style2-with-r12 \
    'main+0x4:  49 c7 c4 f0 ff ff  movq   $-0x10,%r12	<0xfffffffffffffff0>'

make PROTO="${1}" fail 2>&1 | grep_test "bad insn sequence" \
   'ld: fatal: relocation error: R_AMD64_TPOFF32: file style2-with-badness.o: symbol foo: section .text: offset 0x7, relocation against unknown TLS instruction sequence'
