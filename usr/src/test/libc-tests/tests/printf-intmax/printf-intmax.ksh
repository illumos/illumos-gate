#! /usr/bin/ksh
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

#
# Copyright 2025 Hans Rosenfeld
#

unalias -a
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

FAILED=0

cleanup ()
{
    rm -f ${TEMP}/c{89,99}.exp
    rm -f ${TEMP}/c99.{32,64}
    rm -f ${TEMP}/c89
    rmdir ${TEMP}
}

compare ()
{
    if cmp -s ${TEMP}/$1 ${TEMP}/$2; then
        echo "$2 test passed"
    else
        FAILED=1
        echo "$2 test failed" >2
        diff -u ${TEMP}/$1 ${TEMP}/$2
    fi
}

TESTS=/opt/libc-tests/tests
TEMP=$(mktemp -d -t intmax)

[[ -z "${TEMP}" ]] && exit 1

trap cleanup EXIT

cat >${TEMP}/c89.exp <<EOF
long long: 0xffffffffffffffff
intmax_t: 0xffffffff
EOF

(( $? != 0 )) && exit 1

cat >${TEMP}/c99.exp <<EOF
long long: 0xffffffffffffffff
intmax_t: 0xffffffffffffffff
EOF

(( $? != 0 )) && exit 1

${TESTS}/printf-intmax.32 >${TEMP}/c99.32
${TESTS}/printf-intmax.64 >${TEMP}/c99.64
${TESTS}/printf-intmax.c89 >${TEMP}/c89

compare c89.exp c89
compare c99.exp c99.32
compare c99.exp c99.64

(( FAILED != 0 )) && exit 1

exit 0
