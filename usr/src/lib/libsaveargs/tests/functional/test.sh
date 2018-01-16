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
# Copyright 2012, Richard Lowe.
#

function tester {
    prog=${1}
    pattern=${2}

    ./$prog >/dev/null &
    pid=$!
    if (/usr/bin/amd64/pstack $pid | /usr/bin/grep -q "${pattern}"); then
        echo "pass: ${prog}"
    else
        echo "FAIL: ${prog}"
    fi
    kill $pid
}

tester align "test (1, 2, 3, 4, 5)"
tester basic "test (1, 2, 3, 4)"
tester big-struct-ret "test (1, 2, 3, 4)"
tester big-struct-ret-and-spill "test (1, 2, 3, 4, 5, 6, 7, 8)"
tester small-struct-ret "test (1, 2, 3, 4)"
tester small-struct-ret-and-spill "test (1, 2, 3, 4, 5, 6, 7, 8)"
tester stack-spill "test (1, 2, 3, 4, 5, 6, 7, 8)"
