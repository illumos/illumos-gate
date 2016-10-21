#! /usr/bin/ksh
#
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

# Copyright 2015, Richard Lowe.

tmpdir=/tmp/test.$$
mkdir $tmpdir
cd $tmpdir

cleanup() {
    cd /
    rm -fr $tmpdir
}

trap 'cleanup' EXIT

cat > tester.c <<EOF
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	sleep(10000);
	return (0);
}
EOF

gcc -o tester-aslr tester.c -Wl,-z,aslr=enabled
gcc -o tester-noaslr tester.c -Wl,-z,aslr=disabled

# This is the easiest way I've found to get many many DTs, but it's gross
gcc -o many-dts-aslr tester.c -Wl,-z,aslr=enabled $(for elt in /usr/lib/lib*.so; do echo -Wl,-N,$(basename $elt); done)
gcc -o many-dts-noaslr tester.c -Wl,-z,aslr=disabled $(for elt in /usr/lib/lib*.so; do echo -Wl,-N,$(basename $elt); done)

check() {
    bin=$1
    state=$2
    set=$3
    ret=0

    $bin &
    pid=$!
    psecflags $pid | grep -q "${set}:.*aslr"
    (( $? != $state )) && ret=1
    kill -9 $pid
    return $ret
}

fail() {
    echo $@
    exit 1
}

psecflags -s none $$
check ./tester-aslr 0 E || fail "DT_SUNW_ASLR 1 failed"
check ./many-dts-aslr 0 E || fail "DT_SUNW_ASLR 1 with many DTs failed"
check ./tester-aslr 1 I || fail "DT_SUNW_ASLR 1 incorrectly set the inheritable flag"

psecflags -s aslr $$
check ./tester-noaslr 1 E || fail "DT_SUNW_ASLR 0 failed"
check ./many-dts-noaslr 1 E || fail "DT_SUNW_ASLR 0 with many DTs failed"

