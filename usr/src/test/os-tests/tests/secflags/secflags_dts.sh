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

#
# Copyright 2015, Richard Lowe.
# Copyright 2019 Joyent, Inc.
# Copyright 2021 Oxide Computer Company
#

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

gcc -m32 -o tester-aslr.32 tester.c -Wl,-z,aslr=enabled
gcc -m32 -o tester-noaslr.32 tester.c -Wl,-z,aslr=disabled
gcc -m64 -o tester-aslr.64 tester.c -Wl,-z,aslr=enabled
gcc -m64 -o tester-noaslr.64 tester.c -Wl,-z,aslr=disabled

# This is the easiest way I've found to get many many DTs, but it's gross
gcc -m32 -o many-dts-aslr.32 tester.c -Wl,-z,aslr=enabled \
    $(for elt in /usr/lib/lib*.so; do echo -Wl,-N,$(basename $elt); done)
gcc -m32 -o many-dts-noaslr.32 tester.c -Wl,-z,aslr=disabled \
    $(for elt in /usr/lib/lib*.so; do echo -Wl,-N,$(basename $elt); done)
gcc -m64 -o many-dts-aslr.64 tester.c -Wl,-z,aslr=enabled \
    $(for elt in /usr/lib/64/lib*.so; do echo -Wl,-N,$(basename $elt); done)
gcc -m64 -o many-dts-noaslr.64 tester.c -Wl,-z,aslr=disabled \
    $(for elt in /usr/lib/64/lib*.so; do echo -Wl,-N,$(basename $elt); done)

check() {
    bin=$1
    state=$2
    set=$3
    ret=0

    $bin &
    pid=$!
    sleep 1
    psecflags $pid | grep -q "${set}:.*aslr"
    (( $? != state )) && ret=1
    kill -9 $pid
    return $ret
}

fail() {
    echo $@
    exit 1
}

psecflags -s none $$
check ./tester-aslr.32 0 E || fail "DT_SUNW_ASLR 1 failed (32-bit)"
check ./many-dts-aslr.32 0 E || fail \
    "DT_SUNW_ASLR 1 with many DTs failed (32-bit)"
check ./tester-aslr.32 1 I || fail \
    "DT_SUNW_ASLR 1 incorrectly set the inheritable flag (32-bit)"
check ./tester-aslr.64 0 E || fail "DT_SUNW_ASLR 1 failed (64-bit)"
check ./many-dts-aslr.64 0 E || fail \
    "DT_SUNW_ASLR 1 with many DTs failed (64-bit)"
check ./tester-aslr.64 1 I || fail \
    "DT_SUNW_ASLR 1 incorrectly set the inheritable flag (64-bit)"

psecflags -s aslr $$
check ./tester-noaslr.32 1 E || fail "DT_SUNW_ASLR 0 failed (32-bit)"
check ./many-dts-noaslr.32 1 E || fail  \
    "DT_SUNW_ASLR 0 with many DTs failed (32-bit)"
check ./tester-noaslr.64 1 E || fail "DT_SUNW_ASLR 0 failed (64-bit)"
check ./many-dts-noaslr.64 1 E || fail \
    "DT_SUNW_ASLR 0 with many DTs failed (64-bit)"
