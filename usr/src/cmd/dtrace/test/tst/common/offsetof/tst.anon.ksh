#!/usr/bin/ksh
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
# Copyright 2025 Oxide Computer Company
#

#
# Test that we can correctly determine the offsets in various anonymous
# structures and unions.
#

if (( $# != 1 )); then
        printf "%s\n" "expected one argument: <dtrace-path>" >&2
        exit 2
fi

dtrace=$1
$dtrace -c ./tst.anon.exe -qs /dev/stdin <<EOF
BEGIN
{
	printf("a: %d, exp 0\n", offsetof(struct pid\`foo, a));
	printf("b: %d, exp 4\n", offsetof(struct pid\`foo, b));
	printf("c: %d, exp 4\n", offsetof(struct pid\`foo, c));
	printf("d: %d, exp 4\n", offsetof(struct pid\`foo, d));
	printf("e: %d, exp 8\n", offsetof(struct pid\`foo, e));
	printf("f: %d, exp 12\n", offsetof(struct pid\`foo, f));
	printf("g: %d, exp 4\n", offsetof(struct pid\`foo, g));
	printf("h: %d, exp 16\n", offsetof(struct pid\`foo, h));
	printf("i: %d, exp 20\n", offsetof(struct pid\`foo, i));
	printf("j: %d, exp 20\n", offsetof(struct pid\`foo, j));
	printf("k: %d, exp 24\n", offsetof(struct pid\`foo, k));
	printf("l: %d, exp 24\n", offsetof(struct pid\`foo, l));
	printf("m: %d, exp 28\n", offsetof(struct pid\`foo, m));
	printf("n: %d, exp 32\n", offsetof(struct pid\`foo, n));
	printf("o: %d, exp 32\n", offsetof(struct pid\`foo, o));
	printf("p: %d, exp 36\n", offsetof(struct pid\`foo, p));
	printf("q: %d, exp 24\n", offsetof(struct pid\`foo, q));
	printf("r: %d, exp 40\n", offsetof(struct pid\`foo, r));
	printf("s: %d, exp 20\n", offsetof(struct pid\`foo, s));
	printf("t: %d, exp 44\n", offsetof(struct pid\`foo, t));

	exit(0);
}
EOF
