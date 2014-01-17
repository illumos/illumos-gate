#!/bin/ksh -p
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
# Copyright (c) 2013 Joyent, Inc.  All rights reserved.
#

DIR=/var/tmp/dtest.$$
mkdir $DIR
cd $DIR

cat > foo.c <<EOF
#include <stdio.h>

void
foo()
{
	printf("in foo\n");
}

void
main()
{
	foo();
}
EOF

if ! gcc -m32 -S -o foo.orig.s foo.c ; then
	print -u 2 "failed to compile foo in $DIR"
	exit 1
fi

#
# There's the right way, the wrong way, and the Max Power way!
#
cat foo.orig.s | sed 's/foo/foø/g' > foo.s
gcc -o foo foo.s

if ! dtrace -n 'pid$target:a.out:f*:entry{printf("probefunc: %s\n", \
    probefunc)}' -qc ./foo ; then
	print -u 2 "dtrace failed in $DIR"
	exit 1
fi

cd
rm -rf $DIR
exit 0
