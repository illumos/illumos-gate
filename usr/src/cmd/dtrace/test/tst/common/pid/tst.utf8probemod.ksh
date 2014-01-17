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
#include <stdlib.h>

extern void foo();

void
main()
{
	foo();
}
EOF

cat > libfoo.c <<EOF
#include <stdio.h>

void
foo()
{
	printf("called foo\n");
}
EOF

if ! gcc -m32 -fPIC -shared -o libføo.so libfoo.c -lc ; then
	print -u 2 "failed to compile libfoo in $DIR"
	exit 1
fi


if ! gcc -m32 -o foo foo.c -lføo -L. ; then
	print -u 2 "failed to compile foo in $DIR"
	exit 1
fi

export LD_LIBRARY_PATH=`pwd`

if ! dtrace -n 'pid$target:libf*::entry{printf("probemod: %s\n", probemod)}' \
    -qc ./foo ; then
	print -u 2 "dtrace failed in $DIR"
	exit 1
fi

cd 
rm -rf $DIR

