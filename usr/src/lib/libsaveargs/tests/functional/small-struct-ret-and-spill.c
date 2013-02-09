/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2012, Richard Lowe.
 */

#include <stdio.h>
#include <unistd.h>

struct foo {
	long a;
	long b;
};

struct foo
test(long a, long b, long c, long d, long e, long f, long g, long h)
{
	printf("%ld %ld %ld %ld %ld %ld %ld %ld\n", a, b, c, d, e, f, g, h);
	for (;;)
		sleep(60);
}

int
main(int argc, char **argv)
{
	test(1, 2, 3, 4, 5, 6, 7, 8);
	return (0);
}
