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
 * Copyright 2023 Bill Sommerfeld <sommerfeld@alum.mit.edu>
 */

/*
 * Test for closefrom().  Test cases were inspired by xapian's
 * test_closefrom1() and are somewhat incomplete (we don't test
 * what happens when /proc/self/fd isn't available).
 */
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/debug.h>

int
main(void)
{
	closefrom(INT_MAX);	/* should be a no-op */

	VERIFY3S(dup2(1, 10), ==, 10);
	VERIFY3S(dup2(1, 11), ==, 11);
	VERIFY3S(dup2(1, 15), ==, 15);

	closefrom(11);

	VERIFY3S(close(10), ==, 0);
	VERIFY3S(close(11), ==, -1);
	VERIFY3S(errno, ==, EBADF);
	VERIFY3S(close(15), ==, -1);
	VERIFY3S(errno, ==, EBADF);

	exit(0);
}
