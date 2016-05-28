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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Register functions with quick_exit() and verify that we honor the expected
 * function call value. We facilitate this by having a global integer and
 * modifying it to various values in subsequent functions. If we're not called
 * in reverse order, we should spot the differences.
 */

#include <stdlib.h>
#include <sys/debug.h>

static int qeo_val = 5;

static void
qeo_fifth(void)
{
	VERIFY3S(qeo_val, ==, 5);
	qeo_val--;
}

static void
qeo_fourth(void)
{
	VERIFY3S(qeo_val, ==, 4);
	qeo_val--;
}

static void
qeo_third(void)
{
	VERIFY3S(qeo_val, ==, 3);
	qeo_val--;
}

static void
qeo_second(void)
{
	VERIFY3S(qeo_val, ==, 2);
	qeo_val--;
}

static void
qeo_first(void)
{
	VERIFY3S(qeo_val, ==, 1);
	qeo_val--;
}

static void
qeo_zero(void)
{
	VERIFY3S(qeo_val, ==, 0);
}

int
main(void)
{
	VERIFY0(at_quick_exit(qeo_zero));
	VERIFY0(at_quick_exit(qeo_first));
	VERIFY0(at_quick_exit(qeo_second));
	VERIFY0(at_quick_exit(qeo_third));
	VERIFY0(at_quick_exit(qeo_fourth));
	VERIFY0(at_quick_exit(qeo_fifth));
	quick_exit(0);
	abort();
}
