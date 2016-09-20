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
 * Regression test for illumos#7350. Make sure that wcsncasecmp() doesn't read
 * data from the data buffer when zero characters are specified.
 */

#include <wchar.h>
#include <sys/debug.h>

int
main(void)
{
	wchar_t *a = (void *)(uintptr_t)0x8;
	wchar_t *b = (void *)(uintptr_t)0x40;

	VERIFY0(wcsncasecmp(a, b, 0));
	return (0);
}
