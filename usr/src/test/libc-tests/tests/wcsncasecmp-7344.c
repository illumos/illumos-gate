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
 * Regression test for illumos#7344. Make sure that wcsncasecmp() only checks
 * the specified number of bytes.
 */

#include <wchar.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/debug.h>

int
main(void)
{
	wchar_t a[8], b[8];

	(void) memset(a, 'a', sizeof (a));
	(void) memset(b, 'a', sizeof (b));

	a[7] = 'n';
	b[7] = 'o';

	VERIFY0(wcsncasecmp(a, b, 7));
	return (0);
}
