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
 * General tests for wcsncasecmp(). Test to make sure that the following are
 * true:
 *
 *   o Two identical strings are equal
 *   o Two strings with the same contents are equal
 *   o Case insensitive in ASCII works
 *   o Basic cases where strings aren't equal
 *   o An ASCII string that would compare greater due to case is properly less
 *   o Comparing with zero characters succeeds even if different strings
 *   o Characters in a locale / language that don't have a notion of case are
 *     consistent
 */

#include <wchar.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <locale.h>
#include <sys/debug.h>

int
main(void)
{
	int ret;
	wchar_t a[32], b[32];
	const char *str = "kefka";
	const char *caps = "KEFKA";
	const char *less = "celes";
	const char *more = "terra";
	const char *hikari = "光";
	const char *awake = "目覚め";
	size_t len = strlen(str);

	/*
	 * Start in en_US.UTF-8, which the test suites deps guarantee is
	 * present.
	 */
	(void) setlocale(LC_ALL, "en_US.UTF-8");
	(void) memset(a, 'a', sizeof (a));
	(void) memset(b, 'b', sizeof (b));

	ret = mbstowcs(a, str, len);
	VERIFY3U(ret, ==, len);
	ret = mbstowcs(b, str, len);
	VERIFY3U(ret, ==, len);

	VERIFY0(wcsncasecmp(a, a, len));
	VERIFY0(wcsncasecmp(a, b, len));

	ret = mbstowcs(b, caps, len);
	VERIFY3U(ret, ==, len);
	VERIFY0(wcsncasecmp(a, b, len));

	ret = mbstowcs(b, less, len);
	VERIFY3U(ret, ==, len);
	VERIFY3S(wcsncasecmp(a, b, len), >, 0);

	ret = mbstowcs(b, more, len);
	VERIFY3U(ret, ==, len);
	VERIFY3S(wcsncasecmp(a, b, len), <, 0);

	ret = mbstowcs(a, caps, len);
	VERIFY3U(ret, ==, len);
	ret = mbstowcs(b, less, len);
	VERIFY3U(ret, ==, len);
	VERIFY3S(wcsncmp(a, b, len), <, 0);
	VERIFY3S(wcsncasecmp(a, b, len), >, 0);

	VERIFY3S(wcsncasecmp(a, b, 0), ==, 0);

	/*
	 * This locale is also guaranteed by the test suite.
	 */
	(void) setlocale(LC_ALL, "ja_JP.UTF-8");
	ret = mbstowcs(a, hikari, sizeof (a));
	VERIFY3U(ret, >, 0);
	ret = mbstowcs(b, hikari, sizeof (b));
	VERIFY3U(ret, >, 0);
	VERIFY3S(wcsncasecmp(a, b, 1), ==, 0);

	ret = mbstowcs(b, awake, sizeof (b));
	VERIFY3U(ret, >, 0);
	VERIFY3S(wcsncasecmp(a, b, 1), !=, 0);

	return (0);
}
