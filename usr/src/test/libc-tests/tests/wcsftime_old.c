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
 * Copyright 2025 Oxide Computer Company
 * Copyright 2025 Bill Sommerfeld
 */

/*
 * Locale test for the XPG4 version of wcsftime(), which takes a char *
 * format; later standards use a wchar_t * format.
 */

#define	_XOPEN_SOURCE
#define	_XOPEN_VERSION 4

#include <err.h>
#include <stdlib.h>
#include <wchar.h>
#include <locale.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <stdbool.h>
#include <string.h>

#ifndef _XPG4
#error _XPG4 should be defined for this file
#endif

#ifdef _XPG5
#error _XPG5 should not be defined for this file
#endif

/*
 * We're just testing that the desired locale reaches the underlying
 * formatter so we only look at one attribute: the full month name.
 */
static const struct test_locale {
	const char *name;
	const char *monthname;
} locales[] = {
	{ "C.UTF-8", "December" },
	{"ja_JP.UTF-8", "12月", },
	{"de_DE.UTF-8", "Dezember"},
	{"en_US.UTF-8", "December" },
};

struct tm sample_tm = { .tm_mon = 11, .tm_wday = 1 };

#define	WCSSIZE 100
#define	CSIZE 200

/*
 * Test that the correct decimal point is recognized.
 * Use old version of wcsftime which takes a char * parameter.
 */
static bool
test_locale(const char *name, const char *monthname)
{
	bool result_ok = true;
	wchar_t wcs[WCSSIZE];
	char cstring[CSIZE];

	size_t len;

	if (setlocale(LC_ALL, name) == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "set locale %s", name);
	}

	len = wcsftime(wcs, WCSSIZE, "%B", &sample_tm);
	if (len == (size_t)-1) {
		warn("TEST FAILED: wcsftime_l returned -1");
		result_ok = false;
	}

	if (wcstombs(cstring, wcs, CSIZE) == (size_t)-1) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "convert wide char string back to multibyte string");
	}

	if (strcmp(cstring, monthname)) {
		warn("TEST FAILED: Wrong month name for locale %s month %d: "
		    "got %s expected %s", name, sample_tm.tm_mon+1,
		    cstring, monthname);
		result_ok = false;
	}
	return (result_ok);
}


int
main(void)
{
	int ret = EXIT_SUCCESS;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(locales); i++) {
		if (!test_locale(locales[i].name, locales[i].monthname))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}

	return (ret);
}
