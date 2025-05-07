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
 * Tests for modern wcsftime (XPG5 and later) and wcsftime_l.   The libc tests
 * depend on locale/ar, locale/de, locale/en, and locale/ja. We limit
 * ourselves to these locales, plus C.UTF-8.
 */

#include <err.h>
#include <stdlib.h>
#include <xlocale.h>
#include <locale.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <stdbool.h>
#include <string.h>


/*
 * We're just testing that the desired locale reaches the underlying
 * formatter so we only look at one attribute: the full month name.
 */
static const struct test_locale {
	const char *name;
	const char *monthname;
} locales[] = {
	{ "C.UTF-8", "December"},
	{"ja_JP.UTF-8", "12月"},
	{"de_DE.UTF-8", "Dezember"},
	{"en_US.UTF-8", "December"},
};

struct tm sample_tm = { .tm_mon = 11 };

#define	WCSSIZE 100
#define	CSIZE 200

/*
 * Test that the correct decimal point is recognized.
 */
bool
test_locale(const char *name, const char *monthname)
{
	bool result_ok = true;
	wchar_t wfmt[WCSSIZE];
	wchar_t wcs[WCSSIZE];
	char cstring[CSIZE];

	size_t len;

	locale_t loc = newlocale(LC_ALL_MASK, name, NULL);

	if (loc == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "construct locale %s", name);
	}

	if (mbstowcs_l(wfmt, "%B", WCSSIZE, loc) == (size_t)-1) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "construct wide char format string");
	}

	len = wcsftime_l(wcs, WCSSIZE, wfmt, &sample_tm, loc);
	if (len == (size_t)-1) {
		warn("wcsftime_l returned -1");
		result_ok = false;
	}

	if (wcstombs_l(cstring, wcs, CSIZE, loc) == (size_t)-1) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "convert wide char string back to multibyte string");
	}

	if (strcmp(cstring, monthname)) {
		warn("Wrong monthname for locale %s month %d: "
		    "got %s expected %s", name, sample_tm.tm_mon+1,
		    cstring, monthname);
		result_ok = false;
	}

	(void) memset(wcs, 0, sizeof (wcs));
	(void) memset(cstring, 0, sizeof (cstring));

	if (uselocale(loc) == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "set locale %s", name);
	}

	len = wcsftime(wcs, WCSSIZE, wfmt, &sample_tm);
	if (len == (size_t)-1) {
		warn("wcsftime_l returned -1");
		result_ok = false;
	}

	if (wcstombs(cstring, wcs, CSIZE) == (size_t)-1) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "convert wide char string back to multibyte string");
	}

	if (strcmp(cstring, monthname)) {
		warn("Wrong monthname for locale %s month %d: "
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

	for (size_t i = 0; i < ARRAY_SIZE(locales); i++) {
		if (!test_locale(locales[i].name, locales[i].monthname))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}

	return (ret);
}
