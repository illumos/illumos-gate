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
 * Tests for locale interaction with strto{f,d,ld}(3C) and
 * strto{f,d,ld}_l(3C). The libc tests depend on locale/ar, locale/de,
 * locale/en, and locale/ja. We limit ourselves to these locales, plus
 * C.UTF-8.
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
 * We use a value with a fractional part that can be represented exactly
 * as a binary floating point number
 */

static struct test_locale {
	char *name;
	char *number;
} locales[] = {
	{ "C.UTF-8", "1.5"},
	{"ja_JP.UTF-8", "1.5"},
	{"de_DE.UTF-8", "1,5"},
	{"en_US.UTF-8", "1.5"},
	{"en_GB.UTF-8", "1.5" },
};

/*
 * Test that the correct decimal point is recognized.
 */
bool
test_locale(char *name, char *number)
{
	bool result_ok = true;
	const float expected_f = 1.5;
	const double expected_d = 1.5;
	const long double expected_ld = 1.5;
	char *expected_end = number + strlen(number);
	char *actual_end;
	float actual_f;
	double actual_d;
	long double actual_ld;

	locale_t loc = newlocale(LC_ALL_MASK, name, NULL);

	if (loc == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "construct locale %s", name);
	}

#define	CHECK_END(fn) \
	if (actual_end != expected_end) {				\
		warn("Locale %s, function %s: consumed %td characters"	\
		    " (%td expected)", name, #fn,			\
		    actual_end - number, expected_end - number);	\
		result_ok = false;					\
	}

	actual_f = strtof_l(number, &actual_end, loc);
	if (actual_f != expected_f) {
		result_ok = false;
		warn("Locale %s: strtof_l: mismatched value %f vs %f",
		    name, actual_f, expected_f);
	}
	CHECK_END(strtof_l);

	actual_d = strtod_l(number, &actual_end, loc);
	if (actual_d != expected_d) {
		result_ok = false;
		warn("Locale %s: strtod_l: mismatched value %f vs %f",
		    name, actual_d, expected_d);
	}
	CHECK_END(strtod_l);

	actual_ld = strtold_l(number, &actual_end, loc);
	if (actual_ld != expected_ld) {
		result_ok = false;
		warn("Locale %s: strtold_l: mismatched value %Lf vs %Lf",
		    name, actual_ld, expected_ld);
	}
	CHECK_END(strtold_l);

	if (uselocale(loc) == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "set locale %s", name);
	}

	actual_f = strtod(number, &actual_end);
	if (actual_f != expected_f) {
		result_ok = false;
		warn("Locale %s: strtof: mismatched value %f vs %f",
		    name, actual_f, expected_f);
	}
	CHECK_END(strtof);

	actual_d = strtod(number, &actual_end);
	if (actual_d != expected_d) {
		result_ok = false;
		warn("Locale %s: strtod: mismatched value %f vs %f",
		    name, actual_d, expected_d);
	}
	CHECK_END(strtod);

	actual_ld = strtold(number, &actual_end);
	if (actual_ld != expected_ld) {
		result_ok = false;
		warn("Locale %s: strtold: mismatched value %Lf vs %Lf",
		    name, actual_ld, expected_ld);
	}
	CHECK_END(strtold);

	return (result_ok);
}


int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(locales); i++) {
		if (!test_locale(locales[i].name, locales[i].number))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}

	return (ret);
}
