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
 * Copyright 2025 Bill Sommerfeld
 */

/*
 * Tests for localeconv(3C) and localeconv_l(3C). The libc tests depends on
 * locale/ar, locale/de, locale/en, and locale/ja. We limit ourselves to
 * these locales, plus C.UTF-8.
 */

#include <err.h>
#include <stdlib.h>
#include <xlocale.h>
#include <locale.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <stdbool.h>
#include <string.h>


static struct test_locale {
	const char *name;
	locale_t loc;
	struct lconv lconv;
} locales[] = {
	{ "C.UTF-8"},
	{ "ja_JP.UTF-8" },
	{ "de_DE.UTF-8" },
	{ "en_US.UTF-8" },
	{ "en_GB.UTF-8" },
};

static bool
compare_lconv(const char *name, const struct lconv *a, const struct lconv *b)
{
	bool all_match = true;

#define	FAIL(field, fmt) { warnx("TEST FAILED: %s %s mismatched"	\
	" (" fmt " vs " fmt ")",					\
	name, #field, a->field, b->field); all_match = false; }

#define	COMPARE_INT(field) if (a->field != b->field) FAIL(field, "%d")
#define	COMPARE_STR(field) if (strcmp(a->field, b->field)) FAIL(field, "'%s'")
	/* grouping encodes an array of int8_t's; punt on printing them */
#define	COMPARE_GRP(field) if (strcmp(a->field, b->field)) FAIL(field, "%p")

	COMPARE_STR(decimal_point);
	COMPARE_STR(thousands_sep);
	COMPARE_GRP(grouping);
	COMPARE_STR(int_curr_symbol);
	COMPARE_STR(currency_symbol);
	COMPARE_STR(mon_decimal_point);
	COMPARE_STR(mon_thousands_sep);
	COMPARE_GRP(mon_grouping);
	COMPARE_STR(positive_sign);
	COMPARE_STR(negative_sign);

	COMPARE_INT(int_frac_digits);
	COMPARE_INT(frac_digits);
	COMPARE_INT(p_cs_precedes);
	COMPARE_INT(p_sep_by_space);
	COMPARE_INT(n_cs_precedes);
	COMPARE_INT(n_sep_by_space);
	COMPARE_INT(p_sign_posn);
	COMPARE_INT(n_sign_posn);

	COMPARE_INT(int_p_cs_precedes);
	COMPARE_INT(int_p_sep_by_space);
	COMPARE_INT(int_n_cs_precedes);
	COMPARE_INT(int_n_sep_by_space);
	COMPARE_INT(int_p_sign_posn);
	COMPARE_INT(int_n_sign_posn);

	return (all_match);
}
int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(locales); i++) {
		locales[i].loc = newlocale(LC_ALL_MASK, locales[i].name, NULL);
		if (locales[i].loc == NULL) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "construct locale %s", locales[i].name);
		}

		if (uselocale(locales[i].loc) == NULL) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "set locale %s", locales[i].name);
		}

		locales[i].lconv = *localeconv();
	}
	for (size_t i = 0; i < ARRAY_SIZE(locales); i++) {
		if (!compare_lconv(locales[i].name,
		    localeconv_l(locales[i].loc),
		    &locales[i].lconv)) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}

	return (ret);
}
