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
 */

/*
 * Tests for getlocalename_l(3C). The libc tests depends on locale/ar,
 * locale/de, locale/en, and locale/ja. We limit ourselves to these locales,
 * plus C.UTF-8. We use a combination of global locales set via setlocale(),
 * locales set with uselocale(), and composite locale.
 */

#include <err.h>
#include <stdlib.h>
#include <locale.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
	int lc_cat;
	const char *lc_name;
} lc_cat_t;

static const lc_cat_t lc_cats[] = {
	{ LC_CTYPE, "LC_CTYPE" },
	{ LC_NUMERIC, "LC_NUMERIC" },
	{ LC_TIME, "LC_TIME" },
	{ LC_COLLATE, "LC_COLLATE" },
	{ LC_MONETARY, "LC_MONETARY" },
	{ LC_MESSAGES, "LC_MESSAGES" },
	{ LC_ALL, "LC_ALL" }
};
CTASSERT(ARRAY_SIZE(lc_cats) == LC_ALL + 1);

typedef struct {
	int lc_cat;
	int lc_mask;
	const char *lc_loc;
} lc_comp_t;

static const lc_comp_t composite[] = {
	{ LC_CTYPE, LC_CTYPE_MASK, "en_US.UTF-8" },
	{ LC_NUMERIC, LC_NUMERIC_MASK, "en_GB.UTF-8" },
	{ LC_TIME, LC_TIME_MASK, "de_DE.UTF-8" },
	{ LC_COLLATE, LC_COLLATE_MASK, "ar_EG.UTF-8" },
	{ LC_MONETARY, LC_MONETARY_MASK, "ja_JP.UTF-8" },
	{ LC_MESSAGES, LC_MESSAGES_MASK, "C.UTF-8" }
};

static const char *locales[] = { "C.UTF-8", "ja_JP.UTF-8", "de_DE.UTF-8",
	"en_US.UTF-8", "en_GB.UTF-8" };

/*
 * Check each category of a locale. These are ordered in exp by their LC_ type
 * category.
 */
static bool
locname_check(const char *desc, locale_t loc, const char **exp_names)
{
	bool ret = true;

	for (size_t i = 0; i < ARRAY_SIZE(lc_cats); i++) {
		const char *catname = lc_cats[i].lc_name;
		const char *exp = exp_names[lc_cats[i].lc_cat];
		const char *name = getlocalename_l(lc_cats[i].lc_cat, loc);
		if (name == NULL) {
			warnx("TEST FAILED: %s: failed to get locale name for "
			    "category %s: expected %s", desc, catname, exp);
			ret = false;
			continue;
		}

		if (strcmp(name, exp) != 0) {
			warnx("TEST FAILED: %s: got incorrect value for "
			    "category %s: expected %s, but got %s", desc,
			    catname, exp, name);
			ret = false;
		} else {
			(void) printf("TEST PASSED: %s: category %s\n", desc,
			    catname);
		}
	}

	return (ret);
}

/*
 * A small wrapper for names that are uniform.
 */
static bool
locname_check_all(const char *desc, locale_t loc, const char *exp)
{
	const char *names[LC_ALL + 1] = { exp, exp, exp, exp, exp, exp, exp };

	return (locname_check(desc, loc, names));
}

/*
 * Change each locale category one at a time and ensure that we get the expected
 * locale. Then set it as the global locale and ensure that this is what we
 * expect. We start from C. We track the names based on an array indexed by the
 * different categories and use the fact that they're ordered to know what to
 * check against.
 *
 * We also test setting the global locale to the result of this to ensure that
 * the results of composite locales are usable.
 */
static bool
locname_composite(void)
{
	bool ret = true;
	const char *names[LC_ALL + 1] = { "C", "C", "C", "C", "C", "C", NULL };
	locale_t loc = newlocale(LC_ALL_MASK, "C", NULL);

	if (loc == NULL) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to create "
		    "base C locale for composite tests");
	}

	for (size_t i = 0; i < ARRAY_SIZE(composite); i++) {
		char cname[1024], desc[1024];

		names[composite[i].lc_cat] = composite[i].lc_loc;
		(void) snprintf(cname, sizeof (cname), "%s/%s/%s/%s/%s/%s",
		    names[0], names[1], names[2], names[3], names[4], names[5]);
		names[LC_ALL] = cname;

		loc = newlocale(composite[i].lc_mask, composite[i].lc_loc,
		    loc);
		if (loc == NULL) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "evolve composite locale to %s", cname);
		}

		(void) snprintf(desc, sizeof (desc), "composite %s (%d)",
		    composite[i].lc_loc, composite[i].lc_cat);
		if (!locname_check(desc, loc, names))
			ret = false;

		if (setlocale(LC_ALL, getlocalename_l(LC_ALL, loc)) == NULL) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "set global locale to composite %s", cname);
		}

		(void) snprintf(desc, sizeof (desc), "global composite %s (%d)",
		    composite[i].lc_loc, composite[i].lc_cat);
		if (!locname_check(desc, loc, names))
			ret = false;
	}
	freelocale(loc);

	return (ret);
}

static bool
locname_invalid(void)
{
	bool ret = true;

	if (getlocalename_l(LC_ALL, NULL) != NULL) {
		ret = false;
		warnx("TEST FAILED: passing invalid locale: string incorrectly "
		    "returned");
	} else {
		(void) printf("TEST PASSED: invalid locale\n");
	}

	if (getlocalename_l(12345, LC_GLOBAL_LOCALE) != NULL) {
		ret = false;
		warnx("TEST FAILED: passing invalid category (1): string "
		    "incorrectly returned");
	} else {
		(void) printf("TEST PASSED: invalid category (1)\n");
	}

	if (getlocalename_l(0x7777, uselocale(NULL)) != NULL) {
		ret = false;
		warnx("TEST FAILED: passing invalid category (2): string "
		    "incorrectly returned");
	} else {
		(void) printf("TEST PASSED: invalid category (2)\n");
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	/*
	 * The default locale should be C.
	 */
	if (!locname_check_all("global locale: default", LC_GLOBAL_LOCALE, "C"))
		ret = EXIT_FAILURE;

	/*
	 * Test non-composite locales. We always do the thread-specific locale
	 * first so that way we can catch an erroneous locale.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(locales); i++) {
		char desc[1024];
		locale_t loc;

		loc = newlocale(LC_ALL_MASK, locales[i], NULL);
		if (loc == NULL) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "construct locale %s", locales[i]);
		}

		(void) snprintf(desc, sizeof (desc),
		    "%s: newlocale", locales[i]);
		if (!locname_check_all(desc, loc, locales[i]))
			ret = EXIT_FAILURE;

		(void) snprintf(desc, sizeof (desc),
		    "%s: thread locale", locales[i]);
		if (uselocale(loc) == NULL) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "transition thread to thread-specific locale %s, "
			    "cannot continue", locales[i]);
		}
		if (!locname_check_all(desc, uselocale(NULL), locales[i]))
			ret = EXIT_FAILURE;
		if (uselocale(LC_GLOBAL_LOCALE) == NULL) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "transition thread back to global locale, cannot "
			    "continue");
		}
		freelocale(loc);

		(void) snprintf(desc, sizeof (desc),
		    "%s: global locale", locales[i]);
		if (setlocale(LC_ALL, locales[i]) == NULL) {
			errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "set global locale to %s", locales[i]);
		}
		if (!locname_check_all(desc, LC_GLOBAL_LOCALE, locales[i]))
			ret = EXIT_FAILURE;
	}

	if (!locname_composite())
		ret = EXIT_FAILURE;

	if (!locname_invalid())
		ret = EXIT_FAILURE;

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}

	return (ret);
}
