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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2026 Bill Sommerfeld <sommerfeld@hamachi.org>
 */

/*
 * This program tests that newlocale and uselocale work properly in
 * multi-threaded programs.  In order for it to work, it requires that
 * some additional locales be installed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <langinfo.h>
#include <nl_types.h>
#include <err.h>
#include <unistd.h>
#include <pthread.h>
#include <note.h>
#include <errno.h>
#include <sys/mman.h>
#include "test_common.h"

/*
 * Note that on some platforms, different symbols are used.  For example,
 * MacOS Mavericks uses "Eu" for Euro symbol, instead of €.  If the locale
 * data changes, then this program will need to update to reflect that.
 */
struct ldata {
	const char *locale;
	const char *day1;
	const char *cursym;
} ldata[] = {
	{ "C", "Sunday", "" },
	{ "en_US.UTF-8", "Sunday", "$" },
	{ "de_DE.UTF-8", "Sonntag", "€" },
	{ "ru_RU.UTF-8", "воскресенье", "₽" },
	{ "ja_JP.UTF-8", "日曜日", "￥" },
};

static uint8_t *guarded_page;
static size_t page_size;

void
setup_trap(void)
{
	page_size = getpagesize();

	guarded_page = mmap(NULL, 2 * page_size, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0);
	if (guarded_page == MAP_FAILED) {
		perror("mmap");
		guarded_page = NULL;
		return;
	}

	if (mprotect(guarded_page + page_size, page_size, PROT_NONE) < 0) {
		perror("mprotect");
		guarded_page = NULL;
	}
}

const char *
guarded_str(const char *str)
{
	size_t len = strlen(str) + 1;
	char *loc;

	if (guarded_page == NULL)
		return (str);

	if (len > page_size) {
		errx(EXIT_FAILURE,  "%zd byte string exceeds page size %zd",
		    len, page_size);
	}

	memset(guarded_page, 0xa5, page_size);
	loc = (char *)(guarded_page + page_size - len);
	memcpy(loc, str, len);

	return ((const char *)loc);
}

#define	G(s) (guarded_str(s))

#define	NUM_LDATA	5
#define	NUMTHR	20
#define	NUMITR	200

int extra_debug = 0;

static void
testlocale_thr_one(test_t t, void *arg)
{
	_NOTE(ARGUNUSED(arg));
	locale_t	cloc, loc;
	struct lconv	*lc;
	char		*day;

	for (int i = 0; i < NUMITR; i++) {
		struct ldata *l = &ldata[i % NUM_LDATA];
		cloc = uselocale(NULL);

		loc = newlocale(LC_ALL_MASK, l->locale, NULL);
		if (loc == NULL) {
			test_failed(t, "newlocale %s failed", l->locale);
		}
		day = nl_langinfo_l(DAY_1, loc);
		if (strcmp(day, l->day1) != 0) {
			test_failed(t, "newlocale data mismatch (%s != %s)",
			    day, l->day1);
		}
		if (extra_debug)
			test_debugf(t, "DAY1: %s", day);

		day = nl_langinfo(DAY_1);
		if (strcmp(day, "Sunday") != 0) {
			test_failed(t, "C locale day wrong %s != Sunday",
			    day);
		}
		lc = localeconv();
		if (strcmp(lc->currency_symbol, "") != 0) {
			test_failed(t, "C cursym mismatch (%s != %s)",
			    lc->currency_symbol, "");
		}

		/* we sleep a random bit to mix it up */
		(void) usleep(rand() % 10);

		(void) uselocale(loc);
		day = nl_langinfo(DAY_1);
		if (strcmp(day, l->day1) != 0) {
			test_failed(t, "uselocale data mismatch (%s != %s)",
			    day, l->day1);
		}

		lc = localeconv();
		if (strcmp(lc->currency_symbol, l->cursym) != 0) {
			test_failed(t, "uselocal cursym %s != %s",
			    lc->currency_symbol, l->cursym);
		}
		if (extra_debug)
			test_debugf(t, "CSYM: %s", lc->currency_symbol);

		/* we sleep a random bit to mix it up */
		(void) usleep(rand() % 10);

		if (uselocale(cloc) != loc) {
			test_failed(t, "revert old locale mismatch");
		}
		freelocale(loc);
		if (uselocale(LC_GLOBAL_LOCALE) != cloc) {
			test_failed(t, "revert GLOBAL_LOCALE mismatch");
		}
	}
	test_passed(t);
}


static void
test_newlocale_threaded(void)
{
	test_run(NUMTHR, testlocale_thr_one, NULL, "newlocale_threaded");
}

static void
test_newlocale_negative(void)
{
	locale_t loc, bad;
	char *day;
	char *tname = "newlocale_negative";
	test_t t;

	t = test_start(tname);
	loc = newlocale(LC_ALL_MASK, "de_DE.UTF-8", NULL);
	if (loc == NULL) {
		test_failed(t, "cannot set de_DE.UTF-8");
	}
	day = nl_langinfo_l(DAY_1, loc);
	if (strcmp(day, "Sonntag") != 0) {
		test_failed(t, "incorrect Sonntag != %s", day);
	}

	bad = newlocale(LC_ALL_MASK, "cn_US.BIZRRE", loc);
	if (bad != NULL) {
		test_failed(t, "passed setting bogus locale");
	}
	day = nl_langinfo_l(DAY_1, loc);
	if (strcmp(day, "Sonntag") != 0) {
		test_failed(t, "incorrect Sonntag != %s", day);
	}
	test_passed(t);
}

static void
test_newlocale_categories(void)
{
	locale_t loc;
	char *day, *cur, *yes;
	char *tname = "newlocale_categories";
	test_t t;

	t = test_start(tname);

	loc = NULL;
	loc = newlocale(LC_TIME_MASK, "de_DE.UTF-8", loc);
	loc = newlocale(LC_MESSAGES_MASK, "ru_RU.UTF-8", loc);
	loc = newlocale(LC_MONETARY_MASK, "en_US.UTF-8", loc);

	if (loc == NULL) {
		test_failed(t, "failed to set locale");
	}

	day = nl_langinfo_l(DAY_1, loc);
	if ((day == NULL) || (strcmp(day, "Sonntag") != 0)) {
		test_failed(t, "day1 mismatch %s != %s", day, "Sonntag");
	}
	yes = nl_langinfo_l(YESSTR, loc);
	if ((yes == NULL) || (strcmp(yes, "да") != 0)) {
		test_failed(t, "currency mismatch");
	}
	cur = nl_langinfo_l(CRNCYSTR, loc);
	if ((cur == NULL) || (strcmp(cur, "-$") != 0)) {
		test_failed(t, "currency mismatch [%s] != [%s]", cur, "-$");
	}

	test_passed(t);
}

static void
test_newlocale_composite(void)
{
	locale_t loc;
	char *day, *cur, *yes;
	char *tname = "newlocale_composite";
	test_t t;

	t = test_start(tname);

	/* order: CTYPE/NUMERIC/TIME/COLLATE/MONETARY/MESSAGES */
	loc = newlocale(LC_ALL_MASK,
	    "C/C/de_DE.UTF-8/C/en_US.UTF-8/ru_RU.UTF-8", NULL);

	if (loc == NULL) {
		test_failed(t, "failed to set composite locale");
	}

	day = nl_langinfo_l(DAY_1, loc);
	if ((day == NULL) || (strcmp(day, "Sonntag") != 0)) {
		test_failed(t, "day1 mismatch %s != %s", day, "Sonntag");
	}
	yes = nl_langinfo_l(YESSTR, loc);
	if ((yes == NULL) || (strcmp(yes, "да") != 0)) {
		test_failed(t, "currency mismatch");
	}
	cur = nl_langinfo_l(CRNCYSTR, loc);
	if ((cur == NULL) || (strcmp(cur, "-$") != 0)) {
		test_failed(t, "currency mismatch [%s] != [%s]", cur, "-$");
	}

	test_passed(t);
}

static void
test_newlocale_composite_glibc(void)
{
	locale_t loc;
	char *day, *cur;
	const char *name;
	char *tname = "newlocale_composite_glibc";
	test_t t;

	/* parse glibc-style composite locale names */
	t = test_start(tname);

	loc = newlocale(LC_ALL_MASK, "C", NULL);

	if (loc == NULL) {
		test_failed(t, "failed to set base locale");
	}

	loc = newlocale(LC_TIME_MASK | LC_MONETARY_MASK,
	    "LC_FRUIT=banana;LC_TIME=de_DE.UTF-8;LC_MONETARY=en_US.UTF-8",
	    loc);

	if (loc == NULL) {
		test_failed(t, "failed to set composite locale");
	}

	day = nl_langinfo_l(DAY_1, loc);
	if ((day == NULL) || (strcmp(day, "Sonntag") != 0)) {
		test_failed(t, "day1 mismatch %s != %s", day, "Sonntag");
	}
	cur = nl_langinfo_l(CRNCYSTR, loc);
	if ((cur == NULL) || (strcmp(cur, "-$") != 0)) {
		test_failed(t, "currency mismatch [%s] != [%s]", cur, "-$");
	}

	name = getlocalename_l(LC_ALL, loc);
	if (name == NULL) {
		test_failed(t, "empty locale name returned");
	}
	if (strcmp(name, "C/C/de_DE.UTF-8/C/en_US.UTF-8/C") != 0) {
		test_failed(t, "unexpected locale name [%s] returned", name);
	}

	/*
	 * Attempt to check that, in a glibc-style composite name,
	 * LC_ALL does not have special meaning.
	 */
	loc = newlocale(LC_TIME_MASK | LC_MONETARY_MASK,
	    "LC_ALL=C;LC_TIME=de_DE.UTF-8;LC_MONETARY=en_US.UTF-8",
	    NULL);
	if (loc == NULL) {
		test_failed(t, "failed to set composite locale (with LC_ALL)");
	}
	day = nl_langinfo_l(DAY_1, loc);
	if ((day == NULL) || (strcmp(day, "Sonntag") != 0)) {
		test_failed(t, "day1 mismatch %s != %s", day, "Sonntag");
	}

	/*
	 * Check that, in a glibc-style composite name with multiple
	 * assignments of a category, the last one wins.
	 */
	loc = newlocale(LC_TIME_MASK | LC_MONETARY_MASK,
	    "LC_TIME=C;LC_MONETARY=en_US.UTF-8;LC_TIME=de_DE.UTF-8",
	    NULL);
	if (loc == NULL) {
		test_failed(t, "failed to set composite locale (dup category)");
	}
	day = nl_langinfo_l(DAY_1, loc);
	if ((day == NULL) || (strcmp(day, "Sonntag") != 0)) {
		test_failed(t, "day1 mismatch %s != %s", day, "Sonntag");
	}

	test_passed(t);
}

static void
test_newlocale_all_categories(void)
{
	locale_t loc;
	char *tname = "newlocale_all_categories";
	const char *name;
	test_t t;

	/* Composite locale name obstacle course */
	t = test_start(tname);

	/* Test all categories */
	loc = newlocale(LC_ALL_MASK,
	    "LC_MESSAGES=ru_RU.UTF-8;LC_MONETARY=en_US.UTF-8;LC_COLLATE=C;"
	    "LC_TIME=ja_JP.UTF-8;LC_NUMERIC=C;LC_CTYPE=C.UTF-8",
	    NULL);

	name = getlocalename_l(LC_ALL, loc);
	if (name == NULL) {
		test_failed(t, "empty locale name returned");
	}
	if (strcmp(name,
	    "C.UTF-8/C/ja_JP.UTF-8/C/en_US.UTF-8/ru_RU.UTF-8") != 0) {
		test_failed(t, "unexpected locale name [%s] returned", name);
	}

	/* once again, but with setlocale() */
	name = setlocale(LC_ALL,
	    "LC_MESSAGES=en_US.UTF-8;LC_MONETARY=ru_RU.UTF-8;LC_COLLATE=C;"
	    "LC_TIME=ja_JP.UTF-8;LC_NUMERIC=C;LC_CTYPE=C.UTF-8");
	if (name == NULL) {
		test_failed(t, "setlocale returned NULL");
	}
	if (strcmp(name,
	    "C.UTF-8/C/ja_JP.UTF-8/C/ru_RU.UTF-8/en_US.UTF-8") != 0) {
		test_failed(t,
		    "unexpected locale name [%s] returned by setlocale",
		    name);
	}

	name = getlocalename_l(LC_ALL, LC_GLOBAL_LOCALE);
	if (name == NULL) {
		test_failed(t, "empty locale name returned");
	}
	if (strcmp(name,
	    "C.UTF-8/C/ja_JP.UTF-8/C/ru_RU.UTF-8/en_US.UTF-8") != 0) {
		test_failed(t,
		    "unexpected locale name [%s] returned by getlocalename_l",
		    name);
	}

	test_passed(t);
}

static void
test_newlocale_environment(void)
{
	locale_t loc;
	char *day;
	char *tname = "newlocale_environment";
	test_t t;
	static const char *envs[] = {
		"LC_ALL",
		"LC_TIME",
		"LANG",
		NULL
	};
	static const char **envp;

	/* check how glibc composite locales peek into the environment */
	t = test_start(tname);

	for (envp = envs; *envp != NULL; envp++) {
		if (unsetenv(*envp) != 0) {
			errx(EXIT_FAILURE, "Failed to unset %s in environment",
			    *envp);
		}
	}

	for (envp = envs; *envp != NULL; envp++) {
		if (setenv(*envp, "de_DE.UTF-8", 1) != 0) {
			errx(EXIT_FAILURE, "Failed to set %s in environment",
			    *envp);
		}

		/* empty value falls through to environment */
		loc = newlocale(LC_TIME_MASK, G(";LC_TIME="), NULL);
		if (loc == NULL) {
			test_failed(t, "expected newlocale success with %s",
			    *envp);
		}
		day = nl_langinfo_l(DAY_1, loc);
		if ((day == NULL) || (strcmp(day, "Sonntag") != 0)) {
			test_failed(t, "day1 mismatch %s != %s with %s",
			    day, "Sonntag", *envp);
		}
		if (unsetenv(*envp) != 0)
			errx(EXIT_FAILURE, "Failed to unset %s in environment",
			    *envp);
	}

	test_passed(t);
}

#define	CHECK_ERRNO(e) do {						   \
		if (errno != e)						   \
			test_failed(t, "expected " #e " in errno, got %s", \
					    strerrorname_np(errno));	   \
		errno = 0;						   \
	} while (0)

static void
test_newlocale_parser_coverage(void)
{
	locale_t loc;
	char *tname = "newlocale_parser_coverage";
	test_t t;

	/* Composite locale name obstacle course */
	t = test_start(tname);

	setup_trap();

	/* no category names */
	errno = 0;
	loc = newlocale(LC_TIME_MASK, G(";"), NULL);
	if (loc != NULL) {
		test_failed(t, "expected NULL newlocale return");
	}
	CHECK_ERRNO(EINVAL);
	/* don't get trapped by consecutive semicolons */
	loc = newlocale(LC_TIME_MASK, G(";;;;"), NULL);
	if (loc != NULL) {
		test_failed(t, "expected NULL newlocale return");
	}
	CHECK_ERRNO(EINVAL);
	/* too-short category names */
	loc = newlocale(LC_TIME_MASK, G("LC;LC_TIM"), NULL);
	if (loc != NULL) {
		test_failed(t, "expected NULL newlocale return");
	}
	CHECK_ERRNO(EINVAL);
	/* wrong category names */
	loc = newlocale(LC_TIME_MASK, G("LC_DATE=C;LC_CTYPE=C"), NULL);
	if (loc != NULL) {
		test_failed(t, "expected NULL newlocale return");
	}
	CHECK_ERRNO(EINVAL);
	/* one present, one absent */
	loc = newlocale(LC_TIME_MASK | LC_MONETARY_MASK,
	    G("LC_TIME=C;LC_CTYPE=C"), NULL);
	if (loc != NULL) {
		test_failed(t, "expected NULL newlocale return");
	}
	CHECK_ERRNO(EINVAL);
	/* '=' not where expected */
	loc = newlocale(LC_TIME_MASK, G("LC_TIME!=C;"), NULL);
	if (loc != NULL) {
		test_failed(t, "expected NULL newlocale return");
	}
	CHECK_ERRNO(EINVAL);
	/* confirm we don't fall back to LANG= here */
	loc = newlocale(LC_TIME_MASK, G(";LANG=en_US.UTF-8"), NULL);
	if (loc != NULL) {
		test_failed(t, "expected NULL newlocale return");
	}
	CHECK_ERRNO(EINVAL);
	/* too-long value */
	loc = newlocale(LC_TIME_MASK,
	    G(";LC_TIME=supercalifragilisticexpialadocious"), NULL);
	if (loc != NULL) {
		test_failed(t, "expected NULL newlocale return");
	}
	CHECK_ERRNO(ENOENT);

	test_passed(t);
}

int
main(int argc, char **argv)
{
	int optc;

	while ((optc = getopt(argc, argv, "Ddf")) != EOF) {
		switch (optc) {
		case 'd':
			test_set_debug();
			break;
		case 'f':
			test_set_force();
			break;
		case 'D':
			test_set_debug();
			extra_debug++;
			break;
		default:
			(void) fprintf(stderr, "Usage: %s [-df]\n", argv[0]);
			exit(1);
		}
	}

	test_newlocale_threaded();
	test_newlocale_negative();
	test_newlocale_categories();
	test_newlocale_composite();
	test_newlocale_composite_glibc();
	test_newlocale_all_categories();
	test_newlocale_environment();
	test_newlocale_parser_coverage();

	exit(0);
}
