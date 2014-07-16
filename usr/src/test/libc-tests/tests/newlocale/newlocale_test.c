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
	{ "ru_RU.UTF-8", "воскресенье", "руб." },
	{ "ja_JP.UTF-8", "日曜日", "￥" },
};

#define	NUM_LDATA	5
#define	NUMTHR	20
#define	NUMITR	200

int extra_debug = 0;

void
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


void
test_newlocale_threaded(void)
{
	test_run(NUMTHR, testlocale_thr_one, NULL, "newlocale_threaded");
}

void
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

void
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

void
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

	exit(0);
}
