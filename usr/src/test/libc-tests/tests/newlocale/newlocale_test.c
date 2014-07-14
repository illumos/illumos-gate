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

int debug = 0;

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

static void
test_start(const char *testName, const char *format, ...)
{
	va_list args;

	(void) printf("TEST STARTING %s: ", testName);

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);
	(void) fflush(stdout);
}

static void
test_failed(const char *testName, const char *format, ...)
{
	va_list args;

	(void) printf("TEST FAILED %s: ", testName);

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);

	(void) exit(-1);
}

static void
test_passed(const char *testName)
{
	(void) printf("TEST PASS: %s\n", testName);
	(void) fflush(stdout);
}

void *
testlocale_thr(void *ptr)
{
	locale_t	cloc, loc;
	struct lconv	*lc;
	char		*day;
	char		*tname = ptr;

	for (int i = 0; i < NUMITR; i++) {
		struct ldata *l = &ldata[i % NUM_LDATA];
		cloc = uselocale(NULL);

		loc = newlocale(LC_ALL_MASK, l->locale, NULL);
		if (loc == NULL) {
			test_failed("newlocale %s failed", l->locale);
		}
		day = nl_langinfo_l(DAY_1, loc);
		if (strcmp(day, l->day1) != 0) {
			test_failed(tname, "newlocale data mismatch (%s != %s)",
			    day, l->day1);
		}
		if (debug)
			(void) printf("DAY1: %s\n", day);

		day = nl_langinfo(DAY_1);
		if (strcmp(day, "Sunday") != 0) {
			test_failed(tname, "C locale day wrong %s != Sunday",
			    day);
		}
		lc = localeconv();
		if (strcmp(lc->currency_symbol, "") != 0) {
			test_failed(tname, "C cursym mismatch (%s != %s)",
			    lc->currency_symbol, "");
		}

		/* we sleep a random bit to mix it up */
		(void) usleep(rand() % 10);

		(void) uselocale(loc);
		day = nl_langinfo(DAY_1);
		if (strcmp(day, l->day1) != 0) {
			test_failed(tname, "uselocale data mismatch (%s != %s)",
			    day, l->day1);
		}

		lc = localeconv();
		if (strcmp(lc->currency_symbol, l->cursym) != 0) {
			test_failed(tname, "uselocal cursym %s != %s",
			    lc->currency_symbol, l->cursym);
		}
		if (debug)
			(void) printf("CSYM: %s\n", lc->currency_symbol);

		/* we sleep a random bit to mix it up */
		(void) usleep(rand() % 10);

		if (uselocale(cloc) != loc) {
			test_failed(tname, "revert old locale mismatch");
		}
		freelocale(loc);
		if (uselocale(LC_GLOBAL_LOCALE) != cloc) {
			test_failed(tname, "revert GLOBAL_LOCALE mismatch");
		}
	}
	return (NULL);
}


void
testlocale(void)
{
	char		*tname = "newlocale/uselocale";
	pthread_t	tid[NUMTHR];

	test_start(tname, "running %d threads %d iterations\n", NUMTHR, NUMITR);

	for (int i = 0; i < NUMTHR; i++) {
		(void) pthread_create(&tid[i], NULL, testlocale_thr, tname);
	}

	for (int i = 0; i < NUMTHR; i++) {
		(void) pthread_join(tid[i], NULL);
	}
	test_passed(tname);
}

int
main(int argc, char **argv)
{
	int optc;

	while ((optc = getopt(argc, argv, "d")) != EOF) {
		switch (optc) {
		case 'd':
			debug++;
			break;
		default:
			(void) fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
			exit(1);
		}
	}

	testlocale();

	exit(0);
}
