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
 * This program tests that wcsrtombs and friends work properly.
 * In order for it to work, it requires that some additional locales
 * be installed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <wchar.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <xlocale.h>
#include <note.h>
#include "test_common.h"

int extra_debug = 0;

#define	NUMTHR	300
#define	NUMITR	300

/*
 * Note that this file is easiest edited with a UTF-8 capable editor,
 * as there are embedded UTF-8 symbols in some of the strings.
 */
struct wcsrtombs_test {
	char		mbs[32];
	wchar_t		wcs[32];
};

#define	TESTING_MBS	"TESTING"
#define	TESTING_WCS 	{ 'T', 'E', 'S', 'T', 'I', 'N', 'G', 0 }
#define	HELLO_RU_MBS	"ПРИВЕТ"
#define	HELLO_RU_WCS	{ 1055, 1056, 1048, 1042, 1045, 1058, 0 }
#define	HELLO_EN_MBS	"HELLO"
#define	HELLO_EN_WCS	{ 'H', 'E', 'L', 'L', 'O', 0 }

/* Unicode values never have the high order bit set */
#define	BAD_WCS		{ 'B', 'A', 'D', (wchar_t)0xf000f000, 'W', 'C', 'S' }

struct wcsrtombs_test C_data[] = {
	{ TESTING_MBS,	TESTING_WCS },
	{ HELLO_EN_MBS,	HELLO_EN_WCS },
	{ 0, 0 },
};

struct wcsrtombs_test utf8_data[] = {
	{ TESTING_MBS,	TESTING_WCS },
	{ HELLO_EN_MBS,	HELLO_EN_WCS },
	{ HELLO_RU_MBS,	HELLO_RU_WCS },
	{ 0, 0 },
};

struct {
	const char *locale;
	struct wcsrtombs_test *test;
} locales[] =  {
	{ "C",			C_data },
	{ "en_US.UTF-8",	utf8_data },
	{ NULL, 		NULL }
};

void
test_wcsrtombs_1(const char *locale, struct wcsrtombs_test *test)
{
	test_t		t;
	char 		*v;
	mbstate_t	ms;

	t = test_start("wcsrtombs (locale %s)", locale);

	v = setlocale(LC_ALL, locale);
	if (v == NULL) {
		test_failed(t, "setlocale failed: %s", strerror(errno));
	}
	if (strcmp(v, locale) != 0) {
		test_failed(t, "setlocale got %s instead of %s", v, locale);
	}

	for (int i = 0; test[i].mbs[0] != 0; i++) {
		char mbs[32];
		const wchar_t *wcs = test[i].wcs;
		size_t cnt;

		(void) memset(&ms, 0, sizeof (ms));
		(void) memset(mbs, 0, sizeof (mbs));
		cnt = wcsrtombs(mbs, &wcs, sizeof (mbs), &ms);
		if (cnt != strlen(test[i].mbs)) {
			test_failed(t, "incorrect return value: %d != %d",
			    cnt, strlen(test[i].mbs));
		}
		if (strcmp(mbs, test[i].mbs) != 0) {
			test_failed(t, "wrong result: %s != %s",
			    mbs, test[i].mbs);
		}
		if (extra_debug) {
			test_debugf(t, "mbs is %s", mbs);
		}
	}
	test_passed(t);
}

void
test_wcsrtombs_l(const char *locale, struct wcsrtombs_test *test)
{
	test_t	t;
	locale_t loc;
	char 	*v;
	mbstate_t	ms;

	t = test_start("wcsrtombs_l (locale %s)", locale);

	v = setlocale(LC_ALL, "C");
	if (v == NULL) {
		test_failed(t, "setlocale failed: %s", strerror(errno));
	}
	if (strcmp(v, "C") != 0) {
		test_failed(t, "setlocale got %s instead of %s", v, "C");
	}

	loc = newlocale(LC_ALL_MASK, locale, NULL);
	if (loc == NULL) {
		test_failed(t, "newlocale failed: %s", strerror(errno));
	}

	for (int i = 0; test[i].mbs[0] != 0; i++) {
		char mbs[32];
		const wchar_t *wcs = test[i].wcs;
		size_t cnt;

		(void) memset(&ms, 0, sizeof (ms));
		(void) memset(mbs, 0, sizeof (mbs));
		cnt = wcsrtombs_l(mbs, &wcs, sizeof (mbs), &ms, loc);
		if (cnt != strlen(test[i].mbs)) {
			test_failed(t, "incorrect return value: %d != %d",
			    cnt, strlen(test[i].mbs));
		}
		if (strcmp(mbs, test[i].mbs) != 0) {
			test_failed(t, "wrong result: %s != %s", mbs,
			    test[i].mbs);
		}
		if (extra_debug) {
			test_debugf(t, "mbs is %s", mbs);
		}
	}
	test_passed(t);
}

void
test_wcsrtombs_thr_iter(test_t t, const char *locale,
    struct wcsrtombs_test *test)
{
	locale_t loc;
	mbstate_t	ms;

	loc = newlocale(LC_ALL_MASK, locale, NULL);
	if (loc == NULL) {
		test_failed(t, "newlocale failed: %s", strerror(errno));
	}

	for (int i = 0; test[i].mbs[0] != 0; i++) {
		char mbs[32];
		const wchar_t *wcs = test[i].wcs;
		size_t cnt;

		(void) memset(&ms, 0, sizeof (ms));
		(void) memset(mbs, 0, sizeof (mbs));
		cnt = wcsrtombs_l(mbs, &wcs, sizeof (mbs), &ms, loc);
		if (cnt != strlen(test[i].mbs)) {
			test_failed(t, "incorrect return value: %d != %d",
			    cnt, strlen(test[i].mbs));
		}
		if (strcmp(mbs, test[i].mbs) != 0) {
			test_failed(t, "wrong result: %s != %s", mbs,
			    test[i].mbs);
		}
		if (extra_debug) {
			test_debugf(t, "mbs is %s", mbs);
		}
	}

	freelocale(loc);
}

void
test_wcsrtombs_thr_work(test_t t, void *arg)
{
	_NOTE(ARGUNUSED(arg));
	for (int j = 0; j < NUMITR; j++) {
		test_debugf(t, "iteration %d", j);
		for (int i = 0; locales[i].locale != NULL; i++) {
			test_wcsrtombs_thr_iter(t, locales[i].locale,
			    locales[i].test);
		}
	}
	test_passed(t);
}

void
test_wcsrtombs_threaded(void)
{
	(void) setlocale(LC_ALL, "C");
	test_run(NUMTHR, test_wcsrtombs_thr_work, NULL, "wcsrtombs_threaded");
}

void
test_wcsrtombs_partial(void)
{
	test_t		t;
	mbstate_t	ms;
	wchar_t		src[32] = HELLO_RU_WCS;
	char		mbs[32];
	char		*dst;
	const wchar_t	*wcs;
	size_t 		cnt;


	(void) memset(&ms, 0, sizeof (ms));
	t = test_start("wcsrtombs_partial");

	if (setlocale(LC_ALL, "ru_RU.UTF-8") == NULL) {
		test_failed(t, "setlocale failed: %s", strerror(errno));
	}

	wcs = src;
	dst = mbs;
	cnt = wcsrtombs(dst, &wcs, 1, &ms);
	if (cnt != 0) {
		test_failed(t, "gave back a conversion cnt %d != 0", cnt);
	}
	if (wcs != src) {
		test_failed(t, "incorrectly advanced wcs");
	}

	cnt = wcsrtombs(dst, &wcs, 2, &ms);
	if (cnt != 2) {
		test_failed(t, "gave back a conversion cnt %d != 2", cnt);
	}
	dst += cnt;

	cnt = wcsrtombs(dst, &wcs, 4, &ms);
	dst += cnt;

	cnt = wcsrtombs(dst, &wcs, sizeof (mbs) - strlen(mbs), &ms);
	if (extra_debug) {
		test_debugf(t, "mbs is %s", mbs);
	}
	if (strcmp(mbs, HELLO_RU_MBS) != 0) {
		test_failed(t, "wrong result: %s != %s", mbs, HELLO_RU_MBS);
	}
	test_passed(t);
}

void
test_wcsrtombs_negative(void)
{
	mbstate_t	ms;
	const wchar_t	*wcs;
	char		mbs[32];
	char		*dst;
	int		e;
	wchar_t		src[32] = BAD_WCS;
	test_t		t;
	int		cnt;

	t = test_start("wcsrtombs_negative");

	(void) memset(&ms, 0, sizeof (ms));
	if (setlocale(LC_ALL, "ru_RU.UTF-8") == NULL) {
		test_failed(t, "setlocale failed: %s", strerror(errno));
	}

	wcs = src;
	dst = mbs;
	cnt = wcsrtombs(dst, &wcs, sizeof (mbs), &ms);
	if (cnt != -1) {
		test_failed(t, "bogus success (%d)", cnt);
	}
	if ((e = errno) != EILSEQ) {
		test_failed(t, "wrong errno, wanted %d (EILSEQ), got %d: %s",
		    EILSEQ, e, strerror(e));
	}
	test_passed(t);
}

void
test_wcsnrtombs_partial(void)
{
	test_t		t;
	mbstate_t	ms;
	wchar_t		src[32] = HELLO_RU_WCS;
	char		mbs[32];
	char		*dst;
	const wchar_t	*wcs;
	size_t 		cnt;


	(void) memset(&ms, 0, sizeof (ms));
	t = test_start("wcsrntombs_partial");

	if (setlocale(LC_ALL, "ru_RU.UTF-8") == NULL) {
		test_failed(t, "setlocale failed: %s", strerror(errno));
	}

	wcs = src;
	dst = mbs;
	cnt = wcsnrtombs(dst, &wcs, 1, 1, &ms);
	if (cnt != 0) {
		test_failed(t, "gave back a conversion cnt %d != 0", cnt);
	}
	if (wcs != src) {
		test_failed(t, "incorrectly advanced wcs");
	}

	/* we should get just 2 wide characters (expanding to 4 bytes) */
	cnt = wcsnrtombs(dst, &wcs, 2, sizeof (mbs), &ms);
	if (cnt != 4) {
		test_failed(t, "gave back a conversion cnt %d != 4", cnt);
	}
	dst += cnt;

	cnt = wcsnrtombs(dst, &wcs, 32, sizeof (mbs) - strlen(mbs), &ms);
	if (extra_debug) {
		test_debugf(t, "mbs is %s", mbs);
	}
	if (strcmp(mbs, HELLO_RU_MBS) != 0) {
		test_failed(t, "wrong result: %s != %s", mbs, HELLO_RU_MBS);
	}
	test_passed(t);
}

void
test_wcsrtombs(void)
{
	for (int i = 0; locales[i].locale != NULL; i++) {
		test_wcsrtombs_1(locales[i].locale, locales[i].test);
		test_wcsrtombs_l(locales[i].locale, locales[i].test);
	}
}

int
main(int argc, char **argv)
{
	int optc;

	while ((optc = getopt(argc, argv, "dfD")) != EOF) {
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
			(void) fprintf(stderr, "Usage: %s [-dfD]\n", argv[0]);
			exit(1);
		}
	}

	test_wcsrtombs();
	test_wcsrtombs_partial();
	test_wcsrtombs_negative();
	test_wcsrtombs_threaded();
	test_wcsnrtombs_partial();

	exit(0);
}
