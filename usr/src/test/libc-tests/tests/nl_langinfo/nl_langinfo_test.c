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
#include <errno.h>
#include <unistd.h>
#include "test_common.h"

/*
 * Note that on some platforms, different symbols are used.  For example,
 * MacOS Mavericks uses "Eu" for Euro symbol, instead of €.  If the locale
 * data changes, then this program will need to update to reflect that.
 *
 * Note also that this file is easiest edited with a UTF-8 capable editor,
 * as there are embedded UTF-8 symbols in some of the strings.
 */
struct langinfo_test {
	nl_item		param;
	const char	*value;
};

struct langinfo_test C_data[] = {
	{ CODESET,	"646" },
	{ D_T_FMT,	"%a %b %e %H:%M:%S %Y" },
	{ D_FMT,	"%m/%d/%y" },
	{ T_FMT,	"%H:%M:%S" },
	{ T_FMT_AMPM,	"%I:%M:%S %p" },
	{ AM_STR,	"AM" },
	{ PM_STR,	"PM" },
	{ ERA,		"" },
	{ ERA_D_FMT,	"" },
	{ ERA_D_T_FMT,	"" },
	{ ERA_T_FMT,	"" },
	{ DAY_1,	"Sunday" },
	{ DAY_7,	"Saturday" },
	{ ABDAY_1,	"Sun" },
	{ ABDAY_7,	"Sat" },
	{ MON_1,	"January" },
	{ MON_12,	"December" },
	{ ABMON_1,	"Jan" },
	{ ABMON_12,	"Dec" },
	{ RADIXCHAR,	"." },
	{ THOUSEP,	"" },
	{ YESSTR,	"yes" },
	{ NOSTR,	"no" },
	{ YESEXPR,	"^[yY]" },
	{ NOEXPR,	"^[nN]" },
	{ CRNCYSTR,	"" },
	{ -1,		NULL }
};

struct langinfo_test en_us_utf8_data[] = {
	{ CODESET,	"UTF-8" },
	{ D_T_FMT,	"%B %e, %Y %I:%M:%S %p %Z" },
	{ D_FMT,	"%m/%e/%y" },
	{ T_FMT,	"%I:%M:%S %p" },
	{ T_FMT_AMPM,	"%I:%M:%S %p" },
	{ AM_STR,	"AM" },
	{ PM_STR,	"PM" },
	{ ERA,		"" },
	{ ERA_D_FMT,	"" },
	{ ERA_D_T_FMT,	"" },
	{ ERA_T_FMT,	"" },
	{ DAY_1,	"Sunday" },
	{ DAY_7,	"Saturday" },
	{ ABDAY_1,	"Sun" },
	{ ABDAY_7,	"Sat" },
	{ MON_1,	"January" },
	{ MON_12,	"December" },
	{ ABMON_1,	"Jan" },
	{ ABMON_12,	"Dec" },
	{ RADIXCHAR,	"." },
	{ THOUSEP,	"," },
	{ YESSTR,	"yes" },
	{ NOSTR,	"no" },
	{ YESEXPR,	"^(([yY]([eE][sS])?))" },
	{ NOEXPR,	"^(([nN]([oO])?))" },
	{ CRNCYSTR,	"-$" },
	{ -1,		NULL }
};

struct langinfo_test en_gb_latin15_data[] = {
	{ CODESET,	"ISO8859-15" },
	{ D_T_FMT,	"%e %B %Y %H:%M:%S %Z" },
	{ D_FMT,	"%d/%m/%Y" },
	{ T_FMT,	"%H:%M:%S" },
	{ T_FMT_AMPM,	"%I:%M:%S %p" },
	{ AM_STR,	"AM" },
	{ PM_STR,	"PM" },
	{ ERA,		"" },
	{ ERA_D_FMT,	"" },
	{ ERA_D_T_FMT,	"" },
	{ ERA_T_FMT,	"" },
	{ DAY_1,	"Sunday" },
	{ DAY_7,	"Saturday" },
	{ ABDAY_1,	"Sun" },
	{ ABDAY_7,	"Sat" },
	{ MON_1,	"January" },
	{ MON_12,	"December" },
	{ ABMON_1,	"Jan" },
	{ ABMON_12,	"Dec" },
	{ RADIXCHAR,	"." },
	{ THOUSEP,	"," },
	{ YESSTR,	"yes" },
	{ NOSTR,	"no" },
	{ YESEXPR,	"^(([yY]([eE][sS])?))" },
	{ NOEXPR,	"^(([nN]([oO])?))" },
	{ CRNCYSTR,	"-\243" },
	{ -1,		NULL }
};

struct langinfo_test ru_ru_utf8_data[] = {
	{ CODESET,	"UTF-8" },
	{ D_T_FMT,	"%e %B %Y г. %H:%M:%S %Z"},
	{ D_FMT,	"%d.%m.%y" },
	{ T_FMT,	"%H:%M:%S" },
	{ T_FMT_AMPM,	"%I:%M:%S %p" },
	{ AM_STR,	"до полудня" },
	{ PM_STR,	"после полудня" },
	{ ERA,		"" },
	{ ERA_D_FMT,	"" },
	{ ERA_D_T_FMT,	"" },
	{ ERA_T_FMT,	"" },
	{ DAY_1,	"воскресенье" },
	{ DAY_7,	"суббота" },
	{ ABDAY_1,	"вс" },
	{ ABDAY_7,	"сб" },
	{ MON_1,	"января" },
	{ MON_12,	"декабря" },
	{ ABMON_1,	"янв" },
	{ ABMON_12,	"дек" },
	{ RADIXCHAR,	"," },
	{ THOUSEP,	" " },
	{ YESSTR,	"да" },
	{ NOSTR,	"нет" },
	{ YESEXPR,	"^(([дД]([аА])?)|([yY]([eE][sS])?))" },
	{ NOEXPR,	"^(([нН]([еЕ][тТ])?)|([nN]([oO])?))" },
	{ CRNCYSTR,	"+руб." },
	{ -1,		NULL }
};

struct {
	const char *locale;
	struct langinfo_test *loctest;
} locales[] =  {
	{ "C",			C_data },
	{ "en_US.UTF-8",	en_us_utf8_data },
	{ "en_GB.ISO8859-15",	en_gb_latin15_data },
	{ "ru_RU.UTF-8",	ru_ru_utf8_data },
	{ NULL, 		NULL }
};

void
test_nl_langinfo_1(const char *locale, struct langinfo_test *test)
{
	char 	tname[128];
	char 	*v;
	test_t	t;

	(void) snprintf(tname, sizeof (tname), "nl_langinfo (locale %s)",
	    locale);
	t = test_start(tname);

	v = setlocale(LC_ALL, locale);
	if (v == NULL) {
		test_failed(t, "setlocale failed: %s", strerror(errno));
	}
	if (strcmp(v, locale) != 0) {
		test_failed(t, "setlocale got %s instead of %s", v, locale);
	}

	for (int i = 0; test[i].value != NULL; i++) {
		v = nl_langinfo(test[i].param);
		test_debugf(t, "%d: expect [%s], got [%s]",
		    test[i].param, test[i].value, v);
		if (strcmp(v, test[i].value) != 0) {
			test_failed(t,
			    "param %d wrong, expected [%s], got [%s]",
			    test[i].param, test[i].value, v);
		}
	}
	test_passed(t);
}

void
test_nl_langinfo_l(const char *locale, struct langinfo_test *test)
{
	char 		tname[128];
	char 		*v;
	test_t		t;
	locale_t	loc;

	(void) snprintf(tname, sizeof (tname), "nl_langinfo_l (locale %s)",
	    locale);
	t = test_start(tname);

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

	for (int i = 0; test[i].value != NULL; i++) {
		v = nl_langinfo_l(test[i].param, loc);
		test_debugf(t, "%d: expect [%s], got [%s]",
		    test[i].param, test[i].value, v);
		if (strcmp(v, test[i].value) != 0) {
			test_failed(t,
			    "param %d wrong, expected [%s], got [%s]",
			    test[i].param, test[i].value, v);
		}
	}
	test_passed(t);
}
void
test_nl_langinfo(void)
{
	for (int i = 0; locales[i].locale != NULL; i++) {
		test_nl_langinfo_1(locales[i].locale, locales[i].loctest);
		test_nl_langinfo_l(locales[i].locale, locales[i].loctest);
	}
}

int
main(int argc, char **argv)
{
	int optc;

	while ((optc = getopt(argc, argv, "df")) != EOF) {
		switch (optc) {
		case 'd':
			test_set_debug();
			break;
		case 'f':
			test_set_force();
			break;
		default:
			(void) fprintf(stderr, "Usage: %s [-df]\n", argv[0]);
			exit(1);
		}
	}

	test_nl_langinfo();

	exit(0);
}
