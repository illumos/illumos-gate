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
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2017 Nexenta Systems, Inc.
 */

/*
 * LC_TIME database generation routines for localedef.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include "localedef.h"
#include "parser.tab.h"
#include "timelocal.h"

struct lc_time tm;

void
init_time(void)
{
	(void) memset(&tm, 0, sizeof (tm));
}

void
add_time_str(wchar_t *wcs)
{
	char	*str;

	if ((str = to_mb_string(wcs)) == NULL) {
		INTERR;
		return;
	}
	free(wcs);

	switch (last_kw) {
	case T_D_T_FMT:
		tm.c_fmt = str;
		break;
	case T_D_FMT:
		tm.x_fmt = str;
		break;
	case T_T_FMT:
		tm.X_fmt = str;
		break;
	case T_T_FMT_AMPM:
		tm.ampm_fmt = str;
		break;
	case T_DATE_FMT:
		/*
		 * This one is a Solaris extension. Too bad date just
		 * doesn't use %c, which would be simpler.
		 */
		tm.date_fmt = str;
		break;
	case T_ERA_D_FMT:
	case T_ERA_T_FMT:
	case T_ERA_D_T_FMT:
		/* Silently ignore it. */
		free(str);
		break;
	default:
		free(str);
		INTERR;
		break;
	}
}

static void
add_list(const char *ptr[], char *str, int limit)
{
	int	i;
	for (i = 0; i < limit; i++) {
		if (ptr[i] == NULL) {
			ptr[i] = str;
			return;
		}
	}
	errf(_("too many list elements"));
}

void
add_time_list(wchar_t *wcs)
{
	char *str;

	if ((str = to_mb_string(wcs)) == NULL) {
		INTERR;
		return;
	}
	free(wcs);

	switch (last_kw) {
	case T_ABMON:
		add_list(tm.mon, str, 12);
		break;
	case T_MON:
		add_list(tm.month, str, 12);
		break;
	case T_ABDAY:
		add_list(tm.wday, str, 7);
		break;
	case T_DAY:
		add_list(tm.weekday, str, 7);
		break;
	case T_AM_PM:
		if (tm.am == NULL) {
			tm.am = str;
		} else if (tm.pm == NULL) {
			tm.pm = str;
		} else {
			errf(_("too many list elements"));
			free(str);
		}
		break;
	case T_ALT_DIGITS:
	case T_ERA:
		free(str);
		break;
	default:
		free(str);
		INTERR;
		break;
	}
}

void
check_time_list(void)
{
	switch (last_kw) {
	case T_ABMON:
		if (tm.mon[11] != NULL)
			return;
		break;
	case T_MON:
		if (tm.month[11] != NULL)
			return;
		break;
	case T_ABDAY:
		if (tm.wday[6] != NULL)
			return;
		break;
	case T_DAY:
		if (tm.weekday[6] != NULL)
			return;
		break;
	case T_AM_PM:
		if (tm.pm != NULL)
			return;
		break;
	case T_ERA:
	case T_ALT_DIGITS:
		return;
	default:
		errf(_("unknown list"));
		break;
	}

	errf(_("too few items in list (%d)"), last_kw);
}

void
reset_time_list(void)
{
	int i;
	switch (last_kw) {
	case T_ABMON:
		for (i = 0; i < 12; i++) {
			free((char *)tm.mon[i]);
			tm.mon[i] = NULL;
		}
		break;
	case T_MON:
		for (i = 0; i < 12; i++) {
			free((char *)tm.month[i]);
			tm.month[i] = NULL;
		}
		break;
	case T_ABDAY:
		for (i = 0; i < 7; i++) {
			free((char *)tm.wday[i]);
			tm.wday[i] = NULL;
		}
		break;
	case T_DAY:
		for (i = 0; i < 7; i++) {
			free((char *)tm.weekday[i]);
			tm.weekday[i] = NULL;
		}
		break;
	case T_AM_PM:
		free((char *)tm.am);
		tm.am = NULL;
		free((char *)tm.pm);
		tm.pm = NULL;
		break;
	}
}


void
dump_time(void)
{
	FILE *f;
	int i;

	if ((f = open_category()) == NULL) {
		return;
	}

	for (i = 0; i < 12; i++) {
		if (putl_category(tm.mon[i], f) == EOF) {
			return;
		}
	}
	for (i = 0; i < 12; i++) {
		if (putl_category(tm.month[i], f) == EOF) {
			return;
		}
	}
	for (i = 0; i < 7; i++) {
		if (putl_category(tm.wday[i], f) == EOF) {
			return;
		}
	}
	for (i = 0; i < 7; i++) {
		if (putl_category(tm.weekday[i], f) == EOF) {
			return;
		}
	}

	/*
	 * NOTE: If date_fmt is not specified, then we'll default to
	 * using the %c for date.  This is reasonable for most
	 * locales, although for reasons that I don't understand
	 * Solaris historically has had a separate format for date.
	 */
	if ((putl_category(tm.X_fmt, f) == EOF) ||
	    (putl_category(tm.x_fmt, f) == EOF) ||
	    (putl_category(tm.c_fmt, f) == EOF) ||
	    (putl_category(tm.am, f) == EOF) ||
	    (putl_category(tm.pm, f) == EOF) ||
	    (putl_category(tm.date_fmt ? tm.date_fmt : tm.c_fmt, f) == EOF) ||
	    (putl_category(tm.ampm_fmt, f) == EOF)) {
		return;
	}
	close_category(f);
}
