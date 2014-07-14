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
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * LC_MONETARY database generation routines for localedef.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include "localedef.h"
#include "parser.tab.h"
#include "lmonetary.h"

static struct lc_monetary mon;

void
init_monetary(void)
{
	(void) memset(&mon, 0, sizeof (mon));
}

void
add_monetary_str(wchar_t *wcs)
{
	char *str;

	if ((str = to_mb_string(wcs)) == NULL) {
		INTERR;
		return;
	}
	free(wcs);
	switch (last_kw) {
	case T_INT_CURR_SYMBOL:
		mon.int_curr_symbol = str;
		break;
	case T_CURRENCY_SYMBOL:
		mon.currency_symbol = str;
		break;
	case T_MON_DECIMAL_POINT:
		mon.mon_decimal_point = str;
		break;
	case T_MON_THOUSANDS_SEP:
		mon.mon_thousands_sep = str;
		break;
	case T_POSITIVE_SIGN:
		mon.positive_sign = str;
		break;
	case T_NEGATIVE_SIGN:
		mon.negative_sign = str;
		break;
	default:
		free(str);
		INTERR;
		break;
	}
}

void
add_monetary_num(int n)
{
	char *str = NULL;

	(void) asprintf(&str, "%d", n);
	if (str == NULL) {
		errf(_("out of memory"));
		return;
	}

	switch (last_kw) {
	case T_INT_FRAC_DIGITS:
		mon.int_frac_digits = str;
		break;
	case T_FRAC_DIGITS:
		mon.frac_digits = str;
		break;
	case T_P_CS_PRECEDES:
		mon.p_cs_precedes = str;
		break;
	case T_P_SEP_BY_SPACE:
		mon.p_sep_by_space = str;
		break;
	case T_N_CS_PRECEDES:
		mon.n_cs_precedes = str;
		break;
	case T_N_SEP_BY_SPACE:
		mon.n_sep_by_space = str;
		break;
	case T_P_SIGN_POSN:
		mon.p_sign_posn = str;
		break;
	case T_N_SIGN_POSN:
		mon.n_sign_posn = str;
		break;
	case T_INT_P_CS_PRECEDES:
		mon.int_p_cs_precedes = str;
		break;
	case T_INT_N_CS_PRECEDES:
		mon.int_n_cs_precedes = str;
		break;
	case T_INT_P_SEP_BY_SPACE:
		mon.int_p_sep_by_space = str;
		break;
	case T_INT_N_SEP_BY_SPACE:
		mon.int_n_sep_by_space = str;
		break;
	case T_INT_P_SIGN_POSN:
		mon.int_p_sign_posn = str;
		break;
	case T_INT_N_SIGN_POSN:
		mon.int_n_sign_posn = str;
		break;
	case T_MON_GROUPING:
		mon.mon_grouping = str;
		break;
	default:
		INTERR;
		break;
	}
}

void
reset_monetary_group(void)
{
	free((char *)mon.mon_grouping);
	mon.mon_grouping = NULL;
}

void
add_monetary_group(int n)
{
	char *s = NULL;

	if (mon.mon_grouping == NULL) {
		(void) asprintf(&s, "%d", n);
	} else {
		(void) asprintf(&s, "%s;%d", mon.mon_grouping, n);
	}
	if (s == NULL)
		errf(_("out of memory"));

	free((char *)mon.mon_grouping);
	mon.mon_grouping = s;
}

void
dump_monetary(void)
{
	FILE *f;

	if ((f = open_category()) == NULL) {
		return;
	}

	if ((putl_category(mon.int_curr_symbol, f) == EOF) ||
	    (putl_category(mon.currency_symbol, f) == EOF) ||
	    (putl_category(mon.mon_decimal_point, f) == EOF) ||
	    (putl_category(mon.mon_thousands_sep, f) == EOF) ||
	    (putl_category(mon.mon_grouping, f) == EOF) ||
	    (putl_category(mon.positive_sign, f) == EOF) ||
	    (putl_category(mon.negative_sign, f) == EOF) ||
	    (putl_category(mon.int_frac_digits, f) == EOF) ||
	    (putl_category(mon.frac_digits, f) == EOF) ||
	    (putl_category(mon.p_cs_precedes, f) == EOF) ||
	    (putl_category(mon.p_sep_by_space, f) == EOF) ||
	    (putl_category(mon.n_cs_precedes, f) == EOF) ||
	    (putl_category(mon.n_sep_by_space, f) == EOF) ||
	    (putl_category(mon.p_sign_posn, f) == EOF) ||
	    (putl_category(mon.n_sign_posn, f) == EOF) ||
	    (putl_category(mon.int_p_cs_precedes, f) == EOF) ||
	    (putl_category(mon.int_n_cs_precedes, f) == EOF) ||
	    (putl_category(mon.int_p_sep_by_space, f) == EOF) ||
	    (putl_category(mon.int_n_sep_by_space, f) == EOF) ||
	    (putl_category(mon.int_p_sign_posn, f) == EOF) ||
	    (putl_category(mon.int_n_sign_posn, f) == EOF)) {
		return;
	}
	close_category(f);
}
