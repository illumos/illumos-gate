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
 * LC_NUMERIC database generation routines for localedef.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include "localedef.h"
#include "parser.tab.h"
#include "lnumeric.h"

static struct lc_numeric numeric;

void
init_numeric(void)
{
	(void) memset(&numeric, 0, sizeof (numeric));
}

void
add_numeric_str(wchar_t *wcs)
{
	char *str;

	if ((str = to_mb_string(wcs)) == NULL) {
		INTERR;
		return;
	}
	free(wcs);

	switch (last_kw) {
	case T_DECIMAL_POINT:
		numeric.decimal_point = str;
		break;
	case T_THOUSANDS_SEP:
		numeric.thousands_sep = str;
		break;
	default:
		free(str);
		INTERR;
		break;
	}
}

void
reset_numeric_group(void)
{
	free((char *)numeric.grouping);
	numeric.grouping = NULL;
}

void
add_numeric_group(int n)
{
	char *s;

	if (numeric.grouping == NULL) {
		(void) asprintf(&s, "%d", n);
	} else {
		(void) asprintf(&s, "%s;%d", numeric.grouping, n);
	}
	if (s == NULL)
		errf(_("out of memory"));

	free((char *)numeric.grouping);
	numeric.grouping = s;
}

void
dump_numeric(void)
{
	FILE *f;

	if ((f = open_category()) == NULL) {
		return;
	}

	if ((putl_category(numeric.decimal_point, f) == EOF) ||
	    (putl_category(numeric.thousands_sep, f) == EOF) ||
	    (putl_category(numeric.grouping, f) == EOF)) {
		return;
	}
	close_category(f);
}
