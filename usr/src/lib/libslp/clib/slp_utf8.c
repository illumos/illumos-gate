/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * UTF-8 encoded Unicode parsing routines. For efficiency, we convert
 * to wide chars only when absolutely needed. The following interfaces
 * are exported to libslp:
 *
 * slp_utf_strchr:	same semantics as strchr, but handles UTF-8 strings
 * slp_fold_space:	folds white space around and in between works;
 *				handles UTF-8 strings
 * slp_strcasecmp:	same semantics as strcasecmp, but also folds white
 *				space and attempts locale-specific
 *				case-insensitive comparisons.
 */

#include <stdio.h>
#include <string.h>
#include <widec.h>
#include <stdlib.h>
#include <syslog.h>
#include <slp-internal.h>

/*
 * Same semantics as strchr.
 * Assumes that we start on a char boundry, and that c is a 7-bit
 * ASCII char.
 */
char *slp_utf_strchr(const char *s, char c) {
	int len;
	char *p;

	for (p = (char *)s; *p; p += len) {
		len = mblen(p, MB_CUR_MAX);
		if (len == 1 && *p == c)
			return (p);
	}
	return (NULL);
}

/*
 * folds white space around and in between words.
 * " aa    bb   " becomes "aa bb".
 * returns NULL if it couldn't allocate memory. The caller must free
 * the result when done.
 */
static char *slp_fold_space(const char *s) {
	int len;
	char *folded, *f;

	if (!(folded = malloc(strlen(s) + 1))) {
		slp_err(LOG_CRIT, 0, "slp_fold_space", "out of memory");
		return (NULL);
	}

	f = folded;
	for (;;) {
		/* step 1: skip white space */
		for (; *s; s++) {
			len = mblen(s, MB_CUR_MAX);
			if (len != 1)
				break;
			if (!isspace(*s))
				break;
		}

		if (!*s) {
			/* end of string */
			*f = 0;
			return (folded);
		}
		/* if we are in between words, keep one space */
		if (f != folded)
			*f++ = ' ';

		/* step 2: copy into folded until we hit more white space */
		while (*s) {
			int i;
			len = mblen(s, MB_CUR_MAX);
			if (len == 1 && isspace(*s))
				break;

			for (i = 0; i < len; i++)
				*f++ = *s++;
		}
		*f = *s;
		if (!*s++)
			return (folded);
	}
}

/*
 * performs like strcasecmp, but also folds white space before comparing,
 * and will handle UTF-8 comparisons (including case). Note that the
 * application's locale must have been set to a UTF-8 locale for this
 * to work properly.
 */
int slp_strcasecmp(const char *s1, const char *s2) {
	int diff = -1;
	char *p1, *p2;
	size_t wcslen1, wcslen2;
	wchar_t *wcs1, *wcs2;

	p1 = p2 = NULL; wcs1 = wcs2 = NULL;

	/* optimization: try simple case first */
	if (strcasecmp(s1, s2) == 0)
		return (0);

	/* fold white space, and try again */
	p1 = slp_fold_space(s1);
	p2 = slp_fold_space(s2);
	if (!p1 || !p2)
		goto cleanup;

	if ((diff = strcasecmp(p1, p2)) == 0)
		goto cleanup;

	/*
	 * try converting to wide char -- we must be in a locale which
	 * supports the UTF8 codeset for this to work.
	 */
	if ((wcslen1 = mbstowcs(NULL, p1, 0)) == (size_t)-1)
		goto cleanup;

	if (!(wcs1 = malloc(sizeof (*wcs1) * (wcslen1 + 1)))) {
		slp_err(LOG_CRIT, 0, "slp_strcasecmp", "out of memory");
		goto cleanup;
	}

	if ((wcslen2 = mbstowcs(NULL, p2, 0)) == (size_t)-1)
		goto cleanup;

	if (!(wcs2 = malloc(sizeof (*wcs2) * (wcslen2 + 1)))) {
		slp_err(LOG_CRIT, 0, "slp_strcasecmp", "out of memory");
		goto cleanup;
	}
	if (mbstowcs(wcs1, p1, wcslen1 + 1) == (size_t)-1)
		goto cleanup;
	if (mbstowcs(wcs2, p2, wcslen2 + 1) == (size_t)-1)
		goto cleanup;

	diff = wscasecmp(wcs1, wcs2);

cleanup:
	if (p1) free(p1);
	if (p2) free(p2);
	if (wcs1) free(wcs1);
	if (wcs2) free(wcs2);
	return (diff);
}
