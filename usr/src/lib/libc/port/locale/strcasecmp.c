/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include "lint.h"
#include <sys/types.h>
#include <strings.h>
#include <ctype.h>
#include <locale.h>
#include "localeimpl.h"
#include "lctype.h"

int
strcasecmp_l(const char *s1, const char *s2, locale_t loc)
{
	extern int ascii_strcasecmp(const char *s1, const char *s2);
	const int *cm;
	const uchar_t *us1;
	const uchar_t *us2;
	const struct lc_ctype *lct = loc->ctype;

	/*
	 * If we are in a locale that uses the ASCII character set
	 * (C or POSIX), use the fast ascii_strcasecmp() function.
	 */
	if (lct->lc_is_ascii)
		return (ascii_strcasecmp(s1, s2));

	cm = lct->lc_trans_lower;
	us1 = (const uchar_t *)s1;
	us2 = (const uchar_t *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return (0);
	return (cm[*us1] - cm[*(us2 - 1)]);
}

int
strcasecmp(const char *s1, const char *s2)
{
	/* would be nice to avoid uselocale()... but I don't see how */
	return (strcasecmp_l(s1, s2, uselocale(NULL)));
}
