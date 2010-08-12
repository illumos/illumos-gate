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

int
strncasecmp(const char *s1, const char *s2, size_t n)
{
	extern int charset_is_ascii;
	extern int ascii_strncasecmp(const char *s1, const char *s2, size_t n);
	int *cm;
	const uchar_t *us1;
	const uchar_t *us2;

	/*
	 * If we are in a locale that uses the ASCII character set
	 * (C or POSIX), use the fast ascii_strncasecmp() function.
	 */
	if (charset_is_ascii)
		return (ascii_strncasecmp(s1, s2, n));

	cm = __trans_lower;
	us1 = (const uchar_t *)s1;
	us2 = (const uchar_t *)s2;

	while (n != 0 && cm[*us1] == cm[*us2++]) {
		if (*us1++ == '\0')
			return (0);
		n--;
	}
	return (n == 0 ? 0 : cm[*us1] - cm[*(us2 - 1)]);
}
