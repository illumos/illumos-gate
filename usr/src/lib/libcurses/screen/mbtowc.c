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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*  Copyright (c) 1988 AT&T */
/*    All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <widec.h>
#include <ctype.h>
#include <sys/types.h>
#include "curses_wchar.h"

int
_curs_mbtowc(wchar_t *wchar, const char *s, size_t n)
{
	int length, c;
	wchar_t intcode;
	char *olds = (char *)s;
	wchar_t mask;

	if (s == (char *)0)
		return (0);
	if (n == 0)
		return (-1);
	c = (unsigned char)*s++;
	if (c < 0200) {
		if (wchar)
			*wchar = c;
		return (c ? 1 : 0);
	}
	intcode = 0;
	if (c == SS2) {
		if ((length = eucw2) == 0)
			goto lab1;
		mask = P01;
		goto lab2;
	} else if (c == SS3) {
		if ((length = eucw3) == 0)
			goto lab1;
		mask = P10;
		goto lab2;
	}
lab1:
	if (iscntrl(c)) {
		if (wchar)
			*wchar = c;
		return (1);
	}
	length = eucw1 - 1;
	mask = P11;
	intcode = c & 0177;
lab2:
	if (length + 1 > n || length < 0)
		return (-1);
	while (length--) {
		if ((c = (unsigned char)*s++) < 0200 || iscntrl(c))
			return (-1);
		intcode = (intcode << 7) | (c & 0x7F);
	}
	if (wchar)
		*wchar = intcode | mask;
	/*LINTED*/
	return ((int)(s - olds));
}
