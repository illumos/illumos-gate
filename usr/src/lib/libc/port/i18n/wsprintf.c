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

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <widec.h>
#include <string.h>
#include <limits.h>

/*
 * 	wsprintf -- this function will output a wchar_t string
 *		    according to the conversion format.
 *		    Note that the maximum length of the output
 *		    string is 1024 bytes.
 */

/*VARARGS2*/
int
wsprintf(wchar_t *wstring, const char *format, ...)
{
	va_list	ap;
	char	tempstring[1024];
	char *p2;
	size_t len;
	int malloced = 0;
	char *p1 = (char *)wstring;
	int retcode;
	int	i;

	va_start(ap, format);
	if (vsprintf(p1, format, ap) == -1) {
		va_end(ap);
		return (-1);
	}
	va_end(ap);
	len = strlen(p1) + 1;
	if (len > 1024) {
		p2 = malloc(len);
		if (p2 == NULL)
			return (-1);
		malloced = 1;
	} else
		p2 = tempstring;
	(void) strcpy(p2, p1);

	if (mbstowcs(wstring, p2, len) == (size_t)-1) {
		for (i = 0; i < len; i++) {
			if ((retcode = mbtowc(wstring, p2, MB_CUR_MAX)) == -1) {
				*wstring = (wchar_t)*p2 & 0xff;
				p2++;
			} else {
				p2 += retcode;
			}
			if (*wstring++ == (wchar_t)0) {
				break;
			}
		}
	}

	if (malloced == 1)
		free(p2);
	len = wcslen(wstring);
	if (len <= INT_MAX)
		return ((int)len);
	else
		return (EOF);
}
