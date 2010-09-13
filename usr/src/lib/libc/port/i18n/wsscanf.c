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

#include  "lint.h"
#include "file64.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <widec.h>
#include <string.h>
#include "libc.h"
#include "stdiom.h"

/*
 * 	wsscanf -- this function will read wchar_t characters from
 *		    wchar_t string according to the conversion format.
 *		    Note that the performance degrades if the intermediate
 *		    result of conversion exceeds 1024 bytes due to the
 *		    use of malloc() on each call.
 *		    We should implement wchar_t version of doscan()
 *		    for better performance.
 */
#define	MAXINSTR	1024

int
wsscanf(wchar_t *string, const char *format, ...)
{
	va_list		ap;
	size_t		i;
	char		stackbuf[MAXINSTR];
	char		*tempstring = stackbuf;
	size_t		malloced = 0;
	int		j;

	i = wcstombs(tempstring, string, MAXINSTR);
	if (i == (size_t)-1)
		return (-1);

	if (i == MAXINSTR) { /* The buffer was too small.  Malloc it. */
		tempstring = malloc(malloced = MB_CUR_MAX*wcslen(string)+1);
		if (tempstring == 0)
			return (-1);
		i = wcstombs(tempstring, string, malloced); /* Try again. */
		if (i == (size_t)-1) {
			free(tempstring);
			return (-1);
		}
	}

	va_start(ap, format);
	j = vsscanf(tempstring, format, ap);
	va_end(ap);
	if (malloced) free(tempstring);
	return (j);
}
