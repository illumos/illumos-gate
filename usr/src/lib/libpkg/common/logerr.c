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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "pkglocale.h"

/*VARARGS*/
void
logerr(char *fmt, ...)
{
	va_list ap;
	char	*pt, buffer[2048];
	int	flag;
	char	*estr = pkg_gt("ERROR:");
	char	*wstr = pkg_gt("WARNING:");
	char	*nstr = pkg_gt("NOTE:");

	va_start(ap, fmt);
	flag = 0;
	/* This may have to use the i18n strcmp() routines. */
	if (strncmp(fmt, estr, strlen(estr)) &&
	    strncmp(fmt, wstr, strlen(wstr)) &&
	    strncmp(fmt, nstr, strlen(nstr))) {
		flag++;
		(void) fprintf(stderr, "    ");
	}
	/*
	 * NOTE: internationalization in next line REQUIRES that caller of
	 * this routine be in the same internationalization domain
	 * as this library.
	 */
	(void) vsprintf(buffer, fmt, ap);

	va_end(ap);

	for (pt = buffer; *pt; pt++) {
		(void) putc(*pt, stderr);
		if (flag && (*pt == '\n') && pt[1])
			(void) fprintf(stderr, "    ");
	}
	(void) putc('\n', stderr);
}
