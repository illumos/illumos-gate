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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <libintl.h>

void
err_fatal(char *s, ...)
{
	va_list		 ap;

	va_start(ap, s);
	(void) vfprintf(stderr, s, ap);
	(void) fprintf(stderr, gettext("\n"));
	va_end(ap);
	exit(1);
}

#if 0
void
err_warning(char *s, ...)
{
	va_list		 ap;

	va_start(ap, s);
	(void) vfprintf(stderr, s, ap);
	(void) fprintf(stderr, gettext("\n"));
	va_end(ap);
}
#endif
