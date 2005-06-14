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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "common.h"

/*PRINTFLIKE1*/
void
error(char *err, ...)
{
	va_list	ap;
	va_start(ap, err);

	(void) fprintf(stderr, gettext(ERR_ERROR));
	(void) vfprintf(stderr, err, ap);
	va_end(ap);
	exit(2);
}

/*PRINTFLIKE1*/
void
warning(char *err, ...)
{
	va_list	ap;
	va_start(ap, err);

	(void) fprintf(stderr, gettext(WARN_WARNING));
	(void) vfprintf(stderr, err, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
diag(char *err, ...)
{
	va_list	ap;
	va_start(ap, err);

	(void) vfprintf(stderr, err, ap);
	va_end(ap);
}

void	*
Xmalloc(size_t size)
{
	void	*t;

	t = malloc(size);
	if (!t) {
		error(gettext(ERR_MALLOC));
		/* NOTREACHED */
	}
	return (t);
}

void	*
Xcalloc(size_t nelem, size_t elsize)
{
	void	*t;

	t = calloc(nelem, elsize);
	if (!t) {
		error(gettext(ERR_MALLOC));
		/* NOTREACHED */
	}
	return (t);
}

void	*
Xrealloc(void *ptr, size_t size)
{
	void	*t;

	t = realloc(ptr, size);
	if (!t) {
		free(ptr);
		error(gettext(ERR_MALLOC));
		/* NOTREACHED */
	}
	return (t);
}

char	*
Xstrdup(const char *str)
{
	char	*t;

	t = strdup(str);
	if (!t) {
		error(gettext(ERR_MALLOC));
		/* NOTREACHED */
	}
	return (t);
}
