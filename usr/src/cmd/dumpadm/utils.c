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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <libintl.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#include "utils.h"

static const char PNAME_FMT[] = "%s: ";
static const char ERRNO_FMT[] = ": %s\n";

static const char *pname;

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	int err = errno;
	va_list alist;

	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERRNO_FMT), strerror(err));
}

/*PRINTFLIKE1*/
void
die(const char *format, ...)
{
	int err = errno;
	va_list alist;

	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERRNO_FMT), strerror(err));

	exit(E_ERROR);
}

const char *
getpname(const char *arg0)
{
	const char *p = strrchr(arg0, '/');

	if (p == NULL)
		p = arg0;
	else
		p++;

	pname = p;
	return (p);
}

int
valid_abspath(const char *p)
{
	if (p[0] != '/') {
		warn(gettext("pathname is not an absolute path -- %s\n"), p);
		return (0);
	}

	if (strlen(p) > MAXPATHLEN) {
		warn(gettext("pathname is too long -- %s\n"), p);
		return (0);
	}

	return (1);
}

int
valid_str2int(const char *p, int *ip)
{
	int i;
	char *q;

	errno = 0;
	i = (int)strtol(p, &q, 10);

	if (errno != 0 || q == p || i < 0 || (*q != '\0' && *q != '\n'))
		return (0);

	*ip = i;
	return (1);
}

int
valid_str2ull(const char *p, unsigned long long *ullp)
{
	long long ll;
	char *q;

	errno = 0;
	ll = strtoll(p, &q, 10);

	if (errno != 0 || q == p || ll < 0LL || (*q != '\0' && *q != '\n'))
		return (0);

	*ullp = (unsigned long long)ll;
	return (1);
}
