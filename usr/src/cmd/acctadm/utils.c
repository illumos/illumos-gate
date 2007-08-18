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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

static char PNAME_FMT[] = "%s: ";
static char ERRNO_FMT[] = ": %s\n";

static char *pname;

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
die(char *format, ...)
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

char *
setprogname(char *arg0)
{
	char *p = strrchr(arg0, '/');

	if (p == NULL)
		p = arg0;
	else
		p++;
	pname = p;
	return (pname);
}

int
valid_abspath(char *p)
{
	if (p[0] != '/') {
		die(gettext("%s is not an absolute pathname\n"), p);
	}
	if (strlen(p) > MAXPATHLEN) {
		errno = ENAMETOOLONG;
		return (0);
	}
	return (1);
}
