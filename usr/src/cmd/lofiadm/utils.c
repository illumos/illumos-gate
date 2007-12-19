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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <libintl.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <link.h>

#include "utils.h"

static void *lib_hdl = NULL;

static const char PNAME_FMT[] = "%s: ";
static const char ERRNO_FMT[] = ": %s\n";

static const char *pname;

/*PRINTFLIKE1*/
static void
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

/*
 * Wrapper for dlopen'ing a library.
 * The caller must call closelib() once
 * access to the library is no longer needed.
 */
void *
openlib(const char *lib)
{
	lib_hdl = dlopen(lib, RTLD_LAZY);
	return (lib_hdl);
}

void
closelib()
{
	if (lib_hdl != NULL)
		(void) dlclose(lib_hdl);
}
