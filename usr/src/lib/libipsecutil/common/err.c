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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libgen.h>
#include <libintl.h>
#include <errno.h>

#include "ipsec_util.h"

/* Function exit/warning functions and global variables. */

static const char *progname;

/*
 * warncore() is the workhorse of these functions.  Everything else has
 * a warncore() component in it.
 */
static void
warncore(const char *fmt, va_list args)
{
	if (progname == NULL) {
		progname = strrchr(getexecname(), '/');
		if (progname == NULL)
			progname = getexecname();
		else
			progname++;
	}

	(void) fputs(progname, stderr);

	if (fmt != NULL) {
		(void) fputc(':', stderr);
		(void) fputc(' ', stderr);
		(void) vfprintf(stderr, fmt, args);
	}
}

/* Finish a warning with a newline and a flush of stderr. */
static void
warnfinish(void)
{
	(void) fputc('\n', stderr);
	(void) fflush(stderr);
}

void
vwarnx(const char *fmt, va_list args)
{
	warncore(fmt, args);
	warnfinish();
}

void
vwarn(const char *fmt, va_list args)
{
	int tmperr = errno;	/* Capture errno now. */

	warncore(fmt, args);
	(void) fputc(':', stderr);
	(void) fputc(' ', stderr);
	(void) fputs(strerror(tmperr), stderr);
	warnfinish();
}

/* PRINTFLIKE1 */
void
warnx(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vwarnx(fmt, args);
	va_end(args);
}

/* PRINTFLIKE1 */
void
warn(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vwarn(fmt, args);
	va_end(args);
}

/* PRINTFLIKE2 */
void
err(int status, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vwarn(fmt, args);
	va_end(args);
	exit(status);
}

void
verr(int status, const char *fmt, va_list args)
{
	vwarn(fmt, args);
	exit(status);
}

/* PRINTFLIKE2 */
void
errx(int status, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vwarnx(fmt, args);
	va_end(args);
	exit(status);
}

void
verrx(int status, const char *fmt, va_list args)
{
	vwarnx(fmt, args);
	exit(status);
}
