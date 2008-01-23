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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak err = _err
#pragma weak errx = _errx
#pragma weak verr = _verr
#pragma weak verrx = _verrx
#pragma weak warn = _warn
#pragma weak warnx = _warnx
#pragma weak vwarn = _vwarn
#pragma weak vwarnx = _vwarnx

#include "synonyms.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "stdiom.h"

/* Function exit/warning functions and global variables. */

static const char *progname;

/*
 * warncore() is the workhorse of these functions.  Everything else has
 * a warncore() component in it.
 */
static rmutex_t *
warncore(FILE *fp, const char *fmt, va_list args)
{
	const char *execname;
	rmutex_t *lk;

	FLOCKFILE(lk, fp);

	if (progname == NULL) {
		execname = getexecname();
		if ((execname != NULL) &&
		    ((progname = strrchr(execname, '/')) != NULL))
			progname++;
		else
			progname = execname;
	}

	if (progname != NULL)
		(void) fprintf(fp, "%s: ", progname);

	if (fmt != NULL) {
		(void) vfprintf(fp, fmt, args);
	}

	return (lk);
}

/* Finish a warning with a newline and a flush of stderr. */
static void
warnfinish(FILE *fp, rmutex_t *lk)
{
	(void) fputc('\n', fp);
	(void) fflush(fp);
	FUNLOCKFILE(lk);
}

void
_vwarnxfp(FILE *fp, const char *fmt, va_list args)
{
	rmutex_t *lk;

	lk = warncore(fp, fmt, args);
	warnfinish(fp, lk);
}

void
vwarnx(const char *fmt, va_list args)
{
	_vwarnxfp(stderr, fmt, args);
}

void
_vwarnfp(FILE *fp, const char *fmt, va_list args)
{
	int tmperr = errno;	/* Capture errno now. */
	rmutex_t *lk;

	lk = warncore(fp, fmt, args);
	if (fmt != NULL) {
		(void) fputc(':', fp);
		(void) fputc(' ', fp);
	}
	(void) fputs(strerror(tmperr), fp);
	warnfinish(fp, lk);
}

void
vwarn(const char *fmt, va_list args)
{
	_vwarnfp(stderr, fmt, args);
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

void
_warnfp(FILE *fp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_vwarnfp(fp, fmt, args);
	va_end(args);
}

void
_warnxfp(FILE *fp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_vwarnxfp(fp, fmt, args);
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
_errfp(FILE *fp, int status, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_vwarnfp(fp, fmt, args);
	va_end(args);
	exit(status);
}

void
verr(int status, const char *fmt, va_list args)
{
	vwarn(fmt, args);
	exit(status);
}

void
_verrfp(FILE *fp, int status, const char *fmt, va_list args)
{
	_vwarnfp(fp, fmt, args);
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
_errxfp(FILE *fp, int status, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_vwarnxfp(fp, fmt, args);
	va_end(args);
	exit(status);
}

void
verrx(int status, const char *fmt, va_list args)
{
	vwarnx(fmt, args);
	exit(status);
}

void
_verrxfp(FILE *fp, int status, const char *fmt, va_list args)
{
	_vwarnxfp(fp, fmt, args);
	exit(status);
}
