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
 *
 * out.c -- some basic output routines
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fm/fmd_api.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include "out.h"
#include "stats.h"
#include "io.h"

/* stats we keep for "out" module */
static struct stats *Outcount;
static struct stats *Errcount;
static struct stats *Warncount;

static int Exitcode;

static const char *Myname;
static FILE *Altfp;

/* buffer used to format all prints */
#define	MAXOUT 8192
static char Outbuf[MAXOUT];
static int Outidx;		/* next unused char in Outbuf[] */

/*
 * out_init -- initialize this module
 */
void
out_init(const char *myname)
{
	Outcount = stats_new_counter("output.calls", "total calls", 1);
	Errcount = stats_new_counter("output.errors", "total errors", 0);
	Warncount = stats_new_counter("output.warnings", "total warnings", 0);

	if (myname == NULL)
		return;

	if ((Myname = strrchr(myname, '/')) == NULL &&
	    (Myname = strrchr(myname, '\\')) == NULL)
		Myname = myname;
	else
		Myname++;
}

void
out_fini(void)
{
	stats_delete(Outcount);
	Outcount = NULL;
	stats_delete(Errcount);
	Errcount = NULL;
	stats_delete(Warncount);
	Warncount = NULL;
}

/*
 * out_altfp -- store an alternate fp for O_ALTFP
 */
void
out_altfp(FILE *fp)
{
	Altfp = fp;
}

/*
 * voutbufprintf -- like vprintf, but appends to Outbuf
 */
static void
voutbufprintf(const char *fmt, va_list ap)
{
	int len = vsnprintf(&Outbuf[Outidx], MAXOUT - Outidx, fmt, ap);

	Outidx += len;
	if (Outidx >= MAXOUT)
		Outidx = MAXOUT - 1;
}

/*
 * outbufprintf -- like printf, but appends to Outbuf
 */
/*PRINTFLIKE1*/
static void
outbufprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	voutbufprintf(fmt, ap);
	va_end(ap);
}

/*
 * vout -- va_list version of out()
 *
 * all the output processing work is done here.
 */
static void
vout(int flags, const char *fmt, va_list ap)
{
	int safe_errno = errno;

	stats_counter_bump(Outcount);

	/*
	 * just return if called with a disabled output type.  this
	 * prevents debug prints when Debug is off, verbose prints
	 * when Verbose is off, and language warnings when warnings
	 * are quenched (which they are when we're loading a .eft file).
	 *
	 */
	if ((flags & O_DEBUG) && Debug == 0)
		return;

	if ((flags & O_VERB) && Verbose == 0)
		return;

	if ((flags & O_VERB2) && Verbose < 2)
		return;

	if ((flags & O_VERB3) && Verbose < 3)
		return;

	if ((flags & O_WARN) && Warn == 0)
		return;

	if ((flags & O_ALTFP) && Altfp == NULL)
		return;

	/* some things only happen at the beginning of a print */
	if (Outidx == 0) {
		if (flags & O_USAGE) {
			Exitcode++;
			outbufprintf("usage: %s ", Myname);
		} else {
			if (Myname && flags & (O_DIE|O_ERR|O_WARN|O_PROG))
				outbufprintf("%s: ", Myname);

			if (flags & O_DIE) {
				Exitcode++;
				outbufprintf("fatal error: ");
			} else if (flags & O_ERR) {
				Exitcode++;
				stats_counter_bump(Errcount);
				outbufprintf("error: ");
			} else if (flags & O_WARN) {
				stats_counter_bump(Warncount);
				outbufprintf("warning: ");
			}
		}
	}

	/* fmt can be NULL if the caller just wanted flags processed */
	if (fmt != NULL)
		voutbufprintf(fmt, ap);

	/* O_SYS means convert errno to a string and append it */
	if (flags & O_SYS) {
		const char *msg = strerror(safe_errno);

		if (Outidx != 0)
			outbufprintf(": ");

		if (msg)
			outbufprintf("%s", msg);
		else
			outbufprintf("(error %d)", safe_errno);
	}

	/* O_STAMP means convert add a timestamp */
	if (flags & O_STAMP) {
		time_t clock;
		char *tmsg;

		(void) time(&clock);
		tmsg = ctime(&clock);
		if (tmsg && *tmsg) {
			tmsg[strlen(tmsg) - 1] = '\0';

			if (Outidx != 0)
				outbufprintf(" ");

			outbufprintf("%s", tmsg);
		}
	}

	if (flags & O_NONL)
		return;		/* not done filling Outbuf */

	/* done filling Outbuf, platform calls will add newline */
	if (flags & O_ALTFP)
		(void) fprintf(Altfp, "%s\n", Outbuf);
	else if (flags & O_ABORT)
		io_abort(Outbuf);
	else if (flags & O_DIE)
		io_die(Outbuf);
	else if (flags & O_ERR)
		io_err(Outbuf);
	else
		io_out(Outbuf);

	/* reset output buffer */
	Outidx = 0;
	Outbuf[0] = '\0';
}

/*
 * out -- spew a line of output, with various options
 */
/*PRINTFLIKE2*/
void
out(int flags, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vout(flags, fmt, ap);
	va_end(ap);
}

/*
 * outfl -- spew a filename:linenumber message
 */
/*PRINTFLIKE4*/
void
outfl(int flags, const char *fname, int line, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (fname)
		out(flags|O_NONL, "%s:%d: ", fname, line);

	vout(flags, fmt, ap);

	va_end(ap);
}

/*
 * out_exit -- exit the program
 */
void
out_exit(int code)
{
	io_exit(Exitcode + code);
}

/*
 * out_errcount -- return the number of O_ERR messages issued so far
 */
int
out_errcount(void)
{
	return (stats_counter_value(Errcount));
}

/*
 * out_warncount -- return the number of O_WARN messages issued so far
 */
int
out_warncount(void)
{
	return (stats_counter_value(Warncount));
}
