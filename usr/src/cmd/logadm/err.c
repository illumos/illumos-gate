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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * logadm/err.c -- some basic error routines
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <libintl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "err.h"

static const char *Myname;
static int Exitcode;
static FILE *Errorfile;

/*
 * err_init -- initialize the error handling routine
 *
 */
void
err_init(const char *myname)
{
	char *ptr;

	if ((ptr = strrchr(myname, '/')) == NULL)
		Myname = myname;
	else
		Myname = ptr + 1;
}

static const char *File;
static int Line;

/*
 * err_fileline -- record the filename/line number for err(EF_FILE, ...)
 */
void
err_fileline(const char *file, int line)
{
	File = file;
	Line = line;
}

/*
 * err -- print an error message and return, exit or longjmp based on flags
 *
 * this routine calls gettext() to translate the fmt string.
 */
/*PRINTFLIKE2*/
void
err(int flags, const char *fmt, ...)
{
	va_list ap;
	int safe_errno = errno;
	char *errno_msg = NULL;
	int as_is = 0;
	int jump = 0;
	int warning = 0;
	int fileline = 0;
	char *prefix = "Error: ";
	const char *intlfmt;

	va_start(ap, fmt);
	intlfmt = gettext(fmt);

	if (flags & EF_WARN) {
		warning = 1;
		prefix = "Warning: ";
	}
	if (flags & EF_FILE) {
		fileline = 1;
		Exitcode++;
	}
	if (flags & EF_SYS)
		errno_msg = strerror(safe_errno);
	if (flags & EF_JMP)
		jump = 1;
	if (flags & EF_RAW)
		as_is = 1;

	/* print a copy to stderr */
	if (!as_is) {
		if (Myname != NULL) {
			(void) fprintf(stderr, "%s: ", Myname);
			if (Errorfile)
				(void) fprintf(Errorfile, "%s: ", Myname);
		}
		if (fileline && File) {
			(void) fprintf(stderr, "%s line %d: ", File, Line);
			if (Errorfile)
				(void) fprintf(Errorfile,
				    "%s line %d: ", File, Line);
		}
		(void) fputs(gettext(prefix), stderr);
		if (Errorfile)
			(void) fputs(gettext(prefix), Errorfile);
	}
	(void) vfprintf(stderr, intlfmt, ap);
	if (Errorfile)
		(void) vfprintf(Errorfile, intlfmt, ap);
	if (errno_msg != NULL) {
		(void) fprintf(stderr, ": %s", errno_msg);
		if (Errorfile)
			(void) fprintf(Errorfile, ": %s", errno_msg);
	}
	if (!as_is) {
		(void) fprintf(stderr, "\n");
		if (Errorfile)
			(void) fprintf(Errorfile, "\n");
	}
	(void) fflush(stderr);
	if (Errorfile)
		(void) fflush(Errorfile);

	va_end(ap);

	if (jump)
		longjmp(Err_env, 1);

	if (!warning && !fileline) {
		err_done(1);
		/*NOTREACHED*/
	}
}

/*
 * out -- print a message and return
 *
 * this routine calls gettext() to translate the fmt string.
 */
/*PRINTFLIKE1*/
void
out(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	(void) vfprintf(stdout, gettext(fmt), ap);

	va_end(ap);
}

#define	CHUNKSIZE 8192		/* for copying stderr */
/*
 * err_fromfd -- copy data from fd to stderr
 */
void
err_fromfd(int fd)
{
	char buf[CHUNKSIZE];
	int count;

	while ((count = read(fd, buf, CHUNKSIZE)) > 0) {
		(void) fwrite(buf, 1, count, stderr);
		if (Errorfile)
			(void) fwrite(buf, 1, count, Errorfile);
	}
	(void) fflush(stderr);
	if (Errorfile)
		(void) fflush(Errorfile);
}

/*
 * err_done -- exit the program
 */
void
err_done(int exitcode)
{
	/* send error mail if applicable */
	err_mailto(NULL);

	if (exitcode)
		exit(exitcode);
	else
		exit(Exitcode);
	/*NOTREACHED*/
}

#define	MAXLINE	8192	/* for tmp file line buffer */
/*
 * err_mailto -- arrange for error output to be mailed to someone
 */
void
err_mailto(const char *recipient)
{
	static const char *lastrecipient;
	static char mailcmd[] = "/bin/mailx -s 'logadm error output'";
	char *cmd;
	int len;
	FILE *pfp;
	char line[MAXLINE];

	if (lastrecipient != NULL) {
		if (recipient != NULL &&
		    strcmp(recipient, lastrecipient) == 0)
			return;		/* keep going, same recipient */

		/* stop saving output for lastrecipient and send message */
		if (ftell(Errorfile)) {
			rewind(Errorfile);
			len = strlen(lastrecipient) + strlen(mailcmd) + 2;
			cmd = MALLOC(len);
			(void) snprintf(cmd, len, "%s %s",
			    mailcmd, lastrecipient);
			if ((pfp = popen(cmd, "w")) == NULL)
				err(EF_SYS, "popen to mailx");
			while (fgets(line, MAXLINE, Errorfile) != NULL)
				(void) fputs(line, pfp);
			(void) pclose(pfp);
		}
		(void) fclose(Errorfile);
		Errorfile = NULL;
	}

	if (recipient != NULL) {
		/* start saving error output for this recipient */
		if ((Errorfile = tmpfile()) == NULL)
			err(EF_SYS, "tmpfile");
	}
	lastrecipient = recipient;
}

/*
 * err_malloc -- a malloc() with checks
 *
 * this routine is typically called via the MALLOC() macro in err.h
 */
void *
err_malloc(int nbytes, const char *fname, int line)
{
	void *retval = malloc(nbytes);

	if (retval == NULL)
		err(0, "%s:%d: out of memory", fname, line);

	return (retval);
}

/*
 * err_realloc -- a realloc() with checks
 *
 * this routine is typically called via the REALLOC() macro in err.h
 */
void *
err_realloc(void *ptr, int nbytes, const char *fname, int line)
{
	void *retval = realloc(ptr, nbytes);

	if (retval == NULL)
		err(0, "%s:%d: out of memory", fname, line);

	return (retval);
}

/*
 * err_strdup -- a strdup() with checks
 *
 * this routine is typically called via the STRDUP() macro in err.h
 */
char *
err_strdup(const char *ptr, const char *fname, int line)
{
	char *retval = NULL;

	if (ptr != NULL) {
		retval = strdup(ptr);
		if (retval == NULL)
			err(0, "%s:%d: out of memory", fname, line);
	} else
		err(0, "%s:%d: could not strdup", fname, line);


	return (retval);

}

/*
 * err_free -- a free() with checks
 *
 * this routine is typically called via the FREE() macro in err.h
 */
/*ARGSUSED1*/
void
err_free(void *ptr, const char *fname, int line)
{
	/* nothing to check in this version */
	free(ptr);
}

/*
 * err_exitcode -- set an error exit code for when done(0) is called
 */
void
err_exitcode(int exitcode)
{
	Exitcode = exitcode;
}
