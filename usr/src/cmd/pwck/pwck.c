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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>

#define	ERROR1	"Too many/few fields"
#define	ERROR2	"Bad character(s) in logname"
#define	ERROR2a "First char in logname not alphabetic"
#define	ERROR2b "Logname field NULL"
#define	ERROR2c "Logname contains no lower-case letters"
#define	ERROR3	"Logname too long/short"
#define	ERROR4	"Invalid UID"
#define	ERROR5	"Invalid GID"
#define	ERROR6	"Login directory not found"
#define	ERROR6a	"Login directory null"
#define	ERROR7	"Optional shell file not found"

static int eflag, code = 0;
static int badc;
static int lc;
static char buf[512];
static void error(char *);

int
main(int argc, char **argv)
{
	int delim[512];
	char logbuf[512];
	FILE *fptr;
	struct stat obuf;
	uid_t uid;
	gid_t gid;
	int i, j, colons;
	char *pw_file;
	struct stat stat_buf;
	char *str, *lastc;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1)
		pw_file = "/etc/passwd";
	else
		pw_file = argv[1];

	if ((fptr = fopen(pw_file, "r")) == NULL) {
		(void) fprintf(stderr, gettext("cannot open %s\n"), pw_file);
		exit(1);
	}

	if (fstat(fileno(fptr), &stat_buf) < 0) {
		(void) fprintf(stderr, gettext("fstat failed for %s\n"),
		    pw_file);
		(void) fclose(fptr);
		exit(1);
	}

	if (stat_buf.st_size == 0) {
		(void) fprintf(stderr, gettext("file %s is empty\n"), pw_file);
		(void) fclose(fptr);
		exit(1);
	}

	while (fgets(buf, sizeof (buf), fptr) != NULL) {

		colons = 0;
		badc = 0;
		lc = 0;
		eflag = 0;

		/* Check that entry is not a nameservice redirection */

		if (buf[0] == '+' || buf[0] == '-')  {
			/*
			 * Should set flag here to allow special case checking
			 * in the rest of the code,
			 * but for now, we'll just ignore this entry.
			 */
			continue;
		}

		/* Check number of fields */

		for (i = 0; buf[i] != NULL; i++)
			if (buf[i] == ':') {
				delim[colons] = i;
				++colons;
			}

		if (colons != 6) {
			error(ERROR1);
			continue;
		}
		delim[6] = i - 1;
		delim[7] = NULL;

		/*
		 * Check the first char is alpha; the rest alphanumeric;
		 * and that the name does not consist solely of uppercase
		 * alpha chars
		 */
		if (buf[0] == ':')
			error(ERROR2b);
		else if (!isalpha(buf[0]))
			error(ERROR2a);

		for (i = 0; buf[i] != ':'; i++) {
			if (!isalnum(buf[i]) &&
			    buf[i] != '_' &&
			    buf[i] != '-' &&
			    buf[i] != '.')
				badc++;
			else if (islower(buf[i]))
				lc++;
		}
		if (lc == 0)
			error(ERROR2c);
		if (badc > 0)
			error(ERROR2);

		/* Check for valid number of characters in logname */

		if (i <= 0 || i > LOGNAME_MAX)
			error(ERROR3);

		/* Check that UID is numeric and <= MAXUID */

		errno = 0;
		str = &buf[delim[1] + 1];
		uid = strtol(str, &lastc, 10);
		if (lastc != str + (delim[2] - delim[1]) - 1 ||
		    uid > MAXUID || errno == ERANGE)
			error(ERROR4);

		/* Check that GID is numeric and <= MAXUID */

		errno = 0;
		str = &buf[delim[2] + 1];
		gid = strtol(str, &lastc, 10);
		if (lastc != str + (delim[3] - delim[2]) - 1 ||
		    gid > MAXUID || errno == ERANGE)
			error(ERROR5);

		/* Check initial working directory */

		for (j = 0, i = (delim[4] + 1); i < delim[5]; j++, i++)
			logbuf[j] = buf[i];
		logbuf[j] = '\0';

		if (logbuf[0] == NULL)
			error(ERROR6a);
		else if ((stat(logbuf, &obuf)) == -1)
			error(ERROR6);

		/* Check program to use as shell  */

		if ((buf[(delim[5] + 1)]) != '\n') {

			for (j = 0, i = (delim[5] + 1); i < delim[6]; j++, i++)
				logbuf[j] = buf[i];
			logbuf[j] = '\0';

			if (strcmp(logbuf, "*") == 0)	/* subsystem login */
				continue;

			if ((stat(logbuf, &obuf)) == -1)
				error(ERROR7);

			for (j = 0; j < 512; j++)
				logbuf[j] = NULL;
		}
	}
	(void) fclose(fptr);
	return (code);
}

/* Error printing routine */

static void
error(char *msg)
{
	if (!eflag) {
		(void) fprintf(stderr, "\n%s", buf);
		code = 1;
		++eflag;
	}
	if (!badc)
		(void) fprintf(stderr, "\t%s\n", gettext(msg));
	else {
		(void) fprintf(stderr, "\t%d %s\n", badc, gettext(msg));
		badc = 0;
	}
}
