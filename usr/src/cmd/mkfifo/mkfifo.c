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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	  All Rights Reserved					*/
/*								*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<stdio.h>
#include	<errno.h>
#include	<string.h>
#include	<errno.h>
#include	<locale.h>
#include	<stdarg.h>

#define	ALLRW	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

static void
usage();

void
errmsg(int severity, int code, char *format, ...);

/* from chmod:common.c: */

extern mode_t
newmode(char *modestr, mode_t basemode, mode_t umask, char *file, char *path);

int
main(int argc, char *argv[])
{
	char *path;
	int exitval = 0;
	int c, i;
	int mflag = 0;
	int errflg = 0;
	mode_t umsk = umask(0);
	mode_t mode = ALLRW & (~umsk);

	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2) {
		usage();
		exit(1);
	}

	while ((c = getopt(argc, argv, "m:")) != EOF) {
		switch (c) {
		case 'm':
			mflag++;
			mode = newmode(optarg, ALLRW, umsk, "", "");
			break;

		default:
			errflg++;
			break;
		}
	}

	if (argc < optind || errflg) {
		usage();
		exit(1);
	}

	for (i = optind; i < argc; i++) {
		path = argv[i];
		if (mkfifo(path, mode) < 0) {
			perror("mkfifo");
			exitval = 1;
		}
	}

	return (exitval);

}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: mkfifo [-m mode] file ...\n"));
}

/*
 *  errmsg - This is an interface required by the code common to mkfifo and
 *	     chmod.  The severity parameter is ignored here, but is meaningful
 *	     to chmod.
 */

/* ARGSUSED */
/* PRINTFLIKE3 */
void
errmsg(int severity, int code, char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	(void) fprintf(stderr, "mkfifo: ");
	(void) vfprintf(stderr, format, ap);

	va_end(ap);

	if (code > 0) {
		exit(code);
	}
}
