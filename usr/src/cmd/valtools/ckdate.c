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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <locale.h>
#include <libintl.h>
#include <limits.h>
#include "usage.h"
#include "libadm.h"

#define	BADPID	(-2)

static char	*prog;
static char	*deflt = NULL, *prompt = NULL, *error = NULL, *help = NULL;
static int	signo = 0;
static int	kpid = BADPID;
static char	*fmt = NULL;

static const char	vusage[] = "f";
static const char	husage[] = "fWh";
static const char	eusage[] = "fWe";

#define	MYFMT "%s:ERROR:invalid format\n" \
	"valid format descriptors are:\n" \
	"\t%%b  #abbreviated month name\n" \
	"\t%%B  #full month name\n" \
	"\t%%d  #day of month (01-31)\n" \
	"\t%%D  #date as %%m/%%d/%%y or %%m-%%d-%%y (default)\n" \
	"\t%%e  #day of month (1-31)\n" \
	"\t%%m  #month of year (01-12)\n" \
	"\t%%y  #year within century (YY)\n" \
	"\t%%Y  #year as CCYY\n"

static void
usage(void)
{
	switch (*prog) {
	default:
		(void) fprintf(stderr,
			gettext("usage: %s [options] [-f format]\n"), prog);
		(void) fprintf(stderr, gettext(OPTMESG));
		(void) fprintf(stderr, gettext(STDOPTS));
		break;

	case 'v':
		(void) fprintf(stderr,
			gettext("usage: %s [-f format] input\n"), prog);
		break;

	case 'h':
		(void) fprintf(stderr,
			gettext("usage: %s [options] [-f format]\n"), prog);
		(void) fprintf(stderr, gettext(OPTMESG));
		(void) fprintf(stderr,
			gettext("\t-W width\n\t-h help\n"));
		break;

	case 'e':
		(void) fprintf(stderr,
			gettext("usage: %s [options] [-f format]\n"), prog);
		(void) fprintf(stderr, gettext(OPTMESG));
		(void) fprintf(stderr,
			gettext("\t-W width\n\t-h error\n"));
		break;
	}
	exit(1);
}

/*
 * Given argv[0], return a pointer to the basename of the program.
 */
static char *
prog_name(char *arg0)
{
	char *str;

	/* first strip trailing '/' characters (exec() allows these!) */
	str = arg0 + strlen(arg0);
	while (str > arg0 && *--str == '/')
		*str = '\0';
	if ((str = strrchr(arg0, '/')) != NULL)
		return (str + 1);
	return (arg0);
}

int
main(int argc, char **argv)
{
	int	c, n;
	char	*date;
	size_t	len;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prog = prog_name(argv[0]);

	while ((c = getopt(argc, argv, "f:d:p:e:h:k:s:QW:?")) != EOF) {
		/* check for invalid option */
		if ((*prog == 'v') && !strchr(vusage, c))
			usage();
		if ((*prog == 'e') && !strchr(eusage, c))
			usage();
		if ((*prog == 'h') && !strchr(husage, c))
			usage();

		switch (c) {
		case 'Q':
			ckquit = 0;
			break;

		case 'W':
			ckwidth = atoi(optarg);
			if (ckwidth < 0) {
				(void) fprintf(stderr,
		gettext("%s: ERROR: negative display width specified\n"),
					prog);
				exit(1);
			}
			break;

		case 'f':
			fmt = optarg;
			break;

		case 'd':
			deflt = optarg;
			break;

		case 'p':
			prompt = optarg;
			break;

		case 'e':
			error = optarg;
			break;

		case 'h':
			help = optarg;
			break;

		case 'k':
			kpid = atoi(optarg);
			break;

		case 's':
			signo = atoi(optarg);
			break;

		default:
			usage();
		}
	}

	if (signo) {
		if (kpid == BADPID)
			usage();
	} else
		signo = SIGTERM;

	if (*prog == 'v') {
		if (argc != (optind + 1))
			usage();
		n = (ckdate_val(fmt, argv[optind]));
		if (n == 4)
			(void) fprintf(stderr, gettext(MYFMT), prog);
		exit(n);
	}

	if (optind != argc)
		usage();

	if (*prog == 'e') {
		ckindent = 0;
		if (ckdate_err(fmt, error)) {
			(void) fprintf(stderr, gettext(MYFMT), prog);
			exit(4);
		} else
			exit(0);

	} else if (*prog == 'h') {
		ckindent = 0;
		if (ckdate_hlp(fmt, help)) {
			(void) fprintf(stderr, gettext(MYFMT), prog);
			exit(4);
		} else
			exit(0);

	}

	if (deflt) {
		len = strlen(deflt) + 1;
		if (len < MAX_INPUT)
			len = MAX_INPUT;
	} else {
		len = MAX_INPUT;
	}
	date = (char *)malloc(len);
	if (!date) {
		(void) fprintf(stderr,
			gettext("Not enough memory\n"));
		exit(1);
	}
	n = ckdate(date, fmt, deflt, error, help, prompt);
	if (n == 3) {
		if (kpid > -2)
			(void) kill(kpid, signo);
		(void) puts("q");
	} else if (n == 0)
		(void) printf("%s", date);
	if (n == 4)
		(void) fprintf(stderr, gettext(MYFMT), prog);
	return (n);
}
