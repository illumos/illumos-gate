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
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <locale.h>
#include <libintl.h>
#include "usage.h"
#include "libadm.h"

#define	BADPID	(-2)

static char	*prog;
static char	*deflt = NULL, *prompt = NULL, *error = NULL, *help = NULL;
static int	kpid = BADPID;
static int	signo;
static int	base = 10;
static char	*upper;
static char	*lower;

static const char	vusage[] = "bul";
static const char	husage[] = "bulWh";
static const char	eusage[] = "bulWe";

#define	USAGE	"[-l lower] [-u upper] [-b base]"

static void
usage(void)
{
	switch (*prog) {
	default:
		(void) fprintf(stderr,
			gettext("usage: %s [options] %s\n"),
			prog, USAGE);
		(void) fprintf(stderr, gettext(OPTMESG));
		(void) fprintf(stderr, gettext(STDOPTS));
		break;

	case 'v':
		(void) fprintf(stderr,
			gettext("usage: %s %s input\n"), prog, USAGE);
		break;

	case 'h':
		(void) fprintf(stderr,
			gettext("usage: %s [options] %s\n"),
			prog, USAGE);
		(void) fprintf(stderr, gettext(OPTMESG));
		(void) fprintf(stderr,
			gettext("\t-W width\n\t-h help\n"));
		break;

	case 'e':
		(void) fprintf(stderr,
			gettext("usage: %s [options] %s\n"),
			prog, USAGE);
		(void) fprintf(stderr, gettext(OPTMESG));
		(void) fprintf(stderr,
			gettext("\t-W width\n\t-e error\n"));
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
	long	lvalue, uvalue, intval;
	char	*ptr = 0;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prog = prog_name(argv[0]);

	while ((c = getopt(argc, argv, "l:u:b:d:p:e:h:k:s:QW:?")) != EOF) {
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

		case 'b':
			base = atoi(optarg);
			if ((base < 2) || (base > 36)) {
				(void) fprintf(stderr,
		gettext("%s: ERROR: base must be between 2 and 36\n"),
					prog);
				exit(1);
			}
			break;

		case 'u':
			upper = optarg;
			break;

		case 'l':
			lower = optarg;
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

	if (upper) {
		uvalue = strtol(upper, &ptr, base);
		if (ptr == upper) {
			(void) fprintf(stderr,
		gettext("%s: ERROR: invalid upper value specification\n"),
				prog);
			exit(1);
		}
	} else
		uvalue = LONG_MAX;
	if (lower) {
		lvalue =  strtol(lower, &ptr, base);
		if (ptr == lower) {
			(void) fprintf(stderr,
		gettext("%s: ERROR: invalid lower value specification\n"),
				prog);
			exit(1);
		}
	} else
		lvalue = LONG_MIN;

	if (uvalue < lvalue) {
		(void) fprintf(stderr,
		gettext("%s: ERROR: upper value is less than lower value\n"),
			prog);
		exit(1);
	}

	if (*prog == 'v') {
		if (argc != (optind+1))
			usage();
		exit(ckrange_val(lvalue, uvalue, base, argv[optind]));
	}

	if (optind != argc)
		usage();

	if (*prog == 'e') {
		ckindent = 0;
		ckrange_err(lvalue, uvalue, base, error);
		exit(0);
	} else if (*prog == 'h') {
		ckindent = 0;
		ckrange_hlp(lvalue, uvalue, base, help);
		exit(0);
	}

	n = ckrange(&intval, lvalue, uvalue, (short)base,
		deflt, error, help, prompt);	/* libadm interface */
	if (n == 3) {
		if (kpid > -2)
			(void) kill(kpid, signo);
		(void) puts("q");
	} else if (n == 0)
		(void) printf("%ld", intval);
	return (n);
}
