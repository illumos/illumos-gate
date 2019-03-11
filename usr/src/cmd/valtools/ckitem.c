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


/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <valtools.h>
#include <stdlib.h>
#include <locale.h>
#include <libintl.h>
#include <limits.h>
#include <wchar.h>
#include "usage.h"
#include "libadm.h"

#define	BADPID	(-2)
#define	INVISMAXSIZE 36

static char	*prog;
static char	*deflt = NULL, *prompt = NULL, *error = NULL, *help = NULL;
static int	kpid = BADPID;
static int	signo;

static char	*label, **invis;
static int	ninvis = 0;
static int	max = 1;
static int	attr = CKALPHA;

#define	MAXSIZE	128
#define	LSIZE	1024
#define	INTERR	\
	"%s: ERROR: internal error occurred while attempting menu setup\n"
#define	MYOPTS \
	"\t-f file             #file containing choices\n" \
	"\t-l label            #menu label\n" \
	"\t-i invis [, ...]    #invisible menu choices\n" \
	"\t-m max              #maximum choices user may select\n" \
	"\t-n                  #do not sort choices alphabetically\n" \
	"\t-o                  #don't prompt if only one choice\n" \
	"\t-u                  #unnumbered choices\n"

static const char	husage[] = "Wh";
static const char	eusage[] = "We";

static void
usage(void)
{
	switch (*prog) {
	default:
		(void) fprintf(stderr,
			gettext("usage: %s [options] [choice [...]]\n"), prog);
		(void) fprintf(stderr, gettext(OPTMESG));
		(void) fprintf(stderr, gettext(MYOPTS));
		(void) fprintf(stderr, gettext(STDOPTS));
		break;

	case 'h':
		(void) fprintf(stderr,
			gettext("usage: %s [options] [choice [...]]\n"), prog);
		(void) fprintf(stderr, gettext(OPTMESG));
		(void) fprintf(stderr,
			gettext("\t-W width\n\t-h help\n"));
		break;

	case 'e':
		(void) fprintf(stderr,
			gettext("usage: %s [options] [choice [...]]\n"), prog);
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
	CKMENU	*mp;
	FILE	*fp = NULL;
	int	c, i;
	char	**item;
	char	temp[LSIZE * MB_LEN_MAX];
	size_t	mmax;
	size_t invismaxsize = INVISMAXSIZE;
	size_t	n, r;
	wchar_t	wline[LSIZE], wtemp[LSIZE];

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prog = prog_name(argv[0]);

	invis = (char **)calloc(invismaxsize, sizeof (char *));
	if (!invis) {
		(void) fprintf(stderr,
			gettext("Not enough memory\n"));
		exit(1);
	}
	while ((c = getopt(argc, argv, "m:oni:l:f:ud:p:e:h:k:s:QW:?")) != EOF) {
		/* check for invalid option */
		if ((*prog == 'e') && !strchr(eusage, c))
			usage(); /* no valid options */
		if ((*prog == 'h') && !strchr(husage, c))
			usage();

		switch (c) {
		case 'Q':
			ckquit = 0;
			break;

		case 'W':
			ckwidth = atol(optarg);
			if (ckwidth < 0) {
				(void) fprintf(stderr,
		gettext("%s: ERROR: negative display width specified\n"),
					prog);
				exit(1);
			}
			break;

		case 'm':
			max = atoi(optarg);
			if (max > SHRT_MAX || max < SHRT_MIN) {
				(void) fprintf(stderr,
	gettext("%s: ERROR: too large or too small max value specified\n"),
					prog);
				exit(1);
			}
			break;

		case 'o':
			attr |= CKONEFLAG;
			break;

		case 'n':
			attr &= ~CKALPHA;
			break;

		case 'i':
			invis[ninvis++] = optarg;
			if (ninvis == invismaxsize) {
				invismaxsize += INVISMAXSIZE;
				invis = (char **)realloc(invis,
						invismaxsize * sizeof (char *));
				if (!invis) {
					(void) fprintf(stderr,
						gettext("Not enough memory\n"));
					exit(1);
				}
				(void) memset(invis + ninvis, 0,
					(invismaxsize - ninvis) *
					sizeof (char *));
			}
			break;

		case 'l':
			label = optarg;
			break;

		case 'f':
			if ((fp = fopen(optarg, "r")) == NULL) {
				(void) fprintf(stderr,
					gettext("%s: ERROR: can't open %s\n"),
					prog, optarg);
				exit(1);
			}
			break;

		case 'u':
			attr |= CKUNNUM;
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

	mp = allocmenu(label, attr);
	if (fp) {
		*wtemp = L'\0';
		while (fgetws(wline, LSIZE, fp)) {
			/*
			 * Skip comment lines, those beginning with '#'.
			 * Note:  AT&T forgot this & needs the next 2 lines.
			 */
			if (*wline == L'#')
				continue;
			n = wcslen(wline);
			if ((n != 0) && (wline[n - 1] == L'\n'))
				wline[n - 1] = L'\0';
			/*
			 * if the line begins with a space character,
			 * this is a continuous line to the previous line.
			 */
			if (iswspace(*wline)) {
				(void) wcscat(wtemp, L"\n");
				(void) wcscat(wtemp, wline);
			} else {
				if (*wtemp) {
					n = wcslen(wtemp);
					r = wcstombs(temp, wtemp,
						n * MB_LEN_MAX);
					if (r == (size_t)-1) {
						(void) fprintf(stderr,
			gettext("Invalid character in the menu definition.\n"));
						exit(1);
					}
					if (setitem(mp, temp)) {
						(void) fprintf(stderr,
							gettext(INTERR), prog);
						exit(1);
					}
				}
				(void) wcscpy(wtemp, wline);
			}
		}
		if (*wtemp) {
			n = wcslen(wtemp);
			r = wcstombs(temp, wtemp, n * MB_LEN_MAX);
			if (r == (size_t)-1) {
				(void) fprintf(stderr,
			gettext("Invalid character in the menu definition.\n"));
				exit(1);
			}
			if (setitem(mp, temp)) {
				(void) fprintf(stderr, gettext(INTERR), prog);
				exit(1);
			}
		}
	}

	while (optind < argc) {
		if (setitem(mp, argv[optind++])) {
			(void) fprintf(stderr, gettext(INTERR), prog);
			exit(1);
		}
	}

	for (n = 0; n < ninvis; ) {
		if (setinvis(mp, invis[n++])) {
			(void) fprintf(stderr, gettext(INTERR), prog);
			exit(1);
		}
	}

	if (*prog == 'e') {
		ckindent = 0;
		ckitem_err(mp, error);
		exit(0);
	} else if (*prog == 'h') {
		ckindent = 0;
		ckitem_hlp(mp, help);
		exit(0);
	}

	if (max < 1) {
		mmax = mp->nchoices;
	} else {
		mmax = max;
	}

/*
 * if -o option is specified, mp->nchoices is 1, and if no invisible
 * item is specified, ckitem() will consume two entries of item,
 * even though 'max' is set to 1. So to take care of that problem, we
 * allocate one extra element for item
 */
	item = (char **)calloc(mmax+1, sizeof (char *));
	if (!item) {
		(void) fprintf(stderr,
			gettext("Not enough memory\n"));
		exit(1);
	}
	n = ckitem(mp, item, max, deflt, error, help, prompt);
	if (n == 3) {
		if (kpid > -2)
			(void) kill(kpid, signo);
		(void) puts("q");
	} else if (n == 0) {
		i = 0;
		while (item[i])
			(void) puts(item[i++]);
	}
	return (n);
}
