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
 * Copyright 1986-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * zdump 7.24
 * Taken from elsie.nci.nih.gov to replace the existing Solaris zdump,
 * which was based on an earlier version of the elsie code.
 *
 * For zdump 7.24, the following changes were made to the elsie code:
 *   locale/textdomain/messages to match existing Solaris style.
 *   Solaris verbose mode is documented to display the current time first.
 *   cstyle cleaned code.
 *   removed old locale/textdomain code.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* static char	elsieid[] = "@(#)zdump.c	7.28"; */

/*
 * This code has been made independent of the rest of the time
 * conversion package to increase confidence in the verification it provides.
 * You can use this code to help in verifying other implementations.
 */

#include "stdio.h"	/* for stdout, stderr, perror */
#include "string.h"	/* for strcpy */
#include "sys/types.h"	/* for time_t */
#include "time.h"	/* for struct tm */
#include "stdlib.h"	/* for exit, malloc, atoi */
#include "locale.h"	/* for setlocale, textdomain */
#include "libintl.h"
#include "tzfile.h"	/* for defines */

#ifndef MAX_STRING_LENGTH
#define	MAX_STRING_LENGTH	1024
#endif /* !defined MAX_STRING_LENGTH */

#ifndef TRUE
#define	TRUE		1
#endif /* !defined TRUE */

#ifndef FALSE
#define	FALSE		0
#endif /* !defined FALSE */

#ifndef INITIALIZE
#ifdef lint
#define	INITIALIZE(x)	((x) = 0)
#endif /* defined lint */
#ifndef lint
#define	INITIALIZE(x)
#endif /* !defined lint */
#endif /* !defined INITIALIZE */

extern char **	environ;

static char *	abbr(struct tm *);
static long	delta(struct tm *, struct tm *);
static time_t	hunt(char *, time_t, time_t);
static size_t	longest;
static char *	progname;
static void	show(char *, time_t, int);
static void	usage(char *);

int
main(argc, argv)
int	argc;
char *	argv[];
{
	register int		i;
	register int		c;
	register int		vflag;
	register char *		cutoff;
	register int		cutyear;
	register long		cuttime;
	char **			fakeenv;
	time_t			now;
	time_t			t;
	time_t			newt;
	time_t			hibit;
	struct tm		tm;
	struct tm		newtm;

	INITIALIZE(cuttime);

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];
	vflag = 0;
	cutoff = NULL;
	while ((c = getopt(argc, argv, "c:v")) == 'c' || c == 'v')
		if (c == 'v')
			vflag = 1;
		else	cutoff = optarg;
	if (c != EOF ||
		(optind == argc - 1 && strcmp(argv[optind], "=") == 0)) {
			usage(argv[0]);
			/* NOTREACHED */
	}
	if (cutoff != NULL) {
		int	y;

		cutyear = atoi(cutoff);
		cuttime = 0;
		for (y = EPOCH_YEAR; y < cutyear; ++y)
			cuttime += DAYSPERNYEAR + isleap(y);
		cuttime *= SECSPERHOUR * HOURSPERDAY;
	}
	(void) time(&now);
	longest = 0;
	for (i = optind; i < argc; ++i)
		if (strlen(argv[i]) > longest)
			longest = strlen(argv[i]);
	for (hibit = 1; (hibit << 1) != 0; hibit <<= 1)
		continue;
	{
		register int	from;
		register int	to;

		for (i = 0;  environ[i] != NULL;  ++i)
			continue;
		fakeenv = (char **) malloc((size_t) ((i + 2) *
			sizeof (*fakeenv)));
		if (fakeenv == NULL ||
			(fakeenv[0] = (char *) malloc(longest + 4)) == NULL) {
					(void) perror(progname);
					(void) exit(EXIT_FAILURE);
		}
		to = 0;
		(void) strcpy(fakeenv[to++], "TZ=");
		for (from = 0; environ[from] != NULL; ++from)
			if (strncmp(environ[from], "TZ=", 3) != 0)
				fakeenv[to++] = environ[from];
		fakeenv[to] = NULL;
		environ = fakeenv;
	}
	for (i = optind; i < argc; ++i) {
		static char	buf[MAX_STRING_LENGTH];

		(void) strcpy(&fakeenv[0][3], argv[i]);
		if (!vflag) {
			show(argv[i], now, FALSE);
			continue;
		}

#if defined(sun)
		/*
		 * We show the current time first, probably because we froze
		 * the behavior of zdump some time ago and then it got
		 * changed.
		 */
		show(argv[i], now, TRUE);
#endif

		/*
		 * Get lowest value of t.
		 */
		t = hibit;
		if (t > 0)		/* time_t is unsigned */
			t = 0;
		show(argv[i], t, TRUE);
		t += SECSPERHOUR * HOURSPERDAY;
		show(argv[i], t, TRUE);
		tm = *localtime(&t);
		(void) strncpy(buf, abbr(&tm), (sizeof (buf)) - 1);
		for (;;) {
			if (cutoff != NULL && t >= cuttime)
				break;
			newt = t + SECSPERHOUR * 12;
			if (cutoff != NULL && newt >= cuttime)
				break;
			if (newt <= t)
				break;
			newtm = *localtime(&newt);
			if (delta(&newtm, &tm) != (newt - t) ||
				newtm.tm_isdst != tm.tm_isdst ||
				strcmp(abbr(&newtm), buf) != 0) {
					newt = hunt(argv[i], t, newt);
					newtm = *localtime(&newt);
					(void) strncpy(buf, abbr(&newtm),
						(sizeof (buf)) - 1);
			}
			t = newt;
			tm = newtm;
		}
		/*
		 * Get highest value of t.
		 */
		t = ~((time_t) 0);
		if (t < 0)		/* time_t is signed */
			t &= ~hibit;
#if defined(sun)
		show(argv[i], t, TRUE);
		t -= SECSPERHOUR * HOURSPERDAY;
		show(argv[i], t, TRUE);
#else /* !defined(sun) */
		t -= SECSPERHOUR * HOURSPERDAY;
		show(argv[i], t, TRUE);
		t += SECSPERHOUR * HOURSPERDAY;
		show(argv[i], t, TRUE);
#endif /* !defined(sun) */
	}
	if (fflush(stdout) || ferror(stdout)) {
		(void) fprintf(stderr, gettext(
		    "%s: Error writing standard output "), argv[0]);
		(void) perror(gettext("standard output"));
		usage(argv[0]);
	}
	return (EXIT_SUCCESS);
}

static time_t
hunt(name, lot, hit)
char *	name;
time_t	lot;
time_t	hit;
{
	time_t		t;
	struct tm	lotm;
	struct tm	tm;
	static char	loab[MAX_STRING_LENGTH];

	lotm = *localtime(&lot);
	(void) strncpy(loab, abbr(&lotm), (sizeof (loab)) - 1);
	while ((hit - lot) >= 2) {
		t = lot / 2 + hit / 2;
		if (t <= lot)
			++t;
		else if (t >= hit)
			--t;
		tm = *localtime(&t);
		if (delta(&tm, &lotm) == (t - lot) &&
			tm.tm_isdst == lotm.tm_isdst &&
			strcmp(abbr(&tm), loab) == 0) {
				lot = t;
				lotm = tm;
		} else	hit = t;
	}
	show(name, lot, TRUE);
	show(name, hit, TRUE);
	return (hit);
}

/*
 * Thanks to Paul Eggert (eggert@twinsun.com) for logic used in delta.
 */

static long
delta(newp, oldp)
struct tm *	newp;
struct tm *	oldp;
{
	long	result;
	int	tmy;

	if (newp->tm_year < oldp->tm_year)
		return (-delta(oldp, newp));
	result = 0;
	for (tmy = oldp->tm_year; tmy < newp->tm_year; ++tmy)
		result += DAYSPERNYEAR + isleap(tmy + TM_YEAR_BASE);
	result += newp->tm_yday - oldp->tm_yday;
	result *= HOURSPERDAY;
	result += newp->tm_hour - oldp->tm_hour;
	result *= MINSPERHOUR;
	result += newp->tm_min - oldp->tm_min;
	result *= SECSPERMIN;
	result += newp->tm_sec - oldp->tm_sec;
	return (result);
}

static void
show(zone, t, v)
char *	zone;
time_t	t;
int	v;
{
	struct tm *	tmp;

	(void) printf("%-*s  ", (int)longest, zone);
	if (v)
		(void) printf("%.24s UTC = ", asctime(gmtime(&t)));
	tmp = localtime(&t);
	(void) printf("%.24s", asctime(tmp));
	if (*abbr(tmp) != '\0')
		(void) printf(" %s", abbr(tmp));
	if (v) {
		(void) printf(" isdst=%d", tmp->tm_isdst);
	}
	(void) printf("\n");
}

static char *
abbr(tmp)
struct tm *	tmp;
{
	register char *	result;
	static char	nada;

	if (tmp->tm_isdst != 0 && tmp->tm_isdst != 1)
		return (&nada);
	result = tzname[tmp->tm_isdst];
	return ((result == NULL) ? &nada : result);
}

static void
usage(char *progname)
{
	(void) fprintf(stderr, gettext(
	    "%s: [ -v ] [ -c cutoffyear ] [ zonename ... ]\n"), progname);
	(void) exit(EXIT_FAILURE);
	/* NOTREACHED */
}
