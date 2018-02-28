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
/*
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */
/*
 * Copyright (c) 2017, Joyent, Inc.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 *	date - with format capabilities and international flair
 */

#include	<locale.h>
#include	<fcntl.h>
#include	<langinfo.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<unistd.h>
#include	<sys/time.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<ctype.h>
#include	<errno.h>
#include	<utmpx.h>
#include	<tzfile.h>

#define	year_size(A)	((isleap(A)) ? 366 : 365)
static 	char	buf[BUFSIZ];
static	time_t	clock_val;
static  short	month_size[12] =
	{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static  struct  utmpx wtmpx[2] = {
	{"", "", OTIME_MSG, 0, OLD_TIME, 0, 0, 0},
	{"", "", NTIME_MSG, 0, NEW_TIME, 0, 0, 0}
	};
static char *usage =
	"usage:\tdate [-u] mmddHHMM[[cc]yy][.SS]\n"
	"\tdate [-Ru] [-r seconds | filename] [+format]\n"
	"\tdate -a [-]sss[.fff]\n";
static int uflag = 0;
static int Rflag = 0;
static int rflag = 0;

static int get_adj(char *, struct timeval *);
static int setdate(struct tm *, char *);
static void fmt_extensions(char *, size_t,
    const char *, const struct timespec *);

int
main(int argc, char **argv)
{
	struct tm *tp, tm;
	struct timeval tv;
	char *fmt, *eptr;
	char fmtbuf[BUFSIZ];
	int c, aflag = 0, illflag = 0;
	struct timespec ts;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "a:uRr:")) != EOF)
		switch (c) {
		case 'a':
			aflag++;
			if (get_adj(optarg, &tv) < 0) {
				(void) fprintf(stderr,
				    gettext("date: invalid argument -- %s\n"),
				    optarg);
				illflag++;
			}
			break;
		case 'u':
			uflag++;
			break;
		case 'R':
			Rflag++;
			break;
		case 'r':

			/*
			 * BSD originally used -r to specify a unix time. GNU
			 * used -r to specify a reference to a file. Now, like
			 * some BSDs we attempt to parse the time. If we can,
			 * then we use that, otherwise we fall back and treat it
			 * like GNU.
			 */
			rflag++;
			errno = 0;
			ts.tv_sec = strtol(optarg, &eptr, 0);
			if (errno == EINVAL || *eptr != '\0') {
				struct stat st;
				if (stat(optarg, &st) == 0) {
					ts.tv_sec = st.st_mtime;
				} else {
					(void) fprintf(stderr,
					    gettext("date: failed to get stat "
					    "information about %s: %s\n"),
					    optarg, strerror(errno));
					exit(1);
				}
			} else if (errno != 0) {
				(void) fprintf(stderr,
				    gettext("date: failed to parse -r "
				    "argument: %s\n"), optarg);
				exit(1);
			}
			break;
		default:
			illflag++;
		}

	argc -= optind;
	argv  = &argv[optind];

	/* -a is mutually exclusive with -u, -R, and -r */
	if (uflag && aflag)
		illflag++;
	if (Rflag && aflag)
		illflag++;
	if (rflag && aflag)
		illflag++;

	if (illflag) {
		(void) fprintf(stderr, gettext(usage));
		exit(1);
	}

	if (rflag == 0) {
		if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
			perror(gettext("date: Failed to obtain system time"));
			exit(1);
		}
	}
	clock_val = ts.tv_sec;

	if (aflag) {
		if (adjtime(&tv, 0) < 0) {
			perror(gettext("date: Failed to adjust date"));
			exit(1);
		}
		exit(0);
	}

	if (argc > 0) {
		if (*argv[0] == '+')
			fmt = &argv[0][1];
		else {
			if (setdate(localtime(&clock_val), argv[0])) {
				(void) fprintf(stderr, gettext(usage));
				exit(1);
			}
			fmt = nl_langinfo(_DATE_FMT);
		}
	} else if (Rflag) {
		fmt = "%a, %d %h %Y %H:%M:%S %z";
	} else
		fmt = nl_langinfo(_DATE_FMT);

	fmt_extensions(fmtbuf, sizeof (fmtbuf), fmt, &ts);

	if (uflag) {
		(void) putenv("TZ=GMT0");
		tzset();
		tp = gmtime(&clock_val);
	} else
		tp = localtime(&clock_val);
	(void) memcpy(&tm, tp, sizeof (struct tm));
	(void) strftime(buf, BUFSIZ, fmtbuf, &tm);

	(void) puts(buf);

	return (0);
}

int
setdate(struct tm *current_date, char *date)
{
	int	i;
	int	mm;
	int	hh;
	int	min;
	int	sec = 0;
	char	*secptr;
	int	yy;
	int	dd	= 0;
	int	minidx	= 6;
	int	len;
	int	dd_check;

	/*  Parse date string  */
	if ((secptr = strchr(date, '.')) != NULL && strlen(&secptr[1]) == 2 &&
	    isdigit(secptr[1]) && isdigit(secptr[2]) &&
	    (sec = atoi(&secptr[1])) >= 0 && sec < 60)
		secptr[0] = '\0';	/* eat decimal point only on success */

	len = strlen(date);

	for (i = 0; i < len; i++) {
		if (!isdigit(date[i])) {
			(void) fprintf(stderr,
			gettext("date: bad conversion\n"));
			exit(1);
		}
	}
	switch (strlen(date)) {
	case 12:
		yy = atoi(&date[8]);
		date[8] = '\0';
		break;
	case 10:
		/*
		 * The YY format has the following representation:
		 * 00-68 = 2000 thru 2068
		 * 69-99 = 1969 thru 1999
		 */
		if (atoi(&date[8]) <= 68) {
			yy = 1900 + (atoi(&date[8]) + 100);
		} else {
			yy = 1900 + atoi(&date[8]);
		}
		date[8] = '\0';
		break;
	case 8:
		yy = 1900 + current_date->tm_year;
		break;
	case 4:
		yy = 1900 + current_date->tm_year;
		mm = current_date->tm_mon + 1; 	/* tm_mon goes from 1 to 11 */
		dd = current_date->tm_mday;
		minidx = 2;
		break;
	default:
		(void) fprintf(stderr, gettext("date: bad conversion\n"));
		return (1);
	}

	min = atoi(&date[minidx]);
	date[minidx] = '\0';
	hh = atoi(&date[minidx-2]);
	date[minidx-2] = '\0';

	if (!dd) {
		/*
		 * if dd is 0 (not between 1 and 31), then
		 * read the value supplied by the user.
		 */
		dd = atoi(&date[2]);
		date[2] = '\0';
		mm = atoi(&date[0]);
	}

	if (hh == 24)
		hh = 0, dd++;

	/*  Validate date elements  */
	dd_check = 0;
	if (mm >= 1 && mm <= 12) {
		dd_check = month_size[mm - 1];	/* get days in this month */
		if (mm == 2 && isleap(yy))	/* adjust for leap year */
			dd_check++;
	}
	if (!((mm >= 1 && mm <= 12) && (dd >= 1 && dd <= dd_check) &&
	    (hh >= 0 && hh <= 23) && (min >= 0 && min <= 59))) {
		(void) fprintf(stderr, gettext("date: bad conversion\n"));
		return (1);
	}

	/*  Build date and time number  */
	for (clock_val = 0, i = 1970; i < yy; i++)
		clock_val += year_size(i);
	/*  Adjust for leap year  */
	if (isleap(yy) && mm >= 3)
		clock_val += 1;
	/*  Adjust for different month lengths  */
	while (--mm)
		clock_val += (time_t)month_size[mm - 1];
	/*  Load up the rest  */
	clock_val += (time_t)(dd - 1);
	clock_val *= 24;
	clock_val += (time_t)hh;
	clock_val *= 60;
	clock_val += (time_t)min;
	clock_val *= 60;
	clock_val += sec;

	if (!uflag) {
		/* convert to GMT assuming standard time */
		/* correction is made in localtime(3C) */

		/*
		 * call localtime to set up "timezone" variable applicable
		 * for clock_val time, to support Olson timezones which
		 * can allow timezone rules to change.
		 */
		(void) localtime(&clock_val);

		clock_val += (time_t)timezone;

		/* correct if daylight savings time in effect */

		if (localtime(&clock_val)->tm_isdst)
			clock_val = clock_val - (time_t)(timezone - altzone);
	}

	(void) time(&wtmpx[0].ut_xtime);
	if (stime(&clock_val) < 0) {
		perror("date");
		return (1);
	}
#if defined(i386)
	/* correct the kernel's "gmt_lag" and the PC's RTC */
	(void) system("/usr/sbin/rtc -c > /dev/null 2>&1");
#endif
	(void) time(&wtmpx[1].ut_xtime);
	(void) pututxline(&wtmpx[0]);
	(void) pututxline(&wtmpx[1]);
	(void) updwtmpx(WTMPX_FILE, &wtmpx[0]);
	(void) updwtmpx(WTMPX_FILE, &wtmpx[1]);
	return (0);
}

int
get_adj(char *cp, struct timeval *tp)
{
	register int mult;
	int sign;

	/* arg must be [-]sss[.fff] */

	tp->tv_sec = tp->tv_usec = 0;
	if (*cp == '-') {
		sign = -1;
		cp++;
	} else {
		sign = 1;
	}

	while (*cp >= '0' && *cp <= '9') {
		tp->tv_sec *= 10;
		tp->tv_sec += *cp++ - '0';
	}
	if (*cp == '.') {
		cp++;
		mult = 100000;
		while (*cp >= '0' && *cp <= '9') {
			tp->tv_usec += (*cp++ - '0') * mult;
			mult /= 10;
		}
	}
	/*
	 * if there's anything left in the string,
	 * the input was invalid.
	 */
	if (*cp) {
		return (-1);
	} else {
		tp->tv_sec *= sign;
		tp->tv_usec *= sign;
		return (0);
	}
}

/*
 * Extensions that cannot be interpreted by strftime are interpreted here.
 */
void
fmt_extensions(char *fmtbuf, size_t len,
    const char *fmt, const struct timespec *tsp)
{
	const char *p;
	char *q;

	for (p = fmt, q = fmtbuf; *p != '\0' && q < fmtbuf + len; ++p) {
		if (*p == '%') {
			switch (*(p + 1)) {
			case 'N':
				++p;
				q += snprintf(q, len - (q - fmtbuf),
				    "%09lu", tsp->tv_nsec);
				continue;
			}
		}
		*q++ = *p;
	}

	if (q < fmtbuf + len)
		*q = '\0';
	else
		fmtbuf[len - 1] = '\0';
}
