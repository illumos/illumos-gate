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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <libgen.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>
#include <sys/time.h>
#include <errno.h>

#define	BADTIME	"bad time specification"

static char	*myname;

static int isnumber(char *);
static int atoi_for2(char *);
static void usage(const int);
static void touchabort(const char *);
static void parse_datetime(char *, timespec_t *);
static void parse_time(char *, timespec_t *);
static void parse_timespec(char *, timespec_t *);

int
main(int argc, char *argv[])
{
	int c;

	int		aflag	= 0;
	int		cflag	= 0;
	int		rflag	= 0;
	int		mflag	= 0;
	int		tflag	= 0;
	int		stflag	= 0;
	int		status	= 0;
	int		usecurrenttime = 1;
	int		timespecified;
	int		optc;
	int		fd = -1;
	mode_t		cmode =
	    (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	struct stat	stbuf;
	struct stat	prstbuf;
	timespec_t	times[2];
	timespec_t	*tsp;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = basename(argv[0]);
	if (strcmp(myname, "settime") == 0) {
		cflag++;
		stflag++;
		while ((optc = getopt(argc, argv, "f:")) != EOF) {
			switch (optc) {
			case 'f':
				rflag++;
				usecurrenttime = 0;
				if (stat(optarg, &prstbuf) == -1) {
					(void) fprintf(stderr, "%s: ", myname);
					perror(optarg);
					return (2);
				}
				break;
			case '?':
				usage(stflag);
				break;
			}
		}
	} else {
		while ((optc = getopt(argc, argv, "acfmr:d:t:")) != EOF) {
			switch (optc) {
			case 'a':
				aflag++;
				break;
			case 'c':
				cflag++;
				break;
			case 'f':	/* silently ignore for UCB compat */
				break;
			case 'm':
				mflag++;
				break;
			case 'r':	/* same as settime's -f option */
				rflag++;
				usecurrenttime = 0;
				if (stat(optarg, &prstbuf) == -1) {
					(void) fprintf(stderr, "%s: ", myname);
					perror(optarg);
					return (2);
				}
				break;
			case 'd':
				tflag++;
				usecurrenttime = 0;
				parse_datetime(optarg, &prstbuf.st_mtim);
				prstbuf.st_atim = prstbuf.st_mtim;
				break;
			case 't':
				tflag++;
				usecurrenttime = 0;
				parse_time(optarg, &prstbuf.st_mtim);
				prstbuf.st_atim = prstbuf.st_mtim;
				break;
			case '?':
				usage(stflag);
				break;
			}
		}
	}

	argc -= optind;
	argv += optind;

	if ((argc < 1) || (rflag + tflag > 1))
		usage(stflag);

	if ((aflag == 0) && (mflag == 0)) {
		aflag = 1;
		mflag = 1;
	}
	if ((aflag && !mflag) || (mflag && !aflag))
		usecurrenttime = 0;

	/*
	 * If -r, -t or -d has been specified,
	 * use the specified time.
	 */
	timespecified = (rflag | tflag);

	if (timespecified == 0 && argc >= 2 && isnumber(*argv) &&
	    (strlen(*argv) == 8 || strlen(*argv) == 10)) {
		/*
		 * time is specified as an operand; use it.
		 */
		parse_timespec(*argv++, &prstbuf.st_mtim);
		prstbuf.st_atim = prstbuf.st_mtim;
		usecurrenttime = 0;
		timespecified = 1;
		argc--;
	}

	for (c = 0; c < argc; c++) {
		if (stat(argv[c], &stbuf)) {
			/*
			 * If stat failed for reasons other than EOVERFLOW or
			 * ENOENT, the file should not be created, since this
			 * can clobber the contents of an existing file.
			 */
			if (errno == EOVERFLOW) {
				/*
				 * Since we have EOVERFLOW,
				 * we know the file exists.
				 */
				/* EMPTY */;
			} else if (errno != ENOENT) {
				(void) fprintf(stderr,
				    gettext("%s: cannot stat %s: %s\n"),
				    myname, argv[c], strerror(errno));
				status++;
				continue;
			} else if (cflag) {
				continue;
			} else if ((fd = creat(argv[c], cmode)) < 0) {
				(void) fprintf(stderr,
				    gettext("%s: cannot create %s: %s\n"),
				    myname, argv[c], strerror(errno));
				status++;
				continue;
			}
		}

		if (usecurrenttime) {
			tsp = NULL;
		} else {
			if (mflag == 0) {
				/* Keep the mtime of the file */
				times[1].tv_nsec = UTIME_OMIT;
			} else if (timespecified) {
				/* Set the specified time */
				times[1] = prstbuf.st_mtim;
			} else {
				/* Otherwise, use the current time */
				times[1].tv_nsec = UTIME_NOW;
			}

			if (aflag == 0) {
				/* Keep the atime of the file */
				times[0].tv_nsec = UTIME_OMIT;
			} else if (timespecified) {
				/* Set the specified time */
				times[0] = prstbuf.st_atim;
			} else {
				/* Otherwise, use the current time */
				times[0].tv_nsec = UTIME_NOW;
			}

			tsp = times;
		}

		if ((fd >= 0 && futimens(fd, tsp) != 0) ||
		    (fd < 0 && utimensat(AT_FDCWD, argv[c], tsp, 0) != 0)) {
			(void) fprintf(stderr,
			    gettext("%s: cannot change times on %s: %s\n"),
			    myname, argv[c], strerror(errno));
			status++;
		}
		if (fd >= 0) {
			(void) close(fd);
			fd = -1;
		}
	}
	return (status);
}

static int
isnumber(char *s)
{
	int c;

	while ((c = *s++) != '\0')
		if (!isdigit(c))
			return (0);
	return (1);
}

static void
parse_datetime(char *t, timespec_t *ts)
{
	char		date[64];
	char		*year;
	char		*month;
	char		*day;
	char		*hour;
	char		*minute;
	char		*second;
	char		*fraction;
	int		utc = 0;
	char		*p;
	time_t		when;
	int		nanoseconds;
	struct tm	tm;

	/*
	 * The date string has the format (defined by the touch(1) spec):
	 *	YYYY-MM-DDThh:mm:SS[.frac][tz]
	 *	YYYY-MM-DDThh:mm:SS[,frac][tz]
	 * T is either the literal 'T' or is a space character.
	 * tz is either empty (local time) or the literal 'Z' (UTC).
	 * All other fields are strings of digits.
	 */

	/*
	 * Make a copy of the date string so it can be tokenized.
	 */
	if (strlcpy(date, t, sizeof (date)) >= sizeof (date))
		touchabort(BADTIME);

	/* deal with the optional trailing 'Z' first */
	p = date + strlen(date) - 1;
	if (*p == 'Z') {
		utc = 1;
		*p = '\0';
	}

	/* break out the component tokens */
	p = date;
	year = strsep(&p, "-");
	month = strsep(&p, "-");
	day = strsep(&p, "T ");
	hour = strsep(&p, ":");
	minute = strsep(&p, ":");
	second = strsep(&p, ".,");
	fraction = p;

	/* verify the component tokens */
	if (year == NULL || strlen(year) < 4 || !isnumber(year) ||
	    month == NULL || strlen(month) != 2 || !isnumber(month) ||
	    day == NULL || strlen(day) != 2 || !isnumber(day) ||
	    hour == NULL || strlen(hour) != 2 || !isnumber(hour) ||
	    minute == NULL || strlen(minute) != 2 || !isnumber(minute) ||
	    second == NULL || strlen(second) != 2 || !isnumber(second) ||
	    (fraction != NULL && (*fraction == '\0' || !isnumber(fraction))))
		touchabort(BADTIME);

	(void) memset(&tm, 0, sizeof (struct tm));

	tm.tm_year = atoi(year) - 1900;
	tm.tm_mon = atoi(month) - 1;
	tm.tm_mday = atoi(day);
	tm.tm_hour = atoi(hour);
	tm.tm_min = atoi(minute);
	tm.tm_sec = atoi(second);
	if (utc) {
		(void) setenv("TZ", "GMT0", 1);
		tzset();
	}

	errno = 0;
	if ((when = mktime(&tm)) == -1 && errno != 0)
		touchabort(BADTIME);
	if (tm.tm_isdst)
		when -= (timezone - altzone);

	if (fraction == NULL) {
		nanoseconds = 0;
	} else {
		/* truncate beyond 9 digits (nanoseconds) */
		if (strlen(fraction) > 9)
			fraction[9] = '\0';
		nanoseconds = atoi(fraction);

		switch (strlen(fraction)) {
		case 1:
			nanoseconds *= 100000000;
			break;
		case 2:
			nanoseconds *= 10000000;
			break;
		case 3:
			nanoseconds *= 1000000;
			break;
		case 4:
			nanoseconds *= 100000;
			break;
		case 5:
			nanoseconds *= 10000;
			break;
		case 6:
			nanoseconds *= 1000;
			break;
		case 7:
			nanoseconds *= 100;
			break;
		case 8:
			nanoseconds *= 10;
			break;
		case 9:
			break;
		}
	}

	ts->tv_sec = when;
	ts->tv_nsec = nanoseconds;
}

static void
parse_time(char *t, timespec_t *ts)
{
	int		century = 0;
	int		seconds = 0;
	char		*p;
	time_t		when;
	struct tm	tm;

	/*
	 * time in the following format (defined by the touch(1) spec):
	 *	[[CC]YY]MMDDhhmm[.SS]
	 */
	if ((p = strchr(t, '.')) != NULL) {
		if (strchr(p+1, '.') != NULL)
			touchabort(BADTIME);
		seconds = atoi_for2(p+1);
		*p = '\0';
	}

	(void) memset(&tm, 0, sizeof (struct tm));
	when = time(0);
	tm.tm_year = localtime(&when)->tm_year;

	switch (strlen(t)) {
		case 12:	/* CCYYMMDDhhmm */
			century = atoi_for2(t);
			t += 2;
			/* FALLTHROUGH */
		case 10:	/* YYMMDDhhmm */
			tm.tm_year = atoi_for2(t);
			t += 2;
			if (century == 0) {
				if (tm.tm_year < 69)
					tm.tm_year += 100;
			} else
				tm.tm_year += (century - 19) * 100;
			/* FALLTHROUGH */
		case 8:		/* MMDDhhmm */
			tm.tm_mon = atoi_for2(t) - 1;
			t += 2;
			tm.tm_mday = atoi_for2(t);
			t += 2;
			tm.tm_hour = atoi_for2(t);
			t += 2;
			tm.tm_min = atoi_for2(t);
			tm.tm_sec = seconds;
			break;
		default:
			touchabort(BADTIME);
	}

	if ((when = mktime(&tm)) == -1)
		touchabort(BADTIME);
	if (tm.tm_isdst)
		when -= (timezone-altzone);

	ts->tv_sec = when;
	ts->tv_nsec = 0;
}

static void
parse_timespec(char *t, timespec_t *ts)
{
	time_t		when;
	struct tm	tm;

	/*
	 * time in the following format (defined by the touch(1) spec):
	 *	MMDDhhmm[yy]
	 */

	(void) memset(&tm, 0, sizeof (struct tm));
	when = time(0);
	tm.tm_year = localtime(&when)->tm_year;

	switch (strlen(t)) {
		case 10:	/* MMDDhhmmyy */
			tm.tm_year = atoi_for2(t+8);
			if (tm.tm_year < 69)
				tm.tm_year += 100;
			/* FALLTHROUGH */
		case 8:		/* MMDDhhmm */
			tm.tm_mon = atoi_for2(t) - 1;
			t += 2;
			tm.tm_mday = atoi_for2(t);
			t += 2;
			tm.tm_hour = atoi_for2(t);
			t += 2;
			tm.tm_min = atoi_for2(t);
			break;
		default:
			touchabort(BADTIME);
	}

	if ((when = mktime(&tm)) == -1)
		touchabort(BADTIME);
	if (tm.tm_isdst)
		when -= (timezone - altzone);

	ts->tv_sec = when;
	ts->tv_nsec = 0;
}

static int
atoi_for2(char *p)
{
	int value;

	value = (*p - '0') * 10 + *(p+1) - '0';
	if ((value < 0) || (value > 99))
		touchabort(BADTIME);
	return (value);
}

static void
touchabort(const char *message)
{
	(void) fprintf(stderr, "%s: %s\n", myname, gettext(message));
	exit(1);
}

static void
usage(const int settime)
{
	if (settime) {
		(void) fprintf(stderr, gettext(
		    "usage: %s [-f file] [mmddhhmm[yy]] file...\n"), myname);
		exit(2);
	}
	(void) fprintf(stderr, gettext(
	    "usage: %s [-acm] [-r ref_file] file...\n"
	    "       %s [-acm] [-t [[CC]YY]MMDDhhmm[.SS]] file...\n"
	    "       %s [-acm] [-d YYYY-MM-DDThh:mm:SS[.frac][Z]] file...\n"
	    "       %s [-acm] [-d YYYY-MM-DDThh:mm:SS[,frac][Z]] file...\n"
	    "       %s [-acm] [MMDDhhmm[yy]] file...\n"),
	    myname, myname, myname, myname, myname);
	exit(2);
}
