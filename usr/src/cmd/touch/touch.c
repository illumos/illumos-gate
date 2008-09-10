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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
static void parse_time(char *, timestruc_t *);
static void parse_datetime(char *, timestruc_t *);
static void timestruc_to_timeval(timestruc_t *, struct timeval *);

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
	int		fd;
	struct stat	stbuf;
	struct stat	prstbuf;
	struct timeval	times[2];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = basename(argv[0]);
	if (strcmp(myname, "settime") == NULL) {
		cflag++;
		stflag++;
		while ((optc = getopt(argc, argv, "f:")) != EOF)
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
			};
	} else
		while ((optc = getopt(argc, argv, "acfmr:t:")) != EOF)
			switch (optc) {
			case 'a':
				aflag++;
				usecurrenttime = 0;
				break;
			case 'c':
				cflag++;
				break;
			case 'f':	/* silently ignore for UCB compat */
				break;
			case 'm':
				mflag++;
				usecurrenttime = 0;
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

	argc -= optind;
	argv += optind;

	if ((argc < 1) || (rflag + tflag > 1))
		usage(stflag);

	if ((aflag == 0) && (mflag == 0)) {
		aflag = 1;
		mflag = 1;
	}

	/*
	 * If either -r or -t has been specified,
	 * use the specified time.
	 */
	timespecified = rflag || tflag;

	if (timespecified == 0) {
		if (argc >= 2 && isnumber(*argv) && (strlen(*argv) == 8 ||
		    strlen(*argv) == 10)) {
			/*
			 * time is specified as an operand.
			 * use it.
			 */
			parse_datetime(*argv++, &prstbuf.st_mtim);
			prstbuf.st_atim = prstbuf.st_mtim;
			usecurrenttime = 0;
			timespecified = 1;
			argc--;
		} else {
			/*
			 * no time information is specified.
			 * use the current time.
			 */
			(void) gettimeofday(times, NULL);
			times[1] = times[0];
		}
	}
	for (c = 0; c < argc; c++) {
		if (stat(argv[c], &stbuf)) {
			/*
			 * If stat failed for reasons other than EOVERFLOW or
			 * ENOENT, the file should not be created, since this
			 * can clobber the contents of an existing file.
			 */
			if (errno == EOVERFLOW) {
				if (aflag == 0 || mflag == 0) {
					(void) fprintf(stderr,
					    gettext("%s: %s: current timestamps"
					    " unavailable:\n%s"),
					    myname, argv[c], aflag > 0 ?
					    gettext("consider trying again"
					    " without -a option\n") :
					    gettext("consider trying again"
					    " without -m option\n"));
					status++;
					continue;
				}
				/*
				 * Since we have EOVERFLOW, we know the file
				 * exists. Since both atime and mtime are being
				 * changed to known values, we don't care that
				 * st_atime and st_mtime from the file aren't
				 * available.
				 */
			} else if (errno != ENOENT) {
				(void) fprintf(stderr,
				    gettext("%s: cannot stat %s: %s\n"),
				    myname, argv[c], strerror(errno));
				status++;
				continue;
			} else if (cflag) {
				continue;
			} else if ((fd = creat(argv[c],
			    (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)))
			    < 0) {
				(void) fprintf(stderr,
				    gettext("%s: cannot create %s: %s\n"),
				    myname, argv[c], strerror(errno));
				status++;
				continue;
			} else {
				(void) close(fd);
				if (stat(argv[c], &stbuf)) {
					(void) fprintf(stderr,
					    gettext("%s: cannot stat %s: %s\n"),
					    myname, argv[c], strerror(errno));
					status++;
					continue;
				}
			}
		}

		if (mflag == 0) {
			/* Keep the mtime of the file */
			timestruc_to_timeval(&stbuf.st_mtim, times + 1);
		} else {
			if (timespecified) {
				/* Set the specified time */
				timestruc_to_timeval(&prstbuf.st_mtim,
				    times + 1);
			}
			/* Otherwise, use the current time by gettimeofday */
		}

		if (aflag == 0) {
			/* Keep the atime of the file */
			timestruc_to_timeval(&stbuf.st_atim, times);
		} else {
			if (timespecified) {
				/* Set the specified time */
				timestruc_to_timeval(&prstbuf.st_atim, times);
			}
			/* Otherwise, use the current time by gettimeofday */
		}

		if (utimes(argv[c], (usecurrenttime) ? NULL : times)) {
			(void) fprintf(stderr,
			    gettext("%s: cannot change times on %s: %s\n"),
			    myname, argv[c], strerror(errno));
			status++;
			continue;
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
parse_time(char *t, timestruc_t *ts)
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
parse_datetime(char *t, timestruc_t *ts)
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
	if (settime)
		(void) fprintf(stderr, gettext(
		    "usage: %s [-f file] [mmddhhmm[yy]] file...\n"), myname);
	else
		(void) fprintf(stderr, gettext(
		    "usage: %s [-acm] [-r ref_file] file...\n"
		    "       %s [-acm] [MMDDhhmm[yy]] file...\n"
		    "       %s [-acm] [-t [[CC]YY]MMDDhhmm[.SS]] file...\n"),
		    myname, myname, myname);
	exit(2);
}

/*
 * nanoseconds are rounded off to microseconds by flooring.
 */
static void
timestruc_to_timeval(timestruc_t *ts, struct timeval *tv)
{
	tv->tv_sec = ts->tv_sec;
	tv->tv_usec = ts->tv_nsec / 1000;
}
