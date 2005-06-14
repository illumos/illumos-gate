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
 * Copyright (c) 1987-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Time management functions for auditreduce.
 */

#include "auditr.h"
#include <locale.h>
#include <libintl.h>

int	derive_date(char *, struct tm *);
void	derive_str(time_t, char *);
int	parse_time(char *, int);
time_t	tm_to_secs(struct tm *);

static int	check_time(struct tm *);
static int	days_in_year(int);
static char *do_invalid(void);
static time_t	local_to_gm(struct tm *);

static char *invalid_inter = NULL;

/*
 * Array of days per month.
 */
static int	days_month[] = {
		31, 28, 31, 30, 31, 30,
		31, 31, 30, 31, 30, 31 };

char *
do_invalid(void)
{
	if (invalid_inter == NULL)
		invalid_inter = gettext("invalid date/time format -");
	return (invalid_inter);
}

/*
 * .func	local_to_gm - local time to gm time.
 * .desc	Convert a local time to Greenwhich Mean Time.
 *	The local time is in the struct tm (time.h) format, which
 *	is easily got from an ASCII input format (10:30:33 Jan 3, 1983).
 *	It works by assuming that the given local time is a GMT time and
 *	then asking the system for the corresponding local time. It then
 *	takes the difference between those two as the correction for
 * 	time zones and daylight savings time. This is accurate unless
 *	the time the user asked for is near a DST switch. Then a
 *	correction is applied - it is assumed that if we can produce
 *	a GMT that, when run through localtime(), is equivalent to the
 *	user's original input, we have an accurate GMT. The applied
 *	correction simply adjusts the GMT by the amount that the derived
 *	localtime was off. See?
 *	It should be noted that when there is DST there is one local hour
 *	a year when time occurs twice (in the fall) and one local hour a
 *	year when time never occurs (in the spring).
 *	memcpy() is used because the calls to gmtime() and localtime()
 *	return pointers to static structures that are overwritten at each
 *	call.
 * .call	ret = local_to_gm(tme).
 * .arg	tme	- ptr to struct tm (see time.h) containing local time.
 * .ret	time_t	- seconds since epoch of equivalent GMT.
 */
time_t
local_to_gm(struct tm *tme)
{
	time_t secs, gsecs, lsecs, save_gsecs;
	time_t r1secs, r2secs;
	struct tm ltime, gtime;

	/*
	 * Get the input time in local and gmtime assuming the input
	 * was GMT (which it probably wasn't).
	 */
	r1secs = secs = tm_to_secs(tme);
	(void) memcpy((void *)&gtime, (void *)gmtime(&secs), sizeof (gtime));
	(void) memcpy((void *)&ltime, (void *)localtime(&secs), sizeof (ltime));

	/*
	 * Get the local and gmtime in seconds, from the above tm structures.
	 * Calculate difference between local and GMT.
	 */
	gsecs = tm_to_secs(&gtime);
	lsecs = tm_to_secs(&ltime);
	secs = lsecs - gsecs;
	gsecs -= secs;
	(void) memcpy((void *)&ltime, (void *)localtime(&gsecs),
	    sizeof (ltime));

	/*
	 * Now get a computed local time from the computed gmtime.
	 */
	save_gsecs = gsecs;
	r2secs = tm_to_secs(&ltime);

	/*
	 * If the user given local time is != computed local time then
	 * we need to try a correction.
	 */
	if (r1secs != r2secs) {
		/*
		 * Use the difference between give localtime and computed
		 * localtime as our correction.
		 */
		if (r2secs > r1secs) {
			gsecs -= r2secs - r1secs;
		} else {
			gsecs += r1secs - r2secs;
		}
		/*
		 * And try the comparison again...
		 */
		(void) memcpy((void *)&ltime, (void *)localtime(&gsecs),
		    sizeof (ltime));
		r2secs = tm_to_secs(&ltime);
		/*
		 * If the correction fails then we are on a DST line
		 * and the user-given local time never happened.
		 * Do the best we can.
		 */
		if (r1secs != r2secs) {
			gsecs = save_gsecs;
		}
	}
	return (gsecs);
}


/*
 * .func	tm_to_secs - convert to seconds.
 * .desc	Convert a tm time structure (time.h) into seconds since
 *	Jan 1, 1970 00:00:00. The time is assumed to be GMT and
 *	so no daylight savings time correction is applied. That
 *	is left up to the system calls (localtime(), gmtime()).
 * .call	ret = tm_to_secs(tme).
 * .arg	tme	- ptr to tm structure.
 * .ret	time_t	- number of seconds.
 */
time_t
tm_to_secs(struct tm *tme)
{
	int	leap_year = FALSE;
	int	days = 0;
	time_t num_sec = 0;

	int	sec = tme->tm_sec;
	int	min = tme->tm_min;
	int	hour = tme->tm_hour;
	int	day = tme->tm_mday;
	int	month = tme->tm_mon;
	int	year = tme->tm_year + 1900;

	if (days_in_year(year) == 366)
		leap_year = TRUE;

	while (year > 1970) {
		num_sec += days_in_year(--year) * 24 * 60 * 60;
	}
	while (month > 0) {
		days = days_month[--month];
		if (leap_year && month == 1) {	/* 1 is February */
			days++;
		}
		num_sec += days * 24 * 60 * 60;
	}
	num_sec += --day * 24 * 60 * 60;
	num_sec += hour * 60 * 60;
	num_sec += min * 60;
	num_sec += sec;

	return (num_sec);
}


/*
 * .func	check_time - check tm structure.
 * .desc	Check the time in a tm structure to see if all of the fields
 *	are within range.
 * .call	err = check_time(tme).
 * .arg	tme	- ptr to struct tm (see time.h).
 * .ret	0	- time is ok.
 * .ret	-1	- time had a problem (description in error_str).
 */
int
check_time(struct tm *tme)
{
	error_str = NULL;

	if (tme->tm_sec < 0 || tme->tm_sec > 59) {
		(void) sprintf(errbuf,
		    gettext("seconds out of range (%d)"), tme->tm_sec + 1);
		error_str = errbuf;
	} else if (tme->tm_min < 0 || tme->tm_min > 59) {
		(void) sprintf(errbuf,
		    gettext("minutes out of range (%d)"), tme->tm_min + 1);
		error_str = errbuf;
	} else if (tme->tm_hour < 0 || tme->tm_hour > 23) {
		(void) sprintf(errbuf,
		    gettext("hours out of range (%d)"), tme->tm_hour + 1);
		error_str = errbuf;
	} else if (tme->tm_mon < 0 || tme->tm_mon > 11) {
		(void) sprintf(errbuf,
		    gettext("months out of range (%d)"), tme->tm_mon + 1);
		error_str = errbuf;
	} else if (tme->tm_year < 0) {
		(void) sprintf(errbuf,
		    gettext("years out of range (%d)"), tme->tm_year);
		error_str = errbuf;
	} else if (tme->tm_mday < 1 || tme->tm_mday > days_month[tme->tm_mon]) {
		if (!(days_in_year(tme->tm_year + 1900) == 366 &&
			tme->tm_mon == 1 &&
			tme->tm_mday == 29)) { /* leap year and February */
			(void) sprintf(errbuf,
			    gettext("days out of range (%d)"), tme->tm_mday);
			error_str = errbuf;
		}
	} else if (tme->tm_wday < 0 || tme->tm_wday > 6) {
		(void) sprintf(errbuf,
		    gettext("weekday out of range (%d)"), tme->tm_wday);
		error_str = errbuf;
	} else if (tme->tm_yday < 0 || tme->tm_yday > 365) {
		(void) sprintf(errbuf,
		    gettext("day of year out of range (%d)"), tme->tm_yday);
		error_str = errbuf;
	}

	if (error_str == NULL)
		return (0);
	else
		return (-1);
}


/*
 * .func parse_time.
 * .desc Parse a user time from the command line. The user time is assumed
 *	to be local time.
 *	Supported formats currently are:
 *	1. 	+xt	- where x is a number and t is a type.
 *		types are - 's' second, 'm' minute, 'h' hour, and 'd' day.
 *	2. 	yymmdd - yyyymmdd.
 *		yymmddhh - yyyymmddhh.
 *		yymmddhhmm - yyyymmddhhmm.
 *		yymmddhhmmss - yyyymmddhhmmss.
 * .call	err = parse_time(str, opt).
 * .arg	str	- ptr to user input string.
 * .arg	opt	- time option being processed.
 * .ret	0	- succesful.
 * .ret	-1	- failure (error message in error_str).
 */
int
parse_time(char *str, int opt)
{
	int	ret, len, factor;
	char	*strxx;
	long	lnum;
	struct tm thentime;

	len = strlen(str);
	/*
	 * If the strlen < 6 then in the "-b +2d" type of format.
	 */
	if (len < 6) {
		if (*str++ != '+') {
			(void) sprintf(errbuf, gettext("%s needs '+' (%s)"),
			    do_invalid(), str);
			error_str = errbuf;
			return (-1);
		}
		if (opt != 'b') {
			(void) sprintf(errbuf,
			    gettext("%s only allowed with 'b' option (%s)"),
			    do_invalid(), str);
			error_str = errbuf;
			return (-1);
		}
		if (m_after == 0) {
			(void) sprintf(errbuf,
			    gettext("must have -a to use -b +nx form (%s)"),
			    str);
			error_str = errbuf;
			return (-1);
		}
		/*
		 * Find out what type of offset it is - 's' 'm' 'h' or 'd'.
		 * Make sure that the offset is all numbers.
		 */
		if ((strxx = strpbrk(str, "dhms")) == NULL) {
			(void) sprintf(errbuf,
			    gettext("%s needs 'd', 'h', 'm', or 's' (%s)"),
			    do_invalid(), str);
			error_str = errbuf;
			return (-1);
		} else {
			ret = *strxx;
			*strxx = '\0';
		}
		if (strlen(str) != strspn(str, "0123456789")) {
			(void) sprintf(errbuf,
			    gettext("%s non-numeric offset (%s)"),
			    do_invalid(), str);
			error_str = errbuf;
			return (-1);
		}
		factor = 1;			/* seconds is default */
		if (ret == 'd')			/* days */
			factor = 24 * 60 * 60;
		else if (ret == 'h')		/* hours */
			factor = 60 * 60;
		else if (ret == 'm')		/* minutes */
			factor = 60;
		lnum = atol(str);
		m_before = m_after + (lnum * factor);
		return (0);
	}
	/*
	 * Must be a specific date/time format.
	 */
	if (derive_date(str, &thentime))
		return (-1);
	/*
	 * For 'd' option clear out the hh:mm:ss to get to the start of the day.
	 * Then add one day's worth of seconds to get the 'b' time.
	 */
	if (opt == 'd') {
		thentime.tm_sec = 0;
		thentime.tm_min = 0;
		thentime.tm_hour = 0;
		m_after = local_to_gm(&thentime);
		m_before = m_after + (24 * 60 * 60);
	} else if (opt == 'a') {
		m_after = local_to_gm(&thentime);
	} else if (opt == 'b') {
		m_before = local_to_gm(&thentime);
	}
	return (0);
}


/*
 * .func	derive_date.
 * .desc	Derive a date/time structure (tm) from a string.
 *	String is in one of these formats:
 *	[yy]yymmddhhmmss
 *	[yy]yymmddhhmm
 *	[yy]yymmddhh
 *	[yy]yymmdd
 * .call	ret = derive_date(str, tme).
 * .arg	str	- ptr to input string.
 * .arg	tme	- ptr to tm structure (time.h).
 * .ret	0	- no errors in string.
 * .ret	-1	- errors in string (description in error_str).
 */
int
derive_date(char *str, struct tm *tme)
{
	char	*strs;
	char	*digits = "0123456789";
	size_t	len;
	struct tm nowtime;

	len = strlen(str);

	if (len != strspn(str, digits)) {
		(void) sprintf(errbuf, gettext("%s not all digits (%s)"),
		    do_invalid(), str);
		error_str = errbuf;
		return (-1);
	}
	if (len % 2) {
		(void) sprintf(errbuf, gettext("%s odd number of digits (%s)"),
		    do_invalid(), str);
		error_str = errbuf;
		return (-1);
	}
	/*
	 * May need larger string storage to add '19' or '20'.
	 */
	strs = (char *)a_calloc(1, len + 4);

	/*
	 * Get current time to see what century it is.
	 */
	(void) memcpy((char *)&nowtime, (char *)gmtime(&time_now),
	    sizeof (nowtime));
	/*
	 * If the year does not begin with '19' or '20', then report
	 * an error and abort.
	 */
	if ((str[0] != '1' || str[1] != '9') &&		/* 19XX */
	    (str[0] != '2' || str[1] != '0')) {		/* 20XX */
		(void) sprintf(errbuf, gettext("invalid year (%c%c%c%c)"),
		    str[0], str[1], str[2], str[3]);
		error_str = errbuf;
		free(strs);
		return (-1);
	}

	len = strlen(str);			/* may have changed */
	if (len < 8 || len > 14) {
		(void) sprintf(errbuf,
			gettext("invalid date/time length (%s)"), str);
		error_str = errbuf;
		free(strs);
		return (-1);
	}
	/* unspecified values go to 0 */
	(void) memset((void *) tme, 0, (size_t)sizeof (*tme));
	(void) strncpy(strs, str, 4);
	strs[4] = '\0';
	tme->tm_year = atoi(strs) - 1900;	/* get the year */
	(void) strncpy(strs, str + 4, 2);
	strs[2] = '\0';
	tme->tm_mon = atoi(strs) - 1;		/* get months */
	(void) strncpy(strs, str + 6, 2);
	strs[2] = '\0';
	tme->tm_mday = atoi(strs);		/* get days */
	if (len >= 10) {			/* yyyymmddhh */
		(void) strncpy(strs, str + 8, 2);
		strs[2] = '\0';
		tme->tm_hour = atoi(strs);	/* get hours */
	}
	if (len >= 12) {			/* yyyymmddhhmm */
		(void) strncpy(strs, str + 10, 2);
		strs[2] = '\0';
		tme->tm_min = atoi(strs);	/* get minutes */
	}
	if (len >= 14) {			/* yyyymmddhhmmss */
		(void) strncpy(strs, str + 12, 2);
		strs[2] = '\0';
		tme->tm_sec = atoi(strs);	/* get seconds */
	}
	free(strs);
	return (check_time(tme));		/* lastly check the ranges */
}


/*
 * .func	derive_str - derive string.
 * .desc	Derive a string representation of a time for a filename.
 *	The output is in the 14 character format yyyymmddhhmmss.
 * .call	derive_str(clock, buf).
 * .arg	clock	- seconds since epoch.
 * .arg	buf	- place to put resultant string.
 * .ret	void.
 */
void
derive_str(time_t clock, char *buf)
{
	struct tm gtime;

	(void) memcpy((void *) & gtime, (void *)gmtime(&clock), sizeof (gtime));

	(void) sprintf(buf, "%4d", gtime.tm_year + 1900);
	(void) sprintf(buf + 4,  "%.2d", gtime.tm_mon + 1);
	(void) sprintf(buf + 6,  "%.2d", gtime.tm_mday);
	(void) sprintf(buf + 8,  "%.2d", gtime.tm_hour);
	(void) sprintf(buf + 10, "%.2d", gtime.tm_min);
	(void) sprintf(buf + 12, "%.2d", gtime.tm_sec);
	buf[14] = '\0';
}


int
days_in_year(int year)
{
	if (isleap(year))
		return (366);

	return (365);
}
