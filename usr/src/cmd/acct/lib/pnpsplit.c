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
/*	  All Rights Reserved	*/


/*
 * pnpsplit splits interval into prime & nonprime portions
 * ONLY ROUTINE THAT KNOWS ABOUT HOLIDAYS AND DEFN OF PRIME/NONPRIME
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include "acctdef.h"
#include <time.h>
#include <ctype.h>

/*
 * validate that hours and minutes of prime/non-prime read in
 * from holidays file fall within proper boundaries.
 * Time is expected in the form and range of 0000-2400.
 */

static int	thisyear = 1970;	/* this is changed by holidays file */
static int	holidays[NHOLIDAYS];	/* holidays file day-of-year table */


static int day_tab[2][13] = {
	{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
	{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
};

/*
 *	prime(0) and nonprime(1) times during a day
 *	for BTL, prime time is 9AM to 5PM
 */
static struct hours {
	int	h_sec;		/* normally always zero */
	int	h_min;		/* initialized from holidays file (time%100) */
	int	h_hour;		/* initialized from holidays file (time/100) */
	long	h_type;		/* prime/nonprime of previous period */
} h[4];

/* the sec, min, hr of the day's end */
struct tm daysend = {
	.tm_sec = 0,
	.tm_min = 60,
	.tm_hour = 23
};

long tmsecs(struct tm *, struct tm *);

/*
 * split interval of length etime, starting at start into prime/nonprime
 * values, return as result
 * input values in seconds
 */
int
pnpsplit(long start, ulong_t etime, long result[2])
{
	struct tm cur, end, hours;
	time_t tcur, tend;
	long tmp;
	int sameday;
	struct hours *hp;

	/* once holidays file is read, this is zero */
	if(thisyear && (checkhol() == 0)) {
		return(0);
	}
	tcur = start;
	tend = start + etime;
	memcpy(&end, localtime(&tend), sizeof(end));
	result[PRIME] = 0;
	result[NONPRIME] = 0;

	while ( tcur < tend ) {	/* one iteration per day or part thereof */
		memcpy(&cur, localtime(&tcur), sizeof(cur));
		sameday = cur.tm_yday == end.tm_yday;
		if (ssh(&cur)) {	/* ssh:only NONPRIME */
			if (sameday) {
				result[NONPRIME] += tend-tcur;

				break;
			} else {
				tmp = tmsecs(&cur, &daysend);
				result[NONPRIME] += tmp;
				tcur += tmp;
			}
		} else {	/* working day, PRIME or NONPRIME */
			for (hp = h; tmless(hp, &cur); hp++);
			for (; hp->h_sec >= 0; hp++) {
				if (sameday && tmless(&end, hp)) {
			/* WHCC mod, change from = to +=   3/6/86   Paul */
					result[hp->h_type] += tend-tcur;
					tcur = tend;
					break;	/* all done */
				} else {	/* time to next PRIME /NONPRIME change */
					hours.tm_sec = hp->h_sec;
					hours.tm_min = hp->h_min;
					hours.tm_hour = hp->h_hour;
					tmp = tmsecs(&cur, &hours);
					result[hp->h_type] += tmp;
					tcur += tmp;
					cur.tm_sec = hp->h_sec;
					cur.tm_min = hp->h_min;
					cur.tm_hour = hp->h_hour;
				}
			}
		}
	}
	return(1);
}

/*
 *	Starting day after Christmas, complain if holidays not yet updated.
 *	This code is only executed once per program invocation.
 */
int
checkhol(void)
{
	struct tm *tp;
	time_t t;

	if(inithol() == 0) {
		fprintf(stderr, "pnpsplit: holidays table setup failed\n");
		thisyear = 0;
		holidays[0] = -1;
		return(0);
	}
	time(&t);
	tp = localtime(&t);
	tp->tm_year += 1900;
	if ((tp->tm_year == thisyear && tp->tm_yday > 359)
		|| tp->tm_year > thisyear)
		fprintf(stderr,
			"***UPDATE %s WITH NEW HOLIDAYS***\n", HOLFILE);
	thisyear = 0;	/* checkhol() will not be called again */
	return(1);
}

/*
 * ssh returns 1 if Sat, Sun, or Holiday
 */
int
ssh(struct tm *ltp)
{
	int i;

	if (ltp->tm_wday == 0 || ltp->tm_wday == 6)
		return(1);
	for (i = 0; holidays[i] >= 0; i++)
		if (ltp->tm_yday == holidays[i])
			return(1);
	return(0);
}

/*
 * inithol - read from an ascii file and initialize the "thisyear"
 * variable, the times that prime and non-prime start, and the
 * holidays array.
 */
int
inithol(void)
{
	FILE		*holptr;
	char		holbuf[128];
	int		line = 0,
			holindx = 0,
			errflag = 0;
	int		pstart, npstart;
	int		doy;	/* day of the year */
	int 		month, day;
	char		*c;

	if((holptr=fopen(HOLFILE, "r")) == NULL) {
		perror(HOLFILE);
		fclose(holptr);
		return(0);
	}
	while(fgets(holbuf, sizeof(holbuf), holptr) != NULL) {
		/* skip over blank lines and comments */
		if (holbuf[0] == '*')
			continue;

		for (c = holbuf; isspace(*c); c++)
			/* is a space */;

		if (*c == '\0')
			continue;

		else if(++line == 1) {	/* format: year p-start np-start */
			if(sscanf(holbuf, "%4d %4d %4d",
				&thisyear, &pstart, &npstart) != 3) {
				fprintf(stderr,
					"%s: bad {yr ptime nptime} conversion\n",
					HOLFILE);
				errflag++;
				break;
			}

			/* validate year */
			if(thisyear < 1970 || thisyear > 2037) {
				fprintf(stderr, "pnpsplit: invalid year: %d\n",
					thisyear);
				errflag++;
				break;
			}

			/* validate prime/nonprime hours */
			if((! okay(pstart)) || (! okay(npstart))) {
				fprintf(stderr,
					"pnpsplit: invalid p/np hours\n");
				errflag++;
				break;
			}

			/* Set up start of prime time; 2400 == 0000 */
			h[0].h_sec = 0;
			h[0].h_min = pstart%100;
			h[0].h_hour = (pstart/100==24) ? 0 : pstart/100;
			h[0].h_type = NONPRIME;

			/* Set up start of non-prime time; 2400 == 2360 */
			if ((npstart/100) == 24) {
				h[1].h_sec = 0;
				h[1].h_min = 60;
				h[1].h_hour = 23;
			} else {
				h[1].h_sec = 0;
				h[1].h_min = npstart % 100;
				h[1].h_hour = npstart / 100;
			}

			h[1].h_type = PRIME;

			/* This is the end of the day */
			h[2].h_sec = 0;
			h[2].h_min = 60;
			h[2].h_hour = 23;
			h[2].h_type = NONPRIME;

			/* The end of the array */
			h[3].h_sec = -1;

			continue;
		}
		else if(holindx >= NHOLIDAYS) {
			fprintf(stderr, "pnpsplit: too many holidays, ");
			fprintf(stderr, "recompile with larger NHOLIDAYS\n");
			errflag++;
			break;
		}

		/* Fill up holidays array from holidays file */
		sscanf(holbuf, "%d/%d	%*s %*s	%*[^\n]\n", &month, &day);
		if (month < 0 || month > 12) {
			fprintf(stderr, "pnpsplit: invalid month %d\n", month);
			errflag++;
			break;
		}
		if (day < 0 || day > 31) {
			fprintf(stderr, "pnpsplit: invalid day %d\n", day);
			errflag++;
			break;
		}
		doy = day_of_year(thisyear, month, day);
		holidays[holindx++] = (doy - 1);
	}
	fclose(holptr);
	if(!errflag && holindx < NHOLIDAYS) {
		holidays[holindx] = -1;
		return(1);
	}
	else
		return(0);
}

/*
 *	tmsecs returns number of seconds from t1 to t2,
 *	times expressed in localtime format.
 *	assumed that t1 <= t2, and are in same day.
 */

long
tmsecs(struct tm *t1, struct tm *t2)
{
	return((t2->tm_sec - t1->tm_sec) +
		60*(t2->tm_min - t1->tm_min) +
		3600L*(t2->tm_hour - t1->tm_hour));
}

/*
 *	return 1 if t1 earlier than t2 (times in localtime format)
 *	assumed that t1 and t2 are in same day
 */

int
tmless(struct tm *t1, struct tm *t2)
{
	if (t1->tm_hour != t2->tm_hour)
		return(t1->tm_hour < t2->tm_hour);
	if (t1->tm_min != t2->tm_min)
		return(t1->tm_min < t2->tm_min);
	return(t1->tm_sec < t2->tm_sec);
}

/* set day of year from month and day */

int
day_of_year(int year, int month, int day)
{
	int i, leap;

	leap = year%4 == 0 && year%100 || year%400 == 0;
	for (i = 1; i < month; i++)
		day += day_tab[leap][i];
	return(day);
}
