/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * This localtime is a modified version of offtime from libc, which does not
 * bother to figure out the time zone from the kernel, from environment
 * variables, or from Unix files.
 */

#include <sys/types.h>
#include <sys/salib.h>
#include <tzfile.h>
#include <errno.h>

static int mon_lengths[2][MONSPERYEAR] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static int year_lengths[2] = {
	DAYSPERNYEAR, DAYSPERLYEAR
};

struct tm *
localtime(const time_t *clock)
{
	struct tm *tmp;
	long days;
	long rem;
	int y;
	int yleap;
	int *ip;
	static struct tm tm;

	tmp = &tm;
	days = *clock / SECSPERDAY;
	rem = *clock % SECSPERDAY;
	while (rem < 0) {
		rem += SECSPERDAY;
		--days;
	}
	while (rem >= SECSPERDAY) {
		rem -= SECSPERDAY;
		++days;
	}
	tmp->tm_hour = (int)(rem / SECSPERHOUR);
	rem = rem % SECSPERHOUR;
	tmp->tm_min = (int)(rem / SECSPERMIN);
	tmp->tm_sec = (int)(rem % SECSPERMIN);
	tmp->tm_wday = (int)((EPOCH_WDAY + days) % DAYSPERWEEK);
	if (tmp->tm_wday < 0)
		tmp->tm_wday += DAYSPERWEEK;
	y = EPOCH_YEAR;
	if (days >= 0) {
		for (;;) {
			yleap = isleap(y);
			if (days < (long)year_lengths[yleap])
				break;
			if (++y > 9999) {
				errno = EOVERFLOW;
				return (NULL);
			}
			days = days - (long)year_lengths[yleap];
		}
	} else {
		do {
			if (--y < 0) {
				errno = EOVERFLOW;
				return (NULL);
			}
			yleap = isleap(y);
			days = days + (long)year_lengths[yleap];
		} while (days < 0);
	}
	tmp->tm_year = y - TM_YEAR_BASE;
	tmp->tm_yday = (int)days;
	ip = mon_lengths[yleap];
	for (tmp->tm_mon = 0; days >= (long)ip[tmp->tm_mon]; ++(tmp->tm_mon))
		days = days - (long)ip[tmp->tm_mon];
	tmp->tm_mday = (int)(days + 1);
	tmp->tm_isdst = 0;

	return (tmp);
}

/*
 * So is ctime...
 */

/*
 * This routine converts time as follows.
 * The epoch is 0000 Jan 1 1970 GMT.
 * The argument time is in seconds since then.
 * The localtime(t) entry returns a pointer to an array
 * containing
 *  seconds (0-59)
 *  minutes (0-59)
 *  hours (0-23)
 *  day of month (1-31)
 *  month (0-11)
 *  year-1970
 *  weekday (0-6, Sun is 0)
 *  day of the year
 *  daylight savings flag
 *
 * The routine corrects for daylight saving
 * time and will work in any time zone provided
 * "timezone" is adjusted to the difference between
 * Greenwich and local standard time (measured in seconds).
 * In places like Michigan "daylight" must
 * be initialized to 0 to prevent the conversion
 * to daylight time.
 * There is a table which accounts for the peculiarities
 * undergone by daylight time in 1974-1975.
 *
 * The routine does not work
 * in Saudi Arabia which runs on Solar time.
 *
 * asctime(tvec)
 * where tvec is produced by localtime
 * returns a ptr to a character string
 * that has the ascii time in the form
 *	Thu Jan 01 00:00:00 1970\n\0
 *	01234567890123456789012345
 *	0	  1	    2
 *
 * ctime(t) just calls localtime, then asctime.
 *
 * tzset() looks for an environment variable named
 * TZ.
 * If the variable is present, it will set the external
 * variables "timezone", "altzone", "daylight", and "tzname"
 * appropriately. It is called by localtime, and
 * may also be called explicitly by the user.
 */



#define	dysize(A) (((A)%4)? 365: 366)
#define	CBUFSIZ 26

static char *ct_numb();

/*
 * POSIX.1c standard version of the function asctime_r.
 * User gets it via static asctime_r from the header file.
 */
char *
__posix_asctime_r(const struct tm *t, char *cbuf)
{
	const char *Date = "Day Mon 00 00:00:00 1900\n";
	const char *Day  = "SunMonTueWedThuFriSat";
	const char *Month = "JanFebMarAprMayJunJulAugSepOctNovDec";
	const char *ncp;
	const int *tp;
	char *cp;

	if (t == NULL)
		return (NULL);

	cp = cbuf;
	for (ncp = Date; *cp++ = *ncp++; /* */)
		;
	ncp = Day + (3*t->tm_wday);
	cp = cbuf;
	*cp++ = *ncp++;
	*cp++ = *ncp++;
	*cp++ = *ncp++;
	cp++;
	tp = &t->tm_mon;
	ncp = Month + ((*tp) * 3);
	*cp++ = *ncp++;
	*cp++ = *ncp++;
	*cp++ = *ncp++;
	cp = ct_numb(cp, *--tp);
	cp = ct_numb(cp, *--tp+100);
	cp = ct_numb(cp, *--tp+100);
	cp = ct_numb(cp, *--tp+100);
	if (t->tm_year > 9999) {
		errno = EOVERFLOW;
		return (NULL);
	} else {
		uint_t hun = 19 + (t->tm_year / 100);
		cp[1] = (hun / 10) + '0';
		cp[2] = (hun % 10) + '0';
	}
	cp += 2;
	cp = ct_numb(cp, t->tm_year+100);
	return (cbuf);
}

/*
 * POSIX.1c Draft-6 version of the function asctime_r.
 * It was implemented by Solaris 2.3.
 */
char *
asctime_r(const struct tm *t, char *cbuf, int buflen)
{
	if (buflen < CBUFSIZ) {
		errno = ERANGE;
		return (NULL);
	}
	return (__posix_asctime_r(t, cbuf));
}

char *
ctime(const time_t *t)
{
	return (asctime(localtime(t)));
}


char *
asctime(const struct tm *t)
{
	static char cbuf[CBUFSIZ];

	return (asctime_r(t, cbuf, CBUFSIZ));
}


static char *
ct_numb(char *cp, int n)
{
	cp++;
	if (n >= 10)
		*cp++ = (n/10)%10 + '0';
	else
		*cp++ = ' ';		/* Pad with blanks */
	*cp++ = n%10 + '0';
	return (cp);
}
