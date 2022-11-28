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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

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

#include "lint.h"
#include <mtlib.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include "libc.h"
#include "tsd.h"

#define	dysize(A) (((A)%4)? 365: 366)
#define	CBUFSIZ 26

static char *
ct_numb(char *cp, int n, char pad)
{
	cp++;
	if (n >= 10)
		*cp++ = (n / 10) % 10 + '0';
	else
		*cp++ = pad;
	*cp++ = n % 10 + '0';
	return (cp);
}

/*
 * POSIX.1c standard version of the function asctime_r.
 * User gets it via static asctime_r from the header file.
 */
char *
__posix_asctime_r(const struct tm *t, char *cbuf)
{
	char *cp;
	const char *ncp;
	const char *Date = "Day Mon 00 00:00:00 YYYY\n";
	const char *Day  = "SunMonTueWedThuFriSat";
	const char *Month = "JanFebMarAprMayJunJulAugSepOctNovDec";

	int year = t->tm_year + 1900;

	cp = cbuf;
	for (ncp = Date; (*cp++ = *ncp++) != '\0'; /* */)
		;
	ncp = Day + (3 * t->tm_wday);
	cp = cbuf;
	*cp++ = *ncp++;
	*cp++ = *ncp++;
	*cp++ = *ncp++;
	cp++;
	ncp = Month + (3 * t->tm_mon);
	*cp++ = *ncp++;
	*cp++ = *ncp++;
	*cp++ = *ncp++;
	cp = ct_numb(cp, t->tm_mday, ' ');
	cp = ct_numb(cp, t->tm_hour, '0');
	cp = ct_numb(cp, t->tm_min, '0');
	cp = ct_numb(cp, t->tm_sec, '0');

	if (year < 0 || year >= 10000) {
		/* Only positive, 4-digit years are supported */
		errno = EOVERFLOW;
		return (NULL);
	}
	cp = ct_numb(cp, year / 100, '0');
	cp--;
	(void) ct_numb(cp, year, '0');
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
	char *cbuf = tsdalloc(_T_CTIME, CBUFSIZ, NULL);
	struct tm *p;

	if (cbuf == NULL)
		return (NULL);
	p = localtime(t);
	if (p == NULL)
		return (NULL);
	return (__posix_asctime_r(p, cbuf));
}

char *
asctime(const struct tm *t)
{
	char *cbuf = tsdalloc(_T_CTIME, CBUFSIZ, NULL);

	if (cbuf == NULL)
		return (NULL);
	return (__posix_asctime_r(t, cbuf));
}
