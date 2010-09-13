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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Time routines, snagged from libc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <sys/types.h>
#include <sys/bootvfs.h>
#include <sys/salib.h>
#include <sys/promif.h>
#include <stdio.h>
#include <time.h>

#define	CBUFSIZ 26

static time_t	start_time, secs_since_boot;

const int	__year_lengths[2] = {
	DAYS_PER_NYEAR, DAYS_PER_LYEAR
};
const int	__mon_lengths[2][MONS_PER_YEAR] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

/*
 * Initializes our "clock" to the creation date of /timestamp, which is
 * made on the fly for us by the web server. Thereafter, time() will keep
 * time sort of up to date.
 */
void
init_boot_time(void)
{
	struct stat sb;

	if (start_time == 0) {
		if (stat("/timestamp", &sb) < 0)
			prom_panic("init_boot_time: cannot stat /timestamp");

		start_time = sb.st_ctim.tv_sec;
		secs_since_boot = prom_gettime() / 1000;
	}
}

/*
 * Time is crudely incremented.
 */
time_t
time(time_t *tloc)
{
	time_t	time_now;

	time_now = start_time + ((prom_gettime() / 1000) - secs_since_boot);

	if (tloc != NULL)
		*tloc = time_now;

	if (start_time == 0)
		return (0);
	else
		return (time_now);
}

struct tm *
gmtime(const time_t *clock)
{
	static struct tm	result;
	struct tm	*tmp;
	long		days;
	int		rem;
	long		y;
	long		newy;
	const int	*ip;

	tmp = &result;
	days = *clock / SECS_PER_DAY;
	rem = *clock % SECS_PER_DAY;
	while (rem < 0) {
		rem += SECS_PER_DAY;
		--days;
	}
	while (rem >= SECS_PER_DAY) {
		rem -= SECS_PER_DAY;
		++days;
	}
	tmp->tm_hour = (int)(rem / SECS_PER_HOUR);
	rem = rem % SECS_PER_HOUR;
	tmp->tm_min = (int)(rem / SECS_PER_MIN);
	tmp->tm_sec = (int)(rem % SECS_PER_MIN);
	tmp->tm_wday = (int)((EPOCH_WDAY + days) % DAYS_PER_WEEK);
	if (tmp->tm_wday < 0)
		tmp->tm_wday += DAYS_PER_WEEK;
	y = EPOCH_YEAR;

#define	LEAPS_THRU_END_OF(y)    ((y) / 4 - (y) / 100 + (y) / 400)

	while (days < 0 || days >= (long)__year_lengths[isleap(y)]) {
		newy = y + days / DAYS_PER_NYEAR;
		if (days < 0)
			--newy;
		days -= ((long)newy - (long)y) * DAYS_PER_NYEAR +
			LEAPS_THRU_END_OF(newy > 0 ? newy - 1L : newy) -
			LEAPS_THRU_END_OF(y > 0 ? y - 1L : y);
		y = newy;
	}

	tmp->tm_year = y - TM_YEAR_BASE;
	tmp->tm_yday = days;
	ip = __mon_lengths[isleap(y)];
	for (tmp->tm_mon = 0; days >= ip[tmp->tm_mon]; ++(tmp->tm_mon))
		days = days - ip[tmp->tm_mon];
	tmp->tm_mday = (days + 1);
	tmp->tm_isdst = 0;
	return (tmp);
}

/*
 * The standalone booter runs in GMT.
 */
struct tm *
localtime(const time_t *clock)
{
	return (gmtime(clock));
}

static char *
ct_numb(char *cp, int n)
{
	cp++;
	if (n >= 10)
		*cp++ = (n / 10) % 10 + '0';
	else
		*cp++ = ' ';		/* Pad with blanks */
	*cp++ = n % 10 + '0';
	return (cp);
}

char *
asctime(const struct tm *t)
{
	char *cp;
	const char *ncp;
	const int *tp;
	const char *Date = "Day Mon 00 00:00:00 1900\n";
	const char *Day  = "SunMonTueWedThuFriSat";
	const char *Month = "JanFebMarAprMayJunJulAugSepOctNovDec";
	static char cbuf[CBUFSIZ];

	cp = cbuf;
	for (ncp = Date; *cp++ = *ncp++; /* */);
	ncp = Day + (3 * t->tm_wday);
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
	cp = ct_numb(cp, *--tp + 100);
	cp = ct_numb(cp, *--tp + 100);
	--tp;
	cp = ct_numb(cp, *tp + 100);
	if (t->tm_year < 100) {
		/* Common case: "19" already in buffer */
		cp += 2;
	} else if (t->tm_year < 8100) {
		cp = ct_numb(cp, (1900 + t->tm_year) / 100);
		cp--;
	} else {
		/* Only 4-digit years are supported */
		errno = EOVERFLOW;
		return (NULL);
	}
	(void) ct_numb(cp, t->tm_year + 100);
	return (cbuf);
}

char *
ctime(const time_t *t)
{
	return (asctime(localtime(t)));
}
