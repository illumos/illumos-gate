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

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef KERNEL
#define	KERNEL
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/types.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_label.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_node.h>

/*
 * Convert time between DOS formats:
 *	- years since 1980
 *	- months/days/hours/minutes/seconds, local TZ
 * and the UNIX format (seconds since 01/01/1970, 00:00:00 UT).
 *
 * Timezones are adjusted for via mount option arg (secondswest),
 * but daylight savings time corrections are not made. Calculated
 * time may therefore end up being wrong by an hour, but this:
 *	a) will happen as well if media is interchanged between
 *	   two DOS/Windows-based systems that use different
 *	   timezone settings
 *	b) is the best option we have unless we decide to put
 *	   a full ctime(3C) framework into the kernel, including
 *	   all conversion tables - AND keeping them current ...
 */

int pc_tvtopct(timestruc_t *, struct pctime *);
void pc_pcttotv(struct pctime *, int64_t *);

/*
 * Macros/Definitons required to convert between DOS-style and
 * UNIX-style time recording.
 * DOS year zero is 1980.
 */
static int daysinmonth[] =
	    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

#define	YEAR_ZERO	1980
#define	YZ_SECS	(((8 * 365) + (2 * 366)) * 86400)
#define	FAT_ENDOFTIME	\
	LE_16(23 << HOURSHIFT | 59 << MINSHIFT | (59/2) << SECSHIFT)
#define	FAT_ENDOFDATE	\
	LE_16(127 << YEARSHIFT | 12 << MONSHIFT | 31 << DAYSHIFT)
#define	leap_year(y) \
	(((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

#define	YEN	"\xc2\xa5"	/* Yen Sign UTF-8 character */
#define	LRO	"\xe2\x80\xad"	/* Left-To-Right Override UTF-8 character */
#define	RLO	"\xe2\x80\xae"	/* Right-To-Left Override UTF-8 character */

static int
days_in_year(int y)
{
	return (leap_year((y)) ? 366 : 365);
}

static int
days_in_month(int m, int y)
{
	if (m == 2 && leap_year(y))
		return (29);
	else
		return (daysinmonth[m-1]);
}

struct pcfs_args pc_tz; /* this is set by pcfs_mount */

/*
 * Convert time from UNIX to DOS format.
 * Return EOVERFLOW in case no valid DOS time representation
 * exists for the given UNIX time.
 */
int
pc_tvtopct(
	timestruc_t	*tvp,		/* UNIX time input */
	struct pctime *pctp)		/* pctime output */
{
	uint_t year, month, day, hour, min, sec;
	int64_t unixtime;

	unixtime = (int64_t)tvp->tv_sec;
	unixtime -= YZ_SECS;
	unixtime -= pc_tz.secondswest;
	if (unixtime <= 0) {
		/*
		 * "before beginning of all time" for DOS ...
		 */
		return (EOVERFLOW);
	}
	for (year = YEAR_ZERO; unixtime >= days_in_year(year) * 86400;
	    year++)
		unixtime -= 86400 * days_in_year(year);

	if (year > 127 + YEAR_ZERO) {
		/*
		 * "past end of all time" for DOS - can happen
		 * on a 64bit kernel via utimes() syscall ...
		 */
		return (EOVERFLOW);
	}

	for (month = 1; unixtime >= 86400 * days_in_month(month, year);
	    month++)
		unixtime -= 86400 * days_in_month(month, year);

	year -= YEAR_ZERO;

	day = (int)(unixtime / 86400);
	unixtime -= 86400 * day++;	/* counting starts at 1 */

	hour = (int)(unixtime / 3600);
	unixtime -= 3600 * hour;

	min = (int)(unixtime / 60);
	unixtime -= 60 * min;

	sec = (int)unixtime;

	PC_DPRINTF3(1, "ux2pc date: %d.%d.%d\n", day, month, YEAR_ZERO + year);
	PC_DPRINTF3(1, "ux2pc time: %dh%dm%ds\n", hour, min, sec);
	PC_DPRINTF1(1, "ux2pc unixtime: %lld\n", (long long)(unixtime));

	ASSERT(year >= 0 && year < 128);
	ASSERT(month >= 1 && month <= 12);
	ASSERT(day >= 1 && day <= days_in_month(month, year));
	ASSERT(hour < 24);
	ASSERT(min < 60);
	ASSERT(sec < 60);

	pctp->pct_time =
	    LE_16(hour << HOURSHIFT | min << MINSHIFT | (sec / 2) << SECSHIFT);
	pctp->pct_date =
	    LE_16(year << YEARSHIFT | month << MONSHIFT | day << DAYSHIFT);

	return (0);
}

/*
 * Convert time from DOS to UNIX time format.
 * Since FAT timestamps cannot be expressed in 32bit time_t,
 * the calculation is performed using 64bit values. It's up to
 * the caller to decide what to do for out-of-UNIX-range values.
 */
void
pc_pcttotv(
	struct pctime *pctp,		/* DOS time input */
	int64_t *unixtime)		/* caller converts to time_t */
{
	uint_t year, month, day, hour, min, sec;

	sec = 2 * ((LE_16(pctp->pct_time) >> SECSHIFT) & SECMASK);
	min = (LE_16(pctp->pct_time) >> MINSHIFT) & MINMASK;
	hour = (LE_16(pctp->pct_time) >> HOURSHIFT) & HOURMASK;
	day = (LE_16(pctp->pct_date) >> DAYSHIFT) & DAYMASK;
	month = (LE_16(pctp->pct_date) >> MONSHIFT) & MONMASK;
	year = (LE_16(pctp->pct_date) >> YEARSHIFT) & YEARMASK;
	year += YEAR_ZERO;

	/*
	 * Basic sanity checks. The FAT timestamp bitfields allow for
	 * impossible dates/times - return the "FAT epoch" for these.
	 */
	if (pctp->pct_date == 0) {
		year = YEAR_ZERO;
		month = 1;
		day = 1;
	}
	if (month > 12 || month < 1 ||
	    day < 1 || day > days_in_month(month, year) ||
	    hour > 23 || min > 59 || sec > 59) {
		cmn_err(CE_NOTE, "impossible FAT timestamp, "
		    "d/m/y %d/%d/%d, h:m:s %d:%d:%d",
		    day, month, year, hour, min, sec);
		*unixtime = YZ_SECS + pc_tz.secondswest;
		return;
	}

	PC_DPRINTF3(1, "pc2ux date: %d.%d.%d\n", day, month, year);
	PC_DPRINTF3(1, "pc2ux time: %dh%dm%ds\n", hour, min, sec);

	*unixtime = (int64_t)sec;
	*unixtime += 60 * (int64_t)min;
	*unixtime += 3600 * (int64_t)hour;
	*unixtime += 86400 * (int64_t)(day -1);
	while (month > 1) {
		month--;
		*unixtime += 86400 * (int64_t)days_in_month(month, year);
	}
	while (year > YEAR_ZERO) {
		year--;
		*unixtime += 86400 * (int64_t)days_in_year(year);
	}
	/*
	 * For FAT, the beginning of all time is 01/01/1980,
	 * and years are counted relative to that.
	 * We adjust this base value by the timezone offset
	 * that is passed in to pcfs at mount time.
	 */
	*unixtime += YZ_SECS;
	*unixtime += pc_tz.secondswest;

	/*
	 * FAT epoch is past UNIX epoch - negative UNIX times
	 * cannot result from the conversion.
	 */
	ASSERT(*unixtime > 0);
	PC_DPRINTF1(1, "pc2ux unixtime: %lld\n", (long long)(*unixtime));
}

/*
 * Determine whether a character is valid for a long file name.
 * It is easier to determine by filtering out invalid characters.
 * Following are invalid characters in a long filename.
 *	/ \ : * ? < > | "
 */
int
pc_valid_lfn_char(char c)
{
	const char *cp;
	int n;

	static const char invaltab[] = {
		"/\\:*?<>|\""
	};

	cp = invaltab;
	n = sizeof (invaltab) - 1;
	while (n--) {
		if (c == *cp++)
			return (0);
	}
	return (1);
}

int
pc_valid_long_fn(char *namep, int utf8)
{
	char *tmp;
	int len, error;
	char *prohibited[13] = {
		"/", "\\", ":", "*", "?", "<", ">", "|", "\"", YEN, LRO, RLO,
		    NULL
	};

	if (utf8) {
		/* UTF-8 */
		if ((len = u8_validate(namep, strlen(namep), prohibited,
		    (U8_VALIDATE_ENTIRE|U8_VALIDATE_CHECK_ADDITIONAL),
		    &error)) < 0)
			return (0);
		if (len > PCMAXNAMLEN)
			return (0);
	} else {
		/* UTF-16 */
		for (tmp = namep; (*tmp != '\0') || (*(tmp+1) != '\0');
		    tmp += 2) {
			if ((*(tmp+1) == '\0') && !pc_valid_lfn_char(*tmp))
				return (0);

			/* Prohibit the Yen character */
			if ((*(tmp+1) == '\0') && (*tmp == '\xa5'))
				return (0);

			/* Prohibit the left-to-right override control char */
			if ((*(tmp+1) == '\x20') && (*tmp == '\x2d'))
				return (0);

			/* Prohibit the right-to-left override control char */
			if ((*(tmp+1) == '\x20') && (*tmp == '\x2e'))
				return (0);
		}
		if ((tmp - namep) > (PCMAXNAMLEN * sizeof (uint16_t)))
			return (0);
	}
	return (1);
}

int
pc_fname_ext_to_name(char *namep, char *fname, char *ext, int foldcase)
{
	int	i;
	char	*tp = namep;
	char	c;

	i = PCFNAMESIZE;
	while (i-- && ((c = *fname) != ' ')) {
		if (!(c == '.' || pc_validchar(c))) {
			return (-1);
		}
		if (foldcase)
			*tp++ = tolower(c);
		else
			*tp++ = c;
		fname++;
	}
	if (*ext != ' ') {
		*tp++ = '.';
		i = PCFEXTSIZE;
		while (i-- && ((c = *ext) != ' ')) {
			if (!pc_validchar(c)) {
				return (-1);
			}
			if (foldcase)
				*tp++ = tolower(c);
			else
				*tp++ = c;
			ext++;
		}
	}
	*tp = '\0';
	return (0);
}
