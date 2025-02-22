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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _TZFILE_H
#define	_TZFILE_H

/*
 * A part of this file comes from public domain source, so
 * clarified as of June 5, 1996 by Arthur David Olson
 */

#include <sys/types.h>

/*
 * WARNING:
 * The interfaces defined in this header file are for Sun private use only.
 * The contents of this file are subject to change without notice for the
 * future releases.
 */

/* For further information, see ctime(3C) and zic(8) man pages. */

/*
 * This file is in the public domain, so clarified as of
 * 1996-06-05 by Arthur David Olson.
 */

/*
 * This header is for use ONLY with the time conversion code.
 * There is no guarantee that it will remain unchanged,
 * or that it will remain at all.
 * Do NOT copy it to any system include directory.
 * Thank you!
 */

/*
 * Note: Despite warnings from the authors of this code, Solaris has
 * placed this header file in the system include directory.  This was
 * probably done in order to build both zic and zdump which are in
 * separate source directories, but both use this file.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Information about time zone files.
 */

#ifndef TZDIR
#define	TZDIR	"/usr/share/lib/zoneinfo" /* Time zone object file directory */
#endif /* !defined TZDIR */

#ifndef TZDEFAULT
#define	TZDEFAULT	"localtime"
#endif /* !defined TZDEFAULT */

#ifndef TZDEFRULES
#define	TZDEFRULES	"posixrules"
#endif /* !defined TZDEFRULES */


/* See Internet RFC 9636 for more details about the following format.  */

/*
 * Each file begins with. . .
 */

#define	TZ_MAGIC	"TZif"

struct tzhead {
	char	tzh_magic[4];		/* TZ_MAGIC */
	char	tzh_version[1];		/* '\0' or '2'-'4' as of 2021 */
	char	tzh_reserved[15];	/* reserved; must be zero */
	char	tzh_ttisutcnt[4];	/* coded number of trans. time flags */
	char	tzh_ttisstdcnt[4];	/* coded number of trans. time flags */
	char	tzh_leapcnt[4];		/* coded number of leap seconds */
	char	tzh_timecnt[4];		/* coded number of transition times */
	char	tzh_typecnt[4];		/* coded number of local time types */
	char	tzh_charcnt[4];		/* coded number of abbr. chars */
};

/*
 * . . .followed by. . .
 *
 *	tzh_timecnt (char [4])s		coded transition times a la time(2)
 *	tzh_timecnt (unsigned char)s	types of local time starting at above
 *	tzh_typecnt repetitions of
 *		one (char [4])		coded UT offset in seconds
 *		one (unsigned char)	used to set tm_isdst
 *		one (unsigned char)	that's an abbreviation list index
 *	tzh_charcnt (char)s		'\0'-terminated zone abbreviations
 *	tzh_leapcnt repetitions of
 *		one (char [4])		coded leap second transition times
 *		one (char [4])		total correction after above
 *	tzh_ttisstdcnt (char)s		indexed by type; if 1, transition
 *					time is standard time, if 0,
 *					transition time is local (wall clock)
 *					time; if absent, transition times are
 *					assumed to be local time
 *	tzh_ttisutcnt (char)s		indexed by type; if 1, transition
 *					time is UT, if 0, transition time is
 *					local time; if absent, transition
 *					times are assumed to be local time.
 *					When this is 1, the corresponding
 *					std/wall indicator must also be 1.
 */

/*
 * If tzh_version is '2' or greater, the above is followed by a second instance
 * of tzhead and a second instance of the data in which each coded transition
 * time uses 8 rather than 4 chars,
 * then a POSIX.1-2017 proleptic TZ string for use in handling
 * instants after the last transition time stored in the file
 * (with nothing between the newlines if there is no POSIX.1-2017
 * representation for such instants).
 *
 * If tz_version is '3' or greater, the TZ string can be any POSIX.1-2024
 * proleptic TZ string, which means the above is extended as follows.
 * First, the TZ string's hour offset may range from -167
 * through 167 as compared to the range 0 through 24 required
 * by POSIX.1-2017 and earlier.
 * Second, its DST start time may be January 1 at 00:00 and its stop
 * time December 31 at 24:00 plus the difference between DST and
 * standard time, indicating DST all year.
 */

/*
 * In the current implementation, "tzset()" refuses to deal with files that
 * exceed any of the limits below.
 */

#ifndef TZ_MAX_TIMES
/*
 * The TZ_MAX_TIMES value below is enough to handle a bit more than a
 * year's worth of solar time (corrected daily to the nearest second) or
 * 138 years of Pacific Presidential Election time
 * (where there are three time zone transitions every fourth year).
 */
#define	TZ_MAX_TIMES 370
#endif /* !defined TZ_MAX_TIMES */

#ifndef TZ_MAX_TYPES
/* This must be at least 18 for Europe/Vilnius with 'zic -b fat'.  */
#define	TZ_MAX_TYPES 256 /* Limited by what (unsigned char)'s can hold */
#endif /* !defined TZ_MAX_TYPES */

#ifndef TZ_MAX_CHARS
/* This must be at least 40 for America/Anchorage.  */
#define	TZ_MAX_CHARS	50	/* Maximum number of abbreviation characters */
				/* (limited by what unsigned chars can hold) */
#endif /* !defined TZ_MAX_CHARS */

#ifndef TZ_MAX_LEAPS
/* This must be at least 27 for leap seconds from 1972 through mid-2023. */
/* There's a plan to discontinue leap seconds by 2035.  */
#define	TZ_MAX_LEAPS 50	/* Maximum number of leap second corrections */
#endif /* !defined TZ_MAX_LEAPS */

/* Handy macros that are independent of tzfile implementation.  */

enum {
	SECSPERMIN = 60,
	MINSPERHOUR = 60,
	SECSPERHOUR = SECSPERMIN * MINSPERHOUR,
	HOURSPERDAY = 24,
	DAYSPERWEEK = 7,
	DAYSPERNYEAR = 365,
	DAYSPERLYEAR = DAYSPERNYEAR + 1,
	MONSPERYEAR = 12,
	YEARSPERREPEAT = 400	/* years before a Gregorian repeat */
};

#define	SECSPERDAY	((int_fast32_t)SECSPERHOUR * HOURSPERDAY)

#define	DAYSPERREPEAT		((int_fast32_t)400 * 365 + 100 - 4 + 1)
#define	SECSPERREPEAT		((int_fast64_t)DAYSPERREPEAT * SECSPERDAY)
#define	AVGSECSPERYEAR		(SECSPERREPEAT / YEARSPERREPEAT)

/*
 * How many years to generate (in zic.c) or search through (in localtime.c).
 * This is two years larger than the obvious 400, to avoid edge cases.
 * E.g., suppose a rule applies from 2012 on with transitions
 * in March and September, plus one-off transitions in November 2013,
 * and suppose the rule cannot be expressed as a proleptic TZ string.
 * If zic looked only at the last 400 years, it would set max_year=2413,
 * with the intent that the 400 years 2014 through 2413 will be repeated.
 * The last transition listed in the tzfile would be in 2413-09,
 * less than 400 years after the last one-off transition in 2013-11.
 * Two years is not overkill for localtime.c, as a one-year bump
 * would mishandle 2023d's America/Ciudad_Juarez for November 2422.
 */
enum { years_of_observations = YEARSPERREPEAT + 2 };

enum {
	TM_SUNDAY,
	TM_MONDAY,
	TM_TUESDAY,
	TM_WEDNESDAY,
	TM_THURSDAY,
	TM_FRIDAY,
	TM_SATURDAY
};

enum {
	TM_JANUARY,
	TM_FEBRUARY,
	TM_MARCH,
	TM_APRIL,
	TM_MAY,
	TM_JUNE,
	TM_JULY,
	TM_AUGUST,
	TM_SEPTEMBER,
	TM_OCTOBER,
	TM_NOVEMBER,
	TM_DECEMBER
};

enum {
	TM_YEAR_BASE = 1900,
	TM_WDAY_BASE = TM_MONDAY,
	EPOCH_YEAR = 1970,
	EPOCH_WDAY = TM_THURSDAY
};

#define	isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

/*
 * Since everything in isleap is modulo 400 (or a factor of 400), we know that
 *	isleap(y) == isleap(y % 400)
 * and so
 *	isleap(a + b) == isleap((a + b) % 400)
 * or
 *	isleap(a + b) == isleap(a % 400 + b % 400)
 * This is true even if % means modulo rather than Fortran remainder
 * (which is allowed by C89 but not by C99 or later).
 * We use this to avoid addition overflow problems.
 */

#define	isleap_sum(a, b)	isleap((a) % 400 + (b) % 400)

#ifdef	__cplusplus
}
#endif

#endif	/* _TZFILE_H */
