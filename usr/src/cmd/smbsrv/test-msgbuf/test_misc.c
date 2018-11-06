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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * A few excerpts from smb_kutil.c
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/tzfile.h>
#include <sys/atomic.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <smbsrv/smb_kproto.h>

time_t tzh_leapcnt = 0;

struct tm
*smb_gmtime_r(time_t *clock, struct tm *result);

time_t
smb_timegm(struct tm *tm);

struct	tm {
	int	tm_sec;
	int	tm_min;
	int	tm_hour;
	int	tm_mday;
	int	tm_mon;
	int	tm_year;
	int	tm_wday;
	int	tm_yday;
	int	tm_isdst;
};

static const int days_in_month[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

uint64_t
smb_time_unix_to_nt(timestruc_t *unix_time)
{
	uint64_t nt_time;

	if ((unix_time->tv_sec == 0) && (unix_time->tv_nsec == 0))
		return (0);

	nt_time = unix_time->tv_sec;
	nt_time *= 10000000;  /* seconds to 100ns */
	nt_time += unix_time->tv_nsec / 100;
	return (nt_time + NT_TIME_BIAS);
}

void
smb_time_nt_to_unix(uint64_t nt_time, timestruc_t *unix_time)
{
	uint32_t seconds;

	ASSERT(unix_time);

	if ((nt_time == 0) || (nt_time == -1)) {
		unix_time->tv_sec = 0;
		unix_time->tv_nsec = 0;
		return;
	}

	/*
	 * Can't represent times less than or equal NT_TIME_BIAS,
	 * so convert them to the oldest date we can store.
	 * Note that time zero is "special" being converted
	 * both directions as 0:0 (unix-to-nt, nt-to-unix).
	 */
	if (nt_time <= NT_TIME_BIAS) {
		unix_time->tv_sec = 0;
		unix_time->tv_nsec = 100;
		return;
	}

	nt_time -= NT_TIME_BIAS;
	seconds = nt_time / 10000000;
	unix_time->tv_sec = seconds;
	unix_time->tv_nsec = (nt_time  % 10000000) * 100;
}


/*
 * smb_time_dos_to_unix
 *
 * Convert SMB_DATE & SMB_TIME values to a unix timestamp.
 *
 * A date/time field of 0 means that that server file system
 * assigned value need not be changed. The behaviour when the
 * date/time field is set to -1 is not documented but is
 * generally treated like 0.
 * If date or time is 0 or -1 the unix time is returned as 0
 * so that the caller can identify and handle this special case.
 */
int32_t
smb_time_dos_to_unix(int16_t date, int16_t time)
{
	struct tm	atm;

	if (((date == 0) || (time == 0)) ||
	    ((date == -1) || (time == -1))) {
		return (0);
	}

	atm.tm_year = ((date >>  9) & 0x3F) + 80;
	atm.tm_mon  = ((date >>  5) & 0x0F) - 1;
	atm.tm_mday = ((date >>  0) & 0x1F);
	atm.tm_hour = ((time >> 11) & 0x1F);
	atm.tm_min  = ((time >>  5) & 0x3F);
	atm.tm_sec  = ((time >>  0) & 0x1F) << 1;

	return (smb_timegm(&atm));
}

void
smb_time_unix_to_dos(int32_t ux_time, int16_t *date_p, int16_t *time_p)
{
	struct tm	atm;
	int		i;
	time_t		tmp_time;

	if (ux_time == 0) {
		*date_p = 0;
		*time_p = 0;
		return;
	}

	tmp_time = (time_t)ux_time;
	(void) smb_gmtime_r(&tmp_time, &atm);

	if (date_p) {
		i = 0;
		i += atm.tm_year - 80;
		i <<= 4;
		i += atm.tm_mon + 1;
		i <<= 5;
		i += atm.tm_mday;

		*date_p = (short)i;
	}
	if (time_p) {
		i = 0;
		i += atm.tm_hour;
		i <<= 6;
		i += atm.tm_min;
		i <<= 5;
		i += atm.tm_sec >> 1;

		*time_p = (short)i;
	}
}

/*
 * smb_gmtime_r
 *
 * Thread-safe version of smb_gmtime. Returns a null pointer if either
 * input parameter is a null pointer. Otherwise returns a pointer
 * to result.
 *
 * Day of the week calculation: the Epoch was a thursday.
 *
 * There are no timezone corrections so tm_isdst and tm_gmtoff are
 * always zero, and the zone is always WET.
 */
struct tm *
smb_gmtime_r(time_t *clock, struct tm *result)
{
	time_t tsec;
	int year;
	int month;
	int sec_per_month;

	if (clock == 0 || result == 0)
		return (0);

	bzero(result, sizeof (struct tm));
	tsec = *clock;
	tsec -= tzh_leapcnt;

	result->tm_wday = tsec / SECSPERDAY;
	result->tm_wday = (result->tm_wday + TM_THURSDAY) % DAYSPERWEEK;

	year = EPOCH_YEAR;
	while (tsec >= (isleap(year) ? (SECSPERDAY * DAYSPERLYEAR) :
	    (SECSPERDAY * DAYSPERNYEAR))) {
		if (isleap(year))
			tsec -= SECSPERDAY * DAYSPERLYEAR;
		else
			tsec -= SECSPERDAY * DAYSPERNYEAR;

		++year;
	}

	result->tm_year = year - TM_YEAR_BASE;
	result->tm_yday = tsec / SECSPERDAY;

	for (month = TM_JANUARY; month <= TM_DECEMBER; ++month) {
		sec_per_month = days_in_month[month] * SECSPERDAY;

		if (month == TM_FEBRUARY && isleap(year))
			sec_per_month += SECSPERDAY;

		if (tsec < sec_per_month)
			break;

		tsec -= sec_per_month;
	}

	result->tm_mon = month;
	result->tm_mday = (tsec / SECSPERDAY) + 1;
	tsec %= SECSPERDAY;
	result->tm_sec = tsec % 60;
	tsec /= 60;
	result->tm_min = tsec % 60;
	tsec /= 60;
	result->tm_hour = (int)tsec;

	return (result);
}


/*
 * smb_timegm
 *
 * Converts the broken-down time in tm to a time value, i.e. the number
 * of seconds since the Epoch (00:00:00 UTC, January 1, 1970). This is
 * not a POSIX or ANSI function. Per the man page, the input values of
 * tm_wday and tm_yday are ignored and, as the input data is assumed to
 * represent GMT, we force tm_isdst and tm_gmtoff to 0.
 *
 * Before returning the clock time, we use smb_gmtime_r to set up tm_wday
 * and tm_yday, and bring the other fields within normal range. I don't
 * think this is really how it should be done but it's convenient for
 * now.
 */
time_t
smb_timegm(struct tm *tm)
{
	time_t tsec;
	int dd;
	int mm;
	int yy;
	int year;

	if (tm == 0)
		return (-1);

	year = tm->tm_year + TM_YEAR_BASE;
	tsec = tzh_leapcnt;

	for (yy = EPOCH_YEAR; yy < year; ++yy) {
		if (isleap(yy))
			tsec += SECSPERDAY * DAYSPERLYEAR;
		else
			tsec += SECSPERDAY * DAYSPERNYEAR;
	}

	for (mm = TM_JANUARY; mm < tm->tm_mon; ++mm) {
		dd = days_in_month[mm] * SECSPERDAY;

		if (mm == TM_FEBRUARY && isleap(year))
			dd += SECSPERDAY;

		tsec += dd;
	}

	tsec += (tm->tm_mday - 1) * SECSPERDAY;
	tsec += tm->tm_sec;
	tsec += tm->tm_min * SECSPERMIN;
	tsec += tm->tm_hour * SECSPERHOUR;

	tm->tm_isdst = 0;
	(void) smb_gmtime_r(&tsec, tm);
	return (tsec);
}
