/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smbfs_subr.c,v 1.18 2005/02/02 00:22:23 lindak Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Time conversion functions (to/from DOS, NT times)
 * From BSD/Darwin smbfs_subr.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/sunddi.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>

/*
 * Time & date conversion routines taken from msdosfs. Although leap
 * year calculation is bogus, it's sufficient before 2100 :)
 */
/*
 * This is the format of the contents of the deTime field in the direntry
 * structure.
 * We don't use bitfields because we don't know how compilers for
 * arbitrary machines will lay them out.
 */
#define	DT_2SECONDS_MASK	0x1F	/* seconds divided by 2 */
#define	DT_2SECONDS_SHIFT	0
#define	DT_MINUTES_MASK		0x7E0	/* minutes */
#define	DT_MINUTES_SHIFT	5
#define	DT_HOURS_MASK		0xF800	/* hours */
#define	DT_HOURS_SHIFT		11

/*
 * This is the format of the contents of the deDate field in the direntry
 * structure.
 */
#define	DD_DAY_MASK		0x1F	/* day of month */
#define	DD_DAY_SHIFT		0
#define	DD_MONTH_MASK		0x1E0	/* month */
#define	DD_MONTH_SHIFT		5
#define	DD_YEAR_MASK		0xFE00	/* year - 1980 */
#define	DD_YEAR_SHIFT		9
/*
 * Total number of days that have passed for each month in a regular year.
 */
static ushort_t regyear[] = {
	31, 59, 90, 120, 151, 181,
	212, 243, 273, 304, 334, 365
};

/*
 * Total number of days that have passed for each month in a leap year.
 */
static ushort_t leapyear[] = {
	31, 60, 91, 121, 152, 182,
	213, 244, 274, 305, 335, 366
};

/*
 * Variables used to remember parts of the last time conversion.  Maybe we
 * can avoid a full conversion.
 */
static ulong_t  lasttime;
static ulong_t  lastday;
static ushort_t lastddate;
static ushort_t lastdtime;

/* Lock for the lastxxx variables */
static kmutex_t lastdt_lock;

/*
 * Number of seconds between 1970 and 1601 year
 * (134774 days)
 */
const uint64_t DIFF1970TO1601 = 11644473600ULL;
const uint32_t TEN_MIL = 10000000UL;

/*
 * Convert NT time (tenths of microseconds since 1601)
 * to Unix seconds+nanoseconds since 1970.  Any time
 * earlier than 1970 is converted to Unix time zero.
 * Both are GMT-based (no time zone adjustments).
 */
void
smb_time_NT2local(uint64_t nt_time, struct timespec *tsp)
{
	uint64_t nt_sec;	/* seconds */
	uint64_t nt_tus;	/* tenths of uSec. */

	/* Optimize time zero. */
	if (nt_time == 0) {
		tsp->tv_sec = 0;
		tsp->tv_nsec = 0;
		return;
	}

	nt_sec = nt_time / TEN_MIL;
	nt_tus = nt_time % TEN_MIL;

	if (nt_sec <= DIFF1970TO1601) {
		tsp->tv_sec = 0;
		tsp->tv_nsec = 0;
		return;
	}
	tsp->tv_sec = nt_sec - DIFF1970TO1601;
	tsp->tv_nsec = nt_tus * 100;
}

/*
 * Convert Unix time (seconds+nanoseconds since 1970)
 * to NT time (tenths of microseconds since 1601).
 * Exception: Convert time zero (really any time in
 * the first second of 1970) to NT time zero.
 * Both are GMT-based (no time zone adjustments).
 */
void
smb_time_local2NT(struct timespec *tsp, uint64_t *nt_time)
{
	uint64_t nt_sec;	/* seconds */
	uint64_t nt_tus;	/* tenths of uSec. */

	if (tsp->tv_sec == 0) {
		*nt_time = 0;
		return;
	}

	nt_sec = tsp->tv_sec + DIFF1970TO1601;
	nt_tus = tsp->tv_nsec / 100;

	*nt_time = (uint64_t)nt_sec * TEN_MIL + nt_tus;
}

/*
 * Time zone conversion stuff, only used in old dialects.
 * Don't adjust time zero for either conversion.
 */
void
smb_time_local2server(struct timespec *tsp, int tzoff, long *seconds)
{
	if (tsp->tv_sec <= (tzoff * 60))
		*seconds = 0;
	else
		*seconds = tsp->tv_sec - (tzoff * 60);
}

void
smb_time_server2local(ulong_t seconds, int tzoff, struct timespec *tsp)
{
	if (seconds == 0)
		tsp->tv_sec = 0;
	else
		tsp->tv_sec = seconds + tzoff * 60;
	tsp->tv_nsec = 0;
}

/*
 * Time conversions to/from DOS format, for old dialects.
 */

void
smb_time_unix2dos(struct timespec *tsp, int tzoff, u_int16_t *ddp,
	u_int16_t *dtp,	u_int8_t *dhp)
{
	long t;
	ulong_t days, year, month, inc;
	ushort_t *months;

	mutex_enter(&lastdt_lock);

	/*
	 * If the time from the last conversion is the same as now, then
	 * skip the computations and use the saved result.
	 */
	smb_time_local2server(tsp, tzoff, &t);
	t &= ~1;
	if (lasttime != t) {
		lasttime = t;
		if (t < 0) {
			/*
			 * This is before 1970, so it's before 1980,
			 * and can't be represented as a DOS time.
			 * Just represent it as the DOS epoch.
			 */
			lastdtime = 0;
			lastddate = (1 << DD_DAY_SHIFT)
			    + (1 << DD_MONTH_SHIFT)
			    + ((1980 - 1980) << DD_YEAR_SHIFT);
		} else {
			lastdtime = (((t / 2) % 30) << DT_2SECONDS_SHIFT)
			    + (((t / 60) % 60) << DT_MINUTES_SHIFT)
			    + (((t / 3600) % 24) << DT_HOURS_SHIFT);

			/*
			 * If the number of days since 1970 is the same as
			 * the last time we did the computation then skip
			 * all this leap year and month stuff.
			 */
			days = t / (24 * 60 * 60);
			if (days != lastday) {
				lastday = days;
				for (year = 1970; ; year++) {
					/*
					 * XXX - works in 2000, but won't
					 * work in 2100.
					 */
					inc = year & 0x03 ? 365 : 366;
					if (days < inc)
						break;
					days -= inc;
				}
				/*
				 * XXX - works in 2000, but won't work in 2100.
				 */
				months = year & 0x03 ? regyear : leapyear;
				for (month = 0; days >= months[month]; month++)
					;
				if (month > 0)
					days -= months[month - 1];
				lastddate = ((days + 1) << DD_DAY_SHIFT)
				    + ((month + 1) << DD_MONTH_SHIFT);
				/*
				 * Remember DOS's idea of time is relative
				 * to 1980, but UN*X's is relative to 1970.
				 * If somehow we get a time before 1980 then
				 * don't give totally crazy results.
				 */
				if (year > 1980)
					lastddate += (year - 1980) <<
					    DD_YEAR_SHIFT;
			}
		}
	}
	if (dhp)
		*dhp = (tsp->tv_sec & 1) * 100 + tsp->tv_nsec / 10000000;

	*ddp = lastddate;
	*dtp = lastdtime;

	mutex_exit(&lastdt_lock);
}

/*
 * The number of seconds between Jan 1, 1970 and Jan 1, 1980. In that
 * interval there were 8 regular years and 2 leap years.
 */
#define	SECONDSTO1980	(((8 * 365) + (2 * 366)) * (24 * 60 * 60))

static ushort_t lastdosdate;
static ulong_t  lastseconds;

void
smb_dos2unixtime(uint_t dd, uint_t dt, uint_t dh, int tzoff,
	struct timespec *tsp)
{
	ulong_t seconds;
	ulong_t month;
	ulong_t year;
	ulong_t days;
	ushort_t *months;

	if (dd == 0) {
		tsp->tv_sec = 0;
		tsp->tv_nsec = 0;
		return;
	}
	seconds = (((dt & DT_2SECONDS_MASK) >> DT_2SECONDS_SHIFT) << 1)
	    + ((dt & DT_MINUTES_MASK) >> DT_MINUTES_SHIFT) * 60
	    + ((dt & DT_HOURS_MASK) >> DT_HOURS_SHIFT) * 3600
	    + dh / 100;

	/*
	 * If the year, month, and day from the last conversion are the
	 * same then use the saved value.
	 */
	mutex_enter(&lastdt_lock);
	if (lastdosdate != dd) {
		lastdosdate = (ushort_t)dd;
		days = 0;
		year = (dd & DD_YEAR_MASK) >> DD_YEAR_SHIFT;
		days = year * 365;
		days += year / 4 + 1;	/* add in leap days */
		/*
		 * XXX - works in 2000, but won't work in 2100.
		 */
		if ((year & 0x03) == 0)
			days--;		/* if year is a leap year */
		months = year & 0x03 ? regyear : leapyear;
		month = (dd & DD_MONTH_MASK) >> DD_MONTH_SHIFT;
		if (month < 1 || month > 12) {
			month = 1;
		}
		if (month > 1)
			days += months[month - 2];
		days += ((dd & DD_DAY_MASK) >> DD_DAY_SHIFT) - 1;
		lastseconds = (days * 24 * 60 * 60) + SECONDSTO1980;
	}
	smb_time_server2local(seconds + lastseconds, tzoff, tsp);
	tsp->tv_nsec = (dh % 100) * 10000000;
	mutex_exit(&lastdt_lock);
}

void
smb_time_init(void)
{
	mutex_init(&lastdt_lock, NULL, MUTEX_DEFAULT, NULL);
}

void
smb_time_fini(void)
{
	mutex_destroy(&lastdt_lock);
}
