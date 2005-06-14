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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>

#include <sys/cpuvar.h>
#include <sys/clock.h>
#include <sys/debug.h>
#include <sys/rtc.h>
#include <sys/archsystm.h>
#include <sys/sysmacros.h>
#include <sys/lockstat.h>
#include <sys/stat.h>
#include <sys/sunddi.h>

static int pc_rtcget(unsigned char *buf);
static void pc_rtcput(unsigned char *buf);

#define	CLOCK_RES	1000		/* 1 microsec in nanosecs */

int clock_res = CLOCK_RES;

/*
 * Machine-dependent clock routines.
 */

extern long gmt_lag;

/*
 * Write the specified time into the clock chip.
 * Must be called with tod_lock held.
 */
void
pc_tod_set(timestruc_t ts)
{
	todinfo_t tod = utc_to_tod(ts.tv_sec - gmt_lag);
	struct rtc_t rtc;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (pc_rtcget((unsigned char *)&rtc))
		return;

	/*
	 * rtc bytes are in binary-coded decimal, so we have to convert.
	 * We assume that we wrap the rtc year back to zero at 2000.
	 */
	/* LINTED: YRBASE = 0 for x86 */
	tod.tod_year -= YRBASE;
	if (tod.tod_year >= 100) {
		tod.tod_year -= 100;
		rtc.rtc_century = BYTE_TO_BCD(20); /* 20xx year */
	} else
		rtc.rtc_century = BYTE_TO_BCD(19); /* 19xx year */
	rtc.rtc_yr	= BYTE_TO_BCD(tod.tod_year);
	rtc.rtc_mon	= BYTE_TO_BCD(tod.tod_month);
	rtc.rtc_dom	= BYTE_TO_BCD(tod.tod_day);
	/* dow < 10, so no conversion */
	rtc.rtc_dow	= (unsigned char)tod.tod_dow;
	rtc.rtc_hr	= BYTE_TO_BCD(tod.tod_hour);
	rtc.rtc_min	= BYTE_TO_BCD(tod.tod_min);
	rtc.rtc_sec	= BYTE_TO_BCD(tod.tod_sec);

	pc_rtcput((unsigned char *)&rtc);
}

/*
 * Read the current time from the clock chip and convert to UNIX form.
 * Assumes that the year in the clock chip is valid.
 * Must be called with tod_lock held.
 */
timestruc_t
pc_tod_get(void)
{
	timestruc_t ts;
	todinfo_t tod;
	struct rtc_t rtc;
	int compute_century;
	static int century_warn = 1; /* only warn once, not each time called */
	static int range_warn = 1;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (pc_rtcget((unsigned char *)&rtc)) {
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
		tod_fault_reset();
		return (ts);
	}

	/* assume that we wrap the rtc year back to zero at 2000 */
	tod.tod_year	= BCD_TO_BYTE(rtc.rtc_yr);
	if (tod.tod_year < 69) {
		if (range_warn && tod.tod_year > 38) {
			cmn_err(CE_WARN, "hardware real-time clock is out "
				"of range -- time needs to be reset");
			range_warn = 0;
		}
		tod.tod_year += 100 + YRBASE; /* 20xx year */
		compute_century = 20;
	} else {
		/* LINTED: YRBASE = 0 for x86 */
		tod.tod_year += YRBASE; /* 19xx year */
		compute_century = 19;
	}
	if (century_warn && BCD_TO_BYTE(rtc.rtc_century) != compute_century) {
		cmn_err(CE_NOTE,
			"The hardware real-time clock appears to have the "
			"wrong century: %d.\nSolaris will still operate "
			"correctly, but other OS's/firmware agents may "
			"not.\nUse date(1) to set the date to the current "
			"time to correct the RTC.",
			BCD_TO_BYTE(rtc.rtc_century));
		century_warn = 0;
	}
	tod.tod_month	= BCD_TO_BYTE(rtc.rtc_mon);
	tod.tod_day	= BCD_TO_BYTE(rtc.rtc_dom);
	tod.tod_dow	= rtc.rtc_dow;	/* dow < 10, so no conversion needed */
	tod.tod_hour	= BCD_TO_BYTE(rtc.rtc_hr);
	tod.tod_min	= BCD_TO_BYTE(rtc.rtc_min);
	tod.tod_sec	= BCD_TO_BYTE(rtc.rtc_sec);

	ts.tv_sec = tod_to_utc(tod) + gmt_lag;
	ts.tv_nsec = 0;

	return (ts);
}

/*
 * Routine to read contents of real time clock to the specified buffer.
 * Returns -1 if clock not valid, or -2 if clock data cannot be read
 * else 0.
 * The routine will busy wait for the Update-In-Progress flag to clear.
 * On completion of the reads the Seconds register is re-read and the
 * UIP flag is rechecked to confirm that an clock update did not occur
 * during the accesses.  Routine will error exit after 256 attempts.
 * (See bugid 1158298.)
 * Routine returns RTC_NREG (which is 15) bytes of data, as given in the
 * technical reference.  This data includes both time and status registers.
 */

static int
pc_rtcget(unsigned char *buf)
{
	unsigned char	reg;
	int		i;
	int		retries = 256;
	unsigned char	*rawp;

	ASSERT(MUTEX_HELD(&tod_lock));

	outb(RTC_ADDR, RTC_D);		/* check if clock valid */
	reg = inb(RTC_DATA);
	if ((reg & RTC_VRT) == 0)
		return (-1);

checkuip:
	if (retries-- < 0)
		return (-2);
	outb(RTC_ADDR, RTC_A);		/* check if update in progress */
	reg = inb(RTC_DATA);
	if (reg & RTC_UIP) {
		tenmicrosec();
		goto checkuip;
	}

	for (i = 0, rawp = buf; i < RTC_NREG; i++) {
		outb(RTC_ADDR, i);
		*rawp++ = inb(RTC_DATA);
	}
	outb(RTC_ADDR, RTC_CENTURY); /* do century */
	((struct rtc_t *)buf)->rtc_century = inb(RTC_DATA);
	outb(RTC_ADDR, 0);		/* re-read Seconds register */
	reg = inb(RTC_DATA);
	if (reg != ((struct rtc_t *)buf)->rtc_sec ||
	    (((struct rtc_t *)buf)->rtc_statusa & RTC_UIP))
		/* update occured during reads */
		goto checkuip;

	return (0);
}

/*
 * This routine writes the contents of the given buffer to the real time
 * clock.  It is given RTC_NREGP bytes of data, which are the 10 bytes used
 * to write the time and set the alarm.  It should be called with the priority
 * raised to 5.
 */
static void
pc_rtcput(unsigned char *buf)
{
	unsigned char	reg;
	int		i;

	outb(RTC_ADDR, RTC_B);
	reg = inb(RTC_DATA);
	outb(RTC_ADDR, RTC_B);
	outb(RTC_DATA, reg | RTC_SET);	/* allow time set now */
	for (i = 0; i < RTC_NREGP; i++) { /* set the time */
		outb(RTC_ADDR, i);
		outb(RTC_DATA, buf[i]);
	}
	outb(RTC_ADDR, RTC_CENTURY); /* do century */
	outb(RTC_DATA, ((struct rtc_t *)buf)->rtc_century);
	outb(RTC_ADDR, RTC_B);
	outb(RTC_DATA, reg & ~RTC_SET);	/* allow time update */
}

/*
 * The following wrappers have been added so that locking
 * can be exported to platform-independent clock routines
 * (ie adjtime(), clock_setttime()), via a functional interface.
 */
int
hr_clock_lock(void)
{
	ushort_t s;

	CLOCK_LOCK(&s);
	return (s);
}

void
hr_clock_unlock(int s)
{
	CLOCK_UNLOCK(s);
}
