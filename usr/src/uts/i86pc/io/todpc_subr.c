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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

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

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

static int todpc_rtcget(unsigned char *buf);
static void todpc_rtcput(unsigned char *buf);

#define	CLOCK_RES	1000		/* 1 microsec in nanosecs */

int clock_res = CLOCK_RES;

/*
 * The minimum sleep time till an alarm can be fired.
 * This can be tuned in /etc/system, but if the value is too small,
 * there is a danger that it will be missed if it takes too long to
 * get from the set point to sleep.  Or that it can fire quickly, and
 * generate a power spike on the hardware.  And small values are
 * probably only usefull for test setups.
 */
int clock_min_alarm = 4;

/*
 * Machine-dependent clock routines.
 */

extern long gmt_lag;

struct rtc_offset {
	int8_t	loaded;
	uint8_t	day_alrm;
	uint8_t mon_alrm;
	uint8_t	century;
};

static struct rtc_offset pc_rtc_offset = {0, 0, 0, 0};


/*
 * Entry point for ACPI to pass RTC or other clock values that
 * are useful to TOD.
 */
void
pc_tod_set_rtc_offsets(ACPI_TABLE_FADT *fadt) {
	int		ok = 0;

	/*
	 * ASSERT is for debugging, but we don't want the machine
	 * falling over because for some reason we didn't get a valid
	 * pointer.
	 */
	ASSERT(fadt);
	if (fadt == NULL) {
		return;
	}

	if (fadt->DayAlarm) {
		pc_rtc_offset.day_alrm = fadt->DayAlarm;
		ok = 1;
	}

	if (fadt->MonthAlarm) {
		pc_rtc_offset.mon_alrm = fadt->MonthAlarm;
		ok = 1;
	}

	if (fadt->Century) {
		pc_rtc_offset.century = fadt->Century;
		ok = 1;
	}

	pc_rtc_offset.loaded = ok;
}


/*
 * Write the specified time into the clock chip.
 * Must be called with tod_lock held.
 */
/*ARGSUSED*/
static void
todpc_set(tod_ops_t *top, timestruc_t ts)
{
	todinfo_t tod = utc_to_tod(ts.tv_sec - ggmtl());
	struct rtc_t rtc;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (todpc_rtcget((unsigned char *)&rtc))
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

	todpc_rtcput((unsigned char *)&rtc);
}

/*
 * Read the current time from the clock chip and convert to UNIX form.
 * Assumes that the year in the clock chip is valid.
 * Must be called with tod_lock held.
 */
/*ARGSUSED*/
static timestruc_t
todpc_get(tod_ops_t *top)
{
	timestruc_t ts;
	todinfo_t tod;
	struct rtc_t rtc;
	int compute_century;
	static int century_warn = 1; /* only warn once, not each time called */
	static int range_warn = 1;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (todpc_rtcget((unsigned char *)&rtc)) {
		tod_status_set(TOD_GET_FAILED);
		return (hrestime);
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

	/* read was successful so ensure failure flag is clear */
	tod_status_clear(TOD_GET_FAILED);

	ts.tv_sec = tod_to_utc(tod) + ggmtl();
	ts.tv_nsec = 0;

	return (ts);
}

#include <sys/promif.h>
/*
 * Write the specified wakeup alarm into the clock chip.
 * Must be called with tod_lock held.
 */
void
/*ARGSUSED*/
todpc_setalarm(tod_ops_t *top, int nsecs)
{
	struct rtc_t rtc;
	int delta, asec, amin, ahr, adom, amon;
	int day_alrm = pc_rtc_offset.day_alrm;
	int mon_alrm = pc_rtc_offset.mon_alrm;

	ASSERT(MUTEX_HELD(&tod_lock));

	/* A delay of zero is not allowed */
	if (nsecs == 0)
		return;

	/* Make sure that we delay no less than the minimum time */
	if (nsecs < clock_min_alarm)
		nsecs = clock_min_alarm;

	if (todpc_rtcget((unsigned char *)&rtc))
		return;

	/*
	 * Compute alarm secs, mins and hrs, and where appropriate, dom
	 * and mon.  rtc bytes are in binary-coded decimal, so we have
	 * to convert.
	 */
	delta = nsecs + BCD_TO_BYTE(rtc.rtc_sec);
	asec = delta % 60;

	delta = (delta / 60) + BCD_TO_BYTE(rtc.rtc_min);
	amin = delta % 60;

	delta = (delta / 60) + BCD_TO_BYTE(rtc.rtc_hr);
	ahr  = delta % 24;

	if (day_alrm == 0 && delta >= 24) {
		prom_printf("No day alarm - set to end of today!\n");
		asec = 59;
		amin = 59;
		ahr  = 23;
	} else {
		int mon = BCD_TO_BYTE(rtc.rtc_mon);
		static int dpm[] =
		    {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

		adom = (delta / 24) + BCD_TO_BYTE(rtc.rtc_dom);

		if (mon_alrm == 0) {
			if (adom > dpm[mon]) {
				prom_printf("No mon alarm - "
				    "set to end of current month!\n");
				asec = 59;
				amin = 59;
				ahr  = 23;
				adom = dpm[mon];
			}
		} else {
			for (amon = mon;
			    amon <= 12 && adom > dpm[amon]; amon++) {
				adom -= dpm[amon];
			}
			if (amon > 12) {
				prom_printf("Alarm too far in future - "
				    "set to end of current year!\n");
				asec = 59;
				amin = 59;
				ahr  = 23;
				adom = dpm[12];
				amon = 12;
			}
			rtc.rtc_amon = BYTE_TO_BCD(amon);
		}

		rtc.rtc_adom = BYTE_TO_BCD(adom);
	}

	rtc.rtc_asec = BYTE_TO_BCD(asec);
	rtc.rtc_amin = BYTE_TO_BCD(amin);
	rtc.rtc_ahr  = BYTE_TO_BCD(ahr);

	rtc.rtc_statusb |= RTC_AIE;	/* Enable alarm interrupt */

	todpc_rtcput((unsigned char *)&rtc);
}

/*
 * Clear an alarm.  This is effectively setting an alarm of 0.
 */
void
/*ARGSUSED*/
todpc_clralarm(tod_ops_t *top)
{
	mutex_enter(&tod_lock);
	todpc_setalarm(top, 0);
	mutex_exit(&tod_lock);
}

/*
 * Routine to read contents of real time clock to the specified buffer.
 * Returns ENXIO if clock not valid, or EAGAIN if clock data cannot be read
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
todpc_rtcget(unsigned char *buf)
{
	unsigned char	reg;
	int		i;
	int		retries = 256;
	unsigned char	*rawp;
	unsigned char	century = RTC_CENTURY;
	unsigned char	day_alrm;
	unsigned char	mon_alrm;

	ASSERT(MUTEX_HELD(&tod_lock));

	day_alrm = pc_rtc_offset.day_alrm;
	mon_alrm = pc_rtc_offset.mon_alrm;
	if (pc_rtc_offset.century != 0) {
		century = pc_rtc_offset.century;
	}

	outb(RTC_ADDR, RTC_D);		/* check if clock valid */
	reg = inb(RTC_DATA);
	if ((reg & RTC_VRT) == 0)
		return (ENXIO);

checkuip:
	if (retries-- < 0)
		return (EAGAIN);
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
	outb(RTC_ADDR, century); /* do century */
	((struct rtc_t *)buf)->rtc_century = inb(RTC_DATA);

	if (day_alrm > 0) {
		outb(RTC_ADDR, day_alrm);
		((struct rtc_t *)buf)->rtc_adom = inb(RTC_DATA) & 0x3f;
	}
	if (mon_alrm > 0) {
		outb(RTC_ADDR, mon_alrm);
		((struct rtc_t *)buf)->rtc_amon = inb(RTC_DATA);
	}

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
todpc_rtcput(unsigned char *buf)
{
	unsigned char	reg;
	int		i;
	unsigned char	century = RTC_CENTURY;
	unsigned char	day_alrm = pc_rtc_offset.day_alrm;
	unsigned char	mon_alrm = pc_rtc_offset.mon_alrm;
	unsigned char	tmp;

	if (pc_rtc_offset.century != 0) {
		century = pc_rtc_offset.century;
	}

	outb(RTC_ADDR, RTC_B);
	reg = inb(RTC_DATA);
	outb(RTC_ADDR, RTC_B);
	outb(RTC_DATA, reg | RTC_SET);	/* allow time set now */
	for (i = 0; i < RTC_NREGP; i++) { /* set the time */
		outb(RTC_ADDR, i);
		outb(RTC_DATA, buf[i]);
	}
	outb(RTC_ADDR, century); /* do century */
	outb(RTC_DATA, ((struct rtc_t *)buf)->rtc_century);

	if (day_alrm > 0) {
		outb(RTC_ADDR, day_alrm);
		/* preserve RTC_VRT bit; some virt envs accept writes there */
		tmp = inb(RTC_DATA) & RTC_VRT;
		tmp |= ((struct rtc_t *)buf)->rtc_adom & ~RTC_VRT;
		outb(RTC_DATA, tmp);
	}
	if (mon_alrm > 0) {
		outb(RTC_ADDR, mon_alrm);
		outb(RTC_DATA, ((struct rtc_t *)buf)->rtc_amon);
	}

	outb(RTC_ADDR, RTC_B);
	reg = inb(RTC_DATA);
	outb(RTC_ADDR, RTC_B);
	outb(RTC_DATA, reg & ~RTC_SET);	/* allow time update */
}

static tod_ops_t todpc_ops = {
	TOD_OPS_VERSION,
	todpc_get,
	todpc_set,
	NULL,
	NULL,
	todpc_setalarm,
	todpc_clralarm,
	NULL
};

/*
 * Initialize for the default TOD ops vector for use on hardware.
 */

tod_ops_t *tod_ops = &todpc_ops;
