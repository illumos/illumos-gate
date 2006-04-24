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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * tod driver module for TI BQ4802 part
 *
 * Note: The way to access the bq4802's RTC registers is different than
 * the previous RTC devices (m5823, m5819p, ds1287, etc) that we used.
 * The address returns from OBP is mapped directly to the bq4802's RTC
 * registers. To read/write the data from/to the bq4802 registers, one
 * just add the register offset to the base address.
 * To access the previous RTC devices, we write the register index to
 * the address port (v_rtc_addr_reg) then read/write the data from/to
 * the data port (v_rtc_data_reg).
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

#include <sys/todbq4802.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/clock.h>
#include <sys/reboot.h>
#include <sys/machsystm.h>

/*
 * tod_ops entry routines
 */
static timestruc_t	todbq4802_get(void);
static void		todbq4802_set(timestruc_t);
static uint_t		todbq4802_set_watchdog_timer(uint_t);
static uint_t		todbq4802_clear_watchdog_timer(void);
static void		todbq4802_set_power_alarm(timestruc_t);
static void		todbq4802_clear_power_alarm(void);
static uint64_t		todbq4802_get_cpufrequency(void);

extern uint64_t		find_cpufrequency(volatile uint8_t *);

/*
 * External variables
 */
extern int watchdog_enable;
extern int watchdog_available;
extern int boothowto;

/*
 * Global variables
 */
int bq4802_debug_flags;
uint_t bq4802_hrestime_count = 0;
uint_t bq4802_uip_count = 0;

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "tod module for TI BQ4802"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static void read_rtc(struct rtc_t *);
static void write_rtc_time(struct rtc_t *);
static void write_rtc_alarm(struct rtc_t *);

int
_init(void)
{
	if (strcmp(tod_module_name, "todbq4802") == 0) {
		if (v_rtc_addr_reg == NULL)
			cmn_err(CE_PANIC, "addr not set, cannot read RTC\n");

		BQ4802_DATA_REG(RTC_CNTRL) = (RTC_HM | RTC_STOP_N);

		/* Clear AF flag by reading reg Flags (D) */
		(void) BQ4802_DATA_REG(RTC_FLAGS);

		tod_ops.tod_get = todbq4802_get;
		tod_ops.tod_set = todbq4802_set;
		tod_ops.tod_set_watchdog_timer =
		    todbq4802_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer =
		    todbq4802_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todbq4802_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todbq4802_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todbq4802_get_cpufrequency;

		/*
		 * check if hardware watchdog timer is available and user
		 * enabled it.
		 */
		if (watchdog_enable) {
			if (!watchdog_available) {
				cmn_err(CE_WARN, "bq4802: Hardware watchdog "
				    "unavailable");
			} else if (boothowto & RB_DEBUG) {
				cmn_err(CE_WARN, "bq4802: Hardware watchdog"
				    " disabled [debugger]");
			}
		}
	}

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	if (strcmp(tod_module_name, "todbq4802") == 0)
		return (EBUSY);

	return (mod_remove(&modlinkage));
}

/*
 * The loadable-module _info(9E) entry point
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Read the current time from the clock chip and convert to UNIX form.
 * Assumes that the year in the clock chip is valid.
 * Must be called with tod_lock held.
 */
static timestruc_t
todbq4802_get(void)
{
	timestruc_t ts;
	todinfo_t tod;
	struct rtc_t rtc;

	ASSERT(MUTEX_HELD(&tod_lock));

	read_rtc(&rtc);
	DPRINTF("todbq4802_get: century=%d year=%d dom=%d hrs=%d min=%d"
	    " sec=%d\n", rtc.rtc_century, rtc.rtc_year, rtc.rtc_dom,
	    rtc.rtc_hrs, rtc.rtc_min, rtc.rtc_sec);

	/*
	 * tod_year is base 1900 so this code needs to adjust the true
	 * year retrieved from the rtc's century and year fields.
	 */
	tod.tod_year	= rtc.rtc_year + (rtc.rtc_century * 100) - 1900;
	tod.tod_month	= rtc.rtc_mon;
	tod.tod_day	= rtc.rtc_dom;
	tod.tod_dow	= rtc.rtc_dow;
	tod.tod_hour	= rtc.rtc_hrs;
	tod.tod_min	= rtc.rtc_min;
	tod.tod_sec	= rtc.rtc_sec;

	ts.tv_sec = tod_to_utc(tod);
	ts.tv_nsec = 0;
	return (ts);
}

/*
 * Once every second, the user-accessible clock/calendar
 * locations are updated simultaneously from the internal
 * real-time counters. To prevent reading data in transition,
 * updates to the bq4802 clock registers should be halted.
 * Updating is halted by setting the Update Transfer Inhibit
 * (UTI) bit D3 of the control register E. As long as the
 * UTI bit is 1, updates to user-accessible clock locations are
 * inhibited. Once the frozen clock information is retrieved by
 * reading the appropriate clock memory locations, the UTI
 * bit should be reset to 0 in order to allow updates to occur
 * from the internal counters. Because the internal counters
 * are not halted by setting the UTI bit, reading the clock
 * locations has no effect on clock accuracy. Once the UTI bit
 * is reset to 0, the internal registers update within one
 * second the user-accessible registers with the correct time.
 * A halt command issued during a clock update allows the
 * update to occur before freezing the data.
 */
static void
read_rtc(struct rtc_t *rtc)
{
	uint8_t	reg_cntrl;

	/*
	 * Freeze
	 */
	reg_cntrl = BQ4802_DATA_REG(RTC_CNTRL);
	BQ4802_DATA_REG(RTC_CNTRL) = (reg_cntrl | RTC_UTI);

	rtc->rtc_sec = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_SEC));
	rtc->rtc_asec = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_ASEC));
	rtc->rtc_min = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_MIN));
	rtc->rtc_amin = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_AMIN));
	rtc->rtc_hrs = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_HRS));
	rtc->rtc_ahrs = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_AHRS));
	rtc->rtc_dom = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_DOM));
	rtc->rtc_adom = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_ADOM));
	rtc->rtc_dow = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_DOW));
	rtc->rtc_mon = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_MON));
	rtc->rtc_year = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_YEAR));
	rtc->rtc_century = BCD_TO_BYTE(BQ4802_DATA_REG(RTC_CENTURY));

	/*
	 * Unfreeze
	 */
	BQ4802_DATA_REG(RTC_CNTRL) = reg_cntrl;
}

/*
 * Write the specified time into the clock chip.
 * Must be called with tod_lock held.
 */
static void
todbq4802_set(timestruc_t ts)
{
	struct rtc_t	rtc;
	todinfo_t tod = utc_to_tod(ts.tv_sec);
	int year;

	ASSERT(MUTEX_HELD(&tod_lock));

	/* tod_year is base 1900 so this code needs to adjust */
	year = 1900 + tod.tod_year;
	rtc.rtc_year	= year % 100;
	rtc.rtc_century = year / 100;
	rtc.rtc_mon	= (uint8_t)tod.tod_month;
	rtc.rtc_dom	= (uint8_t)tod.tod_day;
	rtc.rtc_dow	= (uint8_t)tod.tod_dow;
	rtc.rtc_hrs	= (uint8_t)tod.tod_hour;
	rtc.rtc_min	= (uint8_t)tod.tod_min;
	rtc.rtc_sec	= (uint8_t)tod.tod_sec;
	DPRINTF("todbq4802_set: year=%d dom=%d hrs=%d min=%d sec=%d\n",
	    rtc.rtc_year, rtc.rtc_dom, rtc.rtc_hrs, rtc.rtc_min, rtc.rtc_sec);

	write_rtc_time(&rtc);
}

/*
 * The UTI bit must be used to set the bq4802 clock.
 * Once set, the locations can be written with the desired
 * information in BCD format. Resetting the UTI bit to 0 causes
 * the written values to be transferred to the internal clock
 * counters and allows updates to the user-accessible registers
 * to resume within one second.
 */
void
write_rtc_time(struct rtc_t *rtc)
{
	uint8_t	reg_cntrl;

	/*
	 * Freeze
	 */
	reg_cntrl = BQ4802_DATA_REG(RTC_CNTRL);
	BQ4802_DATA_REG(RTC_CNTRL) = (reg_cntrl | RTC_UTI);

	BQ4802_DATA_REG(RTC_SEC) = BYTE_TO_BCD(rtc->rtc_sec);
	BQ4802_DATA_REG(RTC_MIN) = BYTE_TO_BCD(rtc->rtc_min);
	BQ4802_DATA_REG(RTC_HRS) = BYTE_TO_BCD(rtc->rtc_hrs);
	BQ4802_DATA_REG(RTC_DOM) = BYTE_TO_BCD(rtc->rtc_dom);
	BQ4802_DATA_REG(RTC_DOW) = BYTE_TO_BCD(rtc->rtc_dow);
	BQ4802_DATA_REG(RTC_MON) = BYTE_TO_BCD(rtc->rtc_mon);
	BQ4802_DATA_REG(RTC_YEAR) = BYTE_TO_BCD(rtc->rtc_year);
	BQ4802_DATA_REG(RTC_CENTURY) = BYTE_TO_BCD(rtc->rtc_century);

	/*
	 * Unfreeze
	 */
	BQ4802_DATA_REG(RTC_CNTRL) = reg_cntrl;
}

void
write_rtc_alarm(struct rtc_t *rtc)
{
	BQ4802_DATA_REG(RTC_ASEC) = BYTE_TO_BCD(rtc->rtc_asec);
	BQ4802_DATA_REG(RTC_AMIN) = BYTE_TO_BCD(rtc->rtc_amin);
	BQ4802_DATA_REG(RTC_AHRS) = BYTE_TO_BCD(rtc->rtc_ahrs);
	BQ4802_DATA_REG(RTC_ADOM) = BYTE_TO_BCD(rtc->rtc_adom);
}

/*
 * program the rtc registers for alarm to go off at the specified time
 */
static void
todbq4802_set_power_alarm(timestruc_t ts)
{
	todinfo_t	tod;
	uint8_t		regc;
	struct rtc_t	rtc;

	ASSERT(MUTEX_HELD(&tod_lock));
	tod = utc_to_tod(ts.tv_sec);

	/*
	 * disable alarms and clear AF flag by reading reg Flags (D)
	 */
	regc = BQ4802_DATA_REG(RTC_ENABLES);
	BQ4802_DATA_REG(RTC_ENABLES) = regc & ~(RTC_AIE | RTC_ABE);
	(void) BQ4802_DATA_REG(RTC_FLAGS);

	rtc.rtc_asec = (uint8_t)tod.tod_sec;
	rtc.rtc_amin = (uint8_t)tod.tod_min;
	rtc.rtc_ahrs = (uint8_t)tod.tod_hour;
	rtc.rtc_adom = (uint8_t)tod.tod_day;
	DPRINTF("todbq4802_set_alarm: dom=%d hrs=%d min=%d sec=%d\n",
	    rtc.rtc_adom, rtc.rtc_ahrs, rtc.rtc_amin, rtc.rtc_asec);

	/*
	 * Write alarm values and enable alarm
	 */
	write_rtc_alarm(&rtc);

	BQ4802_DATA_REG(RTC_ENABLES) = regc | RTC_AIE | RTC_ABE;
}

/*
 * clear alarm interrupt
 */
static void
todbq4802_clear_power_alarm(void)
{
	uint8_t regc;

	ASSERT(MUTEX_HELD(&tod_lock));

	regc = BQ4802_DATA_REG(RTC_ENABLES);
	BQ4802_DATA_REG(RTC_ENABLES) = regc & ~(RTC_AIE | RTC_ABE);
}

/*
 * Determine the cpu frequency by watching the TOD chip rollover twice.
 * Cpu clock rate is determined by computing the ticks added (in tick register)
 * during one second interval on TOD.
 */
uint64_t
todbq4802_get_cpufrequency(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (find_cpufrequency((volatile uint8_t *)v_rtc_addr_reg));
}

/*ARGSUSED*/
static uint_t
todbq4802_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

static uint_t
todbq4802_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}
