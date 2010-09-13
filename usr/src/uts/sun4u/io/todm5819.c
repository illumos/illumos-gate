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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/todm5819.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/clock.h>
#include <sys/reboot.h>
#include <sys/machsystm.h>
#include <sys/poll.h>
#include <sys/pbio.h>

static timestruc_t	todm5819_get(void);
static void		todm5819_set(timestruc_t);
static uint_t		todm5819_set_watchdog_timer(uint_t);
static uint_t		todm5819_clear_watchdog_timer(void);
static void		todm5819_set_power_alarm(timestruc_t);
static void		todm5819_clear_power_alarm(void);
static uint64_t		todm5819_get_cpufrequency(void);

extern uint64_t		find_cpufrequency(volatile uint8_t *);

/*
 * External variables
 */
extern int		watchdog_enable;
extern int		watchdog_available;
extern int		boothowto;

/*
 * Global variables
 */
int m5819_debug_flags;

static todinfo_t	rtc_to_tod(struct rtc_t *);
static uint_t		read_rtc(struct rtc_t *);
static void		write_rtc_time(struct rtc_t *);
static void		write_rtc_alarm(struct rtc_t *);


static struct modlmisc modlmisc = {
	&mod_miscops, "tod module for ALI M5819",
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};


int
_init(void)
{
	if (strcmp(tod_module_name, "todm5819") == 0 ||
	    strcmp(tod_module_name, "m5819") == 0) {
		RTC_PUT8(RTC_B, (RTC_DM | RTC_HM));

		tod_ops.tod_get = todm5819_get;
		tod_ops.tod_set = todm5819_set;
		tod_ops.tod_set_watchdog_timer = todm5819_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer =
		    todm5819_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todm5819_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todm5819_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todm5819_get_cpufrequency;

		/*
		 * check if hardware watchdog timer is available and user
		 * enabled it.
		 */
		if (watchdog_enable) {
			if (!watchdog_available) {
				cmn_err(CE_WARN, "m5819: Hardware watchdog "
				    "unavailable");
			} else if (boothowto & RB_DEBUG) {
				cmn_err(CE_WARN, "m5819: Hardware watchdog "
				    "disabled [debugger]");
			}
		}
	}

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	if (strcmp(tod_module_name, "m5819") == 0 ||
	    strcmp(tod_module_name, "todm5819") == 0) {
		return (EBUSY);
	} else {
		return (mod_remove(&modlinkage));
	}
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
todm5819_get(void)
{
	int i;
	timestruc_t ts;
	struct rtc_t rtc;

	ASSERT(MUTEX_HELD(&tod_lock));

	/*
	 * Read from the tod, and if it isnt accessible wait
	 * before retrying.
	 */
	for (i = 0; i < TODM5819_UIP_RETRY_THRESH; i++) {
		if (read_rtc(&rtc))
			break;
		drv_usecwait(TODM5819_UIP_WAIT_USEC);
	}
	if (i == TODM5819_UIP_RETRY_THRESH) {
		/*
		 * We couldn't read from the TOD.
		 */
		tod_status_set(TOD_GET_FAILED);
		return (hrestime);
	}

	DPRINTF("todm5819_get: century=%d year=%d dom=%d hrs=%d\n",
	    rtc.rtc_century, rtc.rtc_year, rtc.rtc_dom, rtc.rtc_hrs);

	/* read was successful so ensure failure flag is clear */
	tod_status_clear(TOD_GET_FAILED);

	ts.tv_sec = tod_to_utc(rtc_to_tod(&rtc));
	ts.tv_nsec = 0;
	return (ts);
}

static todinfo_t
rtc_to_tod(struct rtc_t *rtc)
{
	todinfo_t tod;

	/*
	 * tod_year is base 1900 so this code needs to adjust the true
	 * year retrieved from the rtc's century and year fields.
	 */
	tod.tod_year	= rtc->rtc_year + (rtc->rtc_century * 100) - 1900;
	tod.tod_month	= rtc->rtc_mon;
	tod.tod_day	= rtc->rtc_dom;
	tod.tod_dow	= rtc->rtc_dow;
	tod.tod_hour	= rtc->rtc_hrs;
	tod.tod_min	= rtc->rtc_min;
	tod.tod_sec	= rtc->rtc_sec;

	return (tod);
}

uint_t
read_rtc(struct rtc_t *rtc)
{
	int s;
	uint_t rtc_readable = 0;

	s = splhi();
	/*
	 * If UIP bit is not set we have at least 274us
	 * to read the values. Otherwise we have up to
	 * 336us to wait before we can read it
	 */
	if (!(RTC_GET8(RTC_A) & RTC_UIP)) {
		rtc_readable = 1;

		rtc->rtc_sec = RTC_GET8(RTC_SEC);
		rtc->rtc_asec = RTC_GET8(RTC_ASEC);
		rtc->rtc_min = RTC_GET8(RTC_MIN);
		rtc->rtc_amin = RTC_GET8(RTC_AMIN);

		rtc->rtc_hrs = RTC_GET8(RTC_HRS);
		rtc->rtc_ahrs = RTC_GET8(RTC_AHRS);
		rtc->rtc_dow = RTC_GET8(RTC_DOW);
		rtc->rtc_dom = RTC_GET8(RTC_DOM);
		rtc->rtc_adom = RTC_GET8(RTC_D) & 0x3f;

		rtc->rtc_mon = RTC_GET8(RTC_MON);
		rtc->rtc_year = RTC_GET8(RTC_YEAR);
		rtc->rtc_century = RTC_GET8(RTC_CENTURY);
		rtc->rtc_amon = 0;

		/* Clear wakeup data */
		rtc->apc_wdwr = 0;
		rtc->apc_wdmr = 0;
		rtc->apc_wmr = 0;
		rtc->apc_wyr = 0;
		rtc->apc_wcr = 0;
	}
	splx(s);
	return (rtc_readable);
}

/*
 * Write the specified time into the clock chip.
 * Must be called with tod_lock held.
 */
static void
todm5819_set(timestruc_t ts)
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
	DPRINTF("todm5819_set: century=%d year=%d dom=%d hrs=%d\n",
	    rtc.rtc_century, rtc.rtc_year, rtc.rtc_dom, rtc.rtc_hrs);

	write_rtc_time(&rtc);
}

void
write_rtc_time(struct rtc_t *rtc)
{
	uint8_t	regb;
	int	i;

	/*
	 * Freeze
	 */
	regb = RTC_GET8(RTC_B);
	RTC_PUT8(RTC_B, (regb | RTC_SET));

	/*
	 * If an update is in progress wait for the UIP flag to clear.
	 * If we write whilst UIP is still set there is a slight but real
	 * possibility of corrupting the RTC date and time registers.
	 *
	 * The expected wait is one internal cycle of the chip.  We could
	 * simply spin but this may hang a CPU if we were to have a broken
	 * RTC chip where UIP is stuck, so we use a retry loop instead.
	 * No critical section is needed here as the UIP flag will not be
	 * re-asserted until we clear RTC_SET.
	 */
	for (i = 0; i < TODM5819_UIP_RETRY_THRESH; i++) {
		if (!(RTC_GET8(RTC_A) & RTC_UIP)) {
			break;
		}
		drv_usecwait(TODM5819_UIP_WAIT_USEC);
	}
	if (i < TODM5819_UIP_RETRY_THRESH) {
		RTC_PUT8(RTC_SEC, (rtc->rtc_sec));
		RTC_PUT8(RTC_ASEC, (rtc->rtc_asec));
		RTC_PUT8(RTC_MIN, (rtc->rtc_min));
		RTC_PUT8(RTC_AMIN, (rtc->rtc_amin));

		RTC_PUT8(RTC_HRS, (rtc->rtc_hrs));
		RTC_PUT8(RTC_AHRS, (rtc->rtc_ahrs));
		RTC_PUT8(RTC_DOW, (rtc->rtc_dow));
		RTC_PUT8(RTC_DOM, (rtc->rtc_dom));

		RTC_PUT8(RTC_MON, (rtc->rtc_mon));
		RTC_PUT8(RTC_YEAR, (rtc->rtc_year));
		RTC_PUT8(RTC_CENTURY, (rtc->rtc_century));
	} else {
		cmn_err(CE_WARN, "todm5819: Could not write the RTC\n");
	}

	/*
	 * Unfreeze
	 */
	RTC_PUT8(RTC_B, regb);
}


void
write_rtc_alarm(struct rtc_t *rtc)
{
	RTC_PUT8(RTC_ASEC, (rtc->rtc_asec));
	RTC_PUT8(RTC_AMIN, (rtc->rtc_amin));
	RTC_PUT8(RTC_AHRS, (rtc->rtc_ahrs));
	RTC_PUT8(RTC_D, (rtc->rtc_adom));
}

/*
 * program the rtc registers for alarm to go off at the specified time
 */
static void
todm5819_set_power_alarm(timestruc_t ts)
{
	todinfo_t	tod;
	uint8_t		regb;
	struct rtc_t	rtc;

	ASSERT(MUTEX_HELD(&tod_lock));
	tod = utc_to_tod(ts.tv_sec);

	/*
	 * disable alarms
	 */
	regb = RTC_GET8(RTC_B);
	RTC_PUT8(RTC_B, (regb & ~RTC_AIE));


	rtc.rtc_asec = (uint8_t)tod.tod_sec;
	rtc.rtc_amin = (uint8_t)tod.tod_min;
	rtc.rtc_ahrs = (uint8_t)tod.tod_hour;
	rtc.rtc_adom = (uint8_t)tod.tod_day;

	write_rtc_alarm(&rtc);
	/*
	 * Enable alarm.
	 */
	RTC_PUT8(RTC_B, (regb | RTC_AIE));
}

/*
 * clear alarm interrupt
 */
static void
todm5819_clear_power_alarm(void)
{
	uint8_t regb;
	ASSERT(MUTEX_HELD(&tod_lock));

	regb = RTC_GET8(RTC_B);
	RTC_PUT8(RTC_B, (regb & ~RTC_AIE));
}

/*
 * Determine the cpu frequency by watching the TOD chip rollover twice.
 * Cpu clock rate is determined by computing the ticks added (in tick register)
 * during one second interval on TOD.
 */
uint64_t
todm5819_get_cpufrequency(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	M5819_ADDR_REG = RTC_SEC;
	return (find_cpufrequency(v_rtc_data_reg));
}


/*ARGSUSED*/
static uint_t
todm5819_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

static uint_t
todm5819_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}
