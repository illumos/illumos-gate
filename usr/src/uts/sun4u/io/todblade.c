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
#include <sys/lom_priv.h>

#define	WDOG_ON 1
#define	WDOG_OFF 0

static timestruc_t	todbl_get(void);
static void		todbl_set(timestruc_t);
static uint_t		todbl_set_watchdog_timer(uint_t);
static uint_t		todbl_clear_watchdog_timer(void);
static void		todbl_set_power_alarm(timestruc_t);
static void		todbl_clear_power_alarm(void);
static uint64_t		todbl_get_cpufrequency(void);

static todinfo_t	rtc_to_tod(struct rtc_t *);
static uint_t		read_rtc(struct rtc_t *);
static void		write_rtc_time(struct rtc_t *);
static uint_t		configure_wdog(uint8_t new_state);

extern uint64_t		find_cpufrequency(volatile uint8_t *);

/*
 * External variables
 */
extern int	watchdog_enable;
extern int	watchdog_available;
extern int	watchdog_activated;
extern uint_t   watchdog_timeout_seconds;
extern int	boothowto;
extern void	(*bsc_drv_func_ptr)(struct bscv_idi_info *);

/*
 * Global variables
 */
int m5819_debug_flags;
uint8_t wdog_reset_on_timeout = 1;
static clock_t last_pat_lbt;


static struct modlmisc modlmisc = {
	&mod_miscops, "todblade module",
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};


int
_init(void)
{
	if (strcmp(tod_module_name, "todblade") == 0) {
		RTC_PUT8(RTC_B, (RTC_DM | RTC_HM));

		tod_ops.tod_get = todbl_get;
		tod_ops.tod_set = todbl_set;
		tod_ops.tod_set_watchdog_timer =
			todbl_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer =
			todbl_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todbl_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todbl_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todbl_get_cpufrequency;

		if (watchdog_enable && (boothowto & RB_DEBUG)) {
				watchdog_available = 0;
				cmn_err(CE_WARN, "todblade: kernel debugger "
				    "detected: hardware watchdog disabled");
		}
	}
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	if (strcmp(tod_module_name, "todblade") == 0) {
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
todbl_get(void)
{
	int i;
	timestruc_t ts;
	struct rtc_t rtc;
	struct bscv_idi_info bscv_info;

	ASSERT(MUTEX_HELD(&tod_lock));

	/*
	 * We must check that the value of watchdog enable hasnt changed
	 * as its a user knob for turning it on and off
	 */
	if (watchdog_available) {
		if (watchdog_activated && !watchdog_enable) {
			(void) configure_wdog(WDOG_OFF);
		} else if (!watchdog_activated && watchdog_enable) {
			(void) configure_wdog(WDOG_ON);
		} else if (watchdog_activated &&
			    (ddi_get_lbolt() - last_pat_lbt) >=
			    SEC_TO_TICK(1)) {
			/*
			 * PAT THE WATCHDOG!!
			 * We dont want to accelerate the pat frequency
			 * when userland calls to the TOD_GET_DATE ioctl
			 * pass through here.
			 */
			bscv_info.type = BSCV_IDI_WDOG_PAT;
			bscv_info.data = NULL;
			bscv_info.size = 0;
			if (bsc_drv_func_ptr != NULL) {
				(*bsc_drv_func_ptr)(&bscv_info);
				last_pat_lbt = ddi_get_lbolt();
			}
		}
	}

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
		 * We couldnt read from the tod
		 */
		tod_fault_reset();
		return (hrestime);
	}

	DPRINTF("todbl_get: century=%d year=%d dom=%d hrs=%d\n",
	    rtc.rtc_century, rtc.rtc_year, rtc.rtc_dom, rtc.rtc_hrs);

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


static uint_t
read_rtc(struct rtc_t *rtc)
{
	int s;
	uint_t rtc_readable = 0;

	s = splhi();
	/*
	 * If UIP bit is not set we have at least 274us
	 * to read the values.
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
todbl_set(timestruc_t ts)
{
	struct rtc_t	rtc;
	todinfo_t tod = utc_to_tod(ts.tv_sec);
	struct bscv_idi_info bscv_info;
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
	DPRINTF("todbl_set: century=%d year=%d dom=%d hrs=%d\n",
	    rtc.rtc_century, rtc.rtc_year, rtc.rtc_dom, rtc.rtc_hrs);

	write_rtc_time(&rtc);

	/*
	 * Because of a generic solaris problem where calls to stime()
	 * starve calls to tod_get(), we need to check to see when the
	 * watchdog was last patted and pat it if necessary.
	 */
	if (watchdog_activated &&
	    (ddi_get_lbolt() - last_pat_lbt) >= SEC_TO_TICK(1)) {
		/*
		 * Pat the watchdog!
		 */
		bscv_info.type = BSCV_IDI_WDOG_PAT;
		bscv_info.data = NULL;
		bscv_info.size = 0;
		if (bsc_drv_func_ptr != NULL) {
			(*bsc_drv_func_ptr)(&bscv_info);
			last_pat_lbt = ddi_get_lbolt();
		}
	}
}

static void
write_rtc_time(struct rtc_t *rtc)
{
	uint8_t	regb;

	/*
	 * Freeze
	 */
	regb = RTC_GET8(RTC_B);
	RTC_PUT8(RTC_B, (regb | RTC_SET));

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

	/*
	 * Unfreeze
	 */
	RTC_PUT8(RTC_B, regb);
}



/*
 * The TOD alarm functionality is not supported on our platform
 * as the interrupt is not wired, so do nothing.
 */
/*ARGSUSED*/
static void
todbl_set_power_alarm(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * clear alarm interrupt
 */
static void
todbl_clear_power_alarm(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Determine the cpu frequency by watching the TOD chip rollover twice.
 * Cpu clock rate is determined by computing the ticks added (in tick register)
 * during one second interval on TOD.
 */
uint64_t
todbl_get_cpufrequency(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	M5819_ADDR_REG = RTC_SEC;
	return (find_cpufrequency(v_rtc_data_reg));
}


static uint_t
todbl_set_watchdog_timer(uint_t timeoutval)
{
	/*
	 * We get started during kernel intilaisation only
	 * if watchdog_enable is set.
	 */
	ASSERT(MUTEX_HELD(&tod_lock));

	if (watchdog_available && (!watchdog_activated ||
	    (watchdog_activated && (timeoutval != watchdog_timeout_seconds)))) {
		watchdog_timeout_seconds = timeoutval;
		if (configure_wdog(WDOG_ON))
			return (watchdog_timeout_seconds);
	}
	return (0);
}

static uint_t
todbl_clear_watchdog_timer(void)
{
	/*
	 * The core kernel will call us here to disable the wdog when:
	 * 1. we're panicing
	 * 2. we're entering debug
	 * 3. we're rebooting
	 */
	ASSERT(MUTEX_HELD(&tod_lock));

	if (watchdog_available && watchdog_activated) {
		watchdog_enable = 0;
		if (!configure_wdog(WDOG_OFF))
			return (0);
	}
	return (watchdog_timeout_seconds);
}

static uint_t
configure_wdog(uint8_t new_state)
{
	bscv_wdog_t wdog_cmd;
	struct bscv_idi_info bscv_info;

	if (new_state == WDOG_ON || new_state == WDOG_OFF) {

		wdog_cmd.enable_wdog = new_state;
		wdog_cmd.wdog_timeout_s = watchdog_timeout_seconds;
		wdog_cmd.reset_system_on_timeout = wdog_reset_on_timeout;
		bscv_info.type = BSCV_IDI_WDOG_CFG;
		bscv_info.data = &wdog_cmd;
		bscv_info.size = sizeof (wdog_cmd);

		if (bsc_drv_func_ptr != NULL) {
			watchdog_activated = new_state;
			(*bsc_drv_func_ptr)(&bscv_info);
			return (1);
		}
	}
	return (0);

}
