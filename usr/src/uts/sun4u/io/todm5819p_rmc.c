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
 * tod driver module for ALI M5819P part
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/todm5819p.h>
#include <sys/rmc_comm_dp.h>
#include <sys/rmc_comm_drvintf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/clock.h>
#include <sys/reboot.h>
#include <sys/machsystm.h>

static timestruc_t	todm5819p_rmc_get(void);
static void		todm5819p_rmc_set(timestruc_t);
static uint_t		todm5819p_rmc_set_watchdog_timer(uint_t);
static uint_t		todm5819p_rmc_clear_watchdog_timer(void);
static void		todm5819p_rmc_set_power_alarm(timestruc_t);
static void		todm5819p_rmc_clear_power_alarm(void);
static uint64_t		todm5819p_rmc_get_cpufrequency(void);

extern uint64_t		find_cpufrequency(volatile uint8_t *);

/*
 * External variables
 */
extern int	watchdog_enable;
extern int	watchdog_available;
extern int	boothowto;

/*
 * Global variables
 */
int m5819p_debug_flags;

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "tod module for ALI M5819P"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static todinfo_t rtc_to_tod(struct rtc_t *);
static void read_rtc(struct rtc_t *);
static void write_rtc_time(struct rtc_t *);
static void write_rtc_alarm(struct rtc_t *);


int
_init(void)
{
	if (strcmp(tod_module_name, "todm5819p_rmc") == 0) {
		M5819P_ADDR_REG = RTC_B;
		M5819P_DATA_REG = (RTC_DM | RTC_HM);

		tod_ops.tod_get = todm5819p_rmc_get;
		tod_ops.tod_set = todm5819p_rmc_set;

		tod_ops.tod_set_watchdog_timer =
		    todm5819p_rmc_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer =
		    todm5819p_rmc_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todm5819p_rmc_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todm5819p_rmc_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todm5819p_rmc_get_cpufrequency;
		if (boothowto & RB_DEBUG) {
			cmn_err(CE_WARN, "todm5819p_rmc: kernel debugger "
			    "detected: hardware watchdog disabled");
		}
	}

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	if (strcmp(tod_module_name, "todm5819p_rmc") == 0)
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
 * todm5819p_rmc is normally called once a second, from the clock thread.
 * It may also be infrequently called from other contexts (eg. ddi framework),
 * in which case our counting to NBAD_READ_LIMIT may be a few seconds short
 * of the desired 15-minute timeframe; this slight inaccuracy is acceptable.
 */
#define	NBAD_READ_LIMIT	(900)   /* 15 minutes, in seconds */
/*
 * Read the current time from the clock chip and convert to UNIX form.
 * Checks the century, but otherwise assumes that the values in the clock
 * chip are valid.
 * Must be called with tod_lock held.
 */
static timestruc_t
todm5819p_rmc_get(void)
{
	int i;
	int s;
	timestruc_t ts;
	struct rtc_t rtc;
	static int nbad_reads = 0;

	ASSERT(MUTEX_HELD(&tod_lock));

	/* set the hw watchdog timer if it's been activated */
	if (watchdog_activated) {
		int ret = 0;
		ret = tod_ops.tod_set_watchdog_timer(0);
		/*
		 * The empty set_watchdog routine returns a 0. So if a
		 * coded routine fails we will look for a -1 for a failure.
		 */
		if (ret == -1)
			cmn_err(CE_WARN, "todm5819p: failed to set hardware "
			    "watchdog timer.");
	}

	/*
	 * Read current time from the tod. If the tod isn't accessible, wait and
	 * retry.
	 * Run critical in the time critical section to avoid being interrupted
	 */
	for (i = 0; i < TODM5819_UIP_RETRY_THRESH; i++) {
		s = ddi_enter_critical();
		M5819P_ADDR_REG = RTC_A;
		if (!(M5819P_DATA_REG & RTC_UIP)) {
			read_rtc(&rtc);
			ddi_exit_critical(s);
			break;
		}
		ddi_exit_critical(s);
		drv_usecwait(TODM5819_UIP_WAIT_USEC);
	}
	if (i == TODM5819_UIP_RETRY_THRESH) {
		/*
		 * tod is inaccessible: just return current software time
		 */
		tod_fault_reset();
		return (hrestime);
	}

	DPRINTF("todm5819p_rmc_get: century=%d year=%d dom=%d hrs=%d\n",
	    (int)rtc.rtc_century, (int)rtc.rtc_year, (int)rtc.rtc_dom,
	    (int)rtc.rtc_hrs);

	/* detect and correct invalid century register data */
	if (rtc.rtc_century < 19) {
		DPRINTF(
		    "todm5819p_rmc_get: century invalid (%d), returning 20\n",
		    (int)rtc.rtc_century);
		rtc.rtc_century = 20;
		if (++nbad_reads == NBAD_READ_LIMIT) {
			nbad_reads = 0;
			cmn_err(CE_WARN, "todm5819p: realtime clock century "
			    "register appears to be defective.");
		}
	}

	ts.tv_sec = tod_to_utc(rtc_to_tod(&rtc));
	ts.tv_nsec = 0;
	return (ts);
}

static todinfo_t
rtc_to_tod(struct rtc_t *rtc)
{
	todinfo_t tod;

	/*
	 * tod_year is base 1900 so this code needs to adjust the true year
	 * retrieved from the rtc's century and year fields.
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

static void
read_rtc(struct rtc_t *rtc)
{
	M5819P_ADDR_REG = RTC_SEC;
	rtc->rtc_sec = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_ASEC;
	rtc->rtc_asec = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_MIN;
	rtc->rtc_min = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_AMIN;
	rtc->rtc_amin = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_HRS;
	rtc->rtc_hrs = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_AHRS;
	rtc->rtc_ahrs = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_DOW;
	rtc->rtc_dow = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_DOM;
	rtc->rtc_dom = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_MON;
	rtc->rtc_mon = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_YEAR;
	rtc->rtc_year = M5819P_DATA_REG;
	M5819P_ADDR_REG = RTC_CENTURY;
	rtc->rtc_century = M5819P_DATA_REG;

	/* Read date alarm */
	M5819P_ADDR_REG = RTC_ADOM_REG;
	rtc->rtc_adom = (M5819P_DATA_REG) & RTC_ADOM;
}

/*
 * Write the specified time into the clock chip.
 * Must be called with tod_lock held.
 */
static void
todm5819p_rmc_set(timestruc_t ts)
{
	struct rtc_t	rtc;
	todinfo_t tod = utc_to_tod(ts.tv_sec);
	int year;
	rmc_comm_msg_t request;
	dp_set_date_time_t set_time_msg;

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

	DPRINTF("todm5819p_rmc_set: century=%d year=%d dom=%d hrs=%d\n",
	    (int)rtc.rtc_century, (int)rtc.rtc_year, (int)rtc.rtc_dom,
	    (int)rtc.rtc_hrs);

	write_rtc_time(&rtc);

	set_time_msg.year	= year - 1900;
	set_time_msg.month	= tod.tod_month - 1;
	set_time_msg.day	= tod.tod_day;
	set_time_msg.hour	= tod.tod_hour;
	set_time_msg.minute	= tod.tod_min;
	set_time_msg.second	= tod.tod_sec;

	request.msg_type = DP_SET_DATE_TIME;
	request.msg_len = sizeof (set_time_msg);
	request.msg_buf = (caddr_t)&set_time_msg;

	(void) rmc_comm_request_nowait(&request, 0);
}

void
write_rtc_time(struct rtc_t *rtc)
{
	uint8_t	regb;

	/*
	 * Freeze
	 */
	M5819P_ADDR_REG = RTC_B;
	regb = M5819P_DATA_REG;
	M5819P_DATA_REG = (regb | RTC_SET);

	M5819P_ADDR_REG = RTC_SEC;
	M5819P_DATA_REG = rtc->rtc_sec;
	M5819P_ADDR_REG = RTC_MIN;
	M5819P_DATA_REG = rtc->rtc_min;
	M5819P_ADDR_REG = RTC_HRS;
	M5819P_DATA_REG = rtc->rtc_hrs;
	M5819P_ADDR_REG = RTC_DOW;
	M5819P_DATA_REG = rtc->rtc_dow;
	M5819P_ADDR_REG = RTC_DOM;
	M5819P_DATA_REG = rtc->rtc_dom;
	M5819P_ADDR_REG = RTC_MON;
	M5819P_DATA_REG = rtc->rtc_mon;
	M5819P_ADDR_REG = RTC_YEAR;
	M5819P_DATA_REG = rtc->rtc_year;
	M5819P_ADDR_REG = RTC_CENTURY;
	M5819P_DATA_REG = rtc->rtc_century;

	/*
	 * Unfreeze
	 */
	M5819P_ADDR_REG = RTC_B;
	M5819P_DATA_REG = regb;
}

void
write_rtc_alarm(struct rtc_t *rtc)
{
	M5819P_ADDR_REG = RTC_ASEC;
	M5819P_DATA_REG = rtc->rtc_asec;
	M5819P_ADDR_REG = RTC_AMIN;
	M5819P_DATA_REG = rtc->rtc_amin;
	M5819P_ADDR_REG = RTC_AHRS;
	M5819P_DATA_REG = rtc->rtc_ahrs;

	M5819P_ADDR_REG = RTC_ADOM_REG;
	M5819P_DATA_REG = rtc->rtc_adom;
}

/*
 * program the rtc registers for alarm to go off at the specified time
 */
static void
todm5819p_rmc_set_power_alarm(timestruc_t ts)
{
	todinfo_t	tod;
	uint8_t		regb;
	struct rtc_t	rtc;

	ASSERT(MUTEX_HELD(&tod_lock));
	tod = utc_to_tod(ts.tv_sec);

	/*
	 * disable alarms and clear AF flag by reading reg C
	 */
	M5819P_ADDR_REG = RTC_B;
	regb = M5819P_DATA_REG;
	M5819P_DATA_REG = regb & ~RTC_AIE;
	M5819P_ADDR_REG = RTC_C;
	(void) M5819P_DATA_REG;

	rtc.rtc_asec = (uint8_t)tod.tod_sec;
	rtc.rtc_amin = (uint8_t)tod.tod_min;
	rtc.rtc_ahrs = (uint8_t)tod.tod_hour;
	rtc.rtc_adom = (uint8_t)tod.tod_day;

	/*
	 * Write alarm values and enable alarm
	 */
	write_rtc_alarm(&rtc);

	M5819P_ADDR_REG = RTC_B;
	M5819P_DATA_REG = regb | RTC_AIE;
}

/*
 * clear alarm interrupt
 */
static void
todm5819p_rmc_clear_power_alarm(void)
{
	uint8_t regb;

	ASSERT(MUTEX_HELD(&tod_lock));

	M5819P_ADDR_REG = RTC_B;
	regb = M5819P_DATA_REG;
	M5819P_DATA_REG = regb & ~RTC_AIE;
}

/*
 * Determine the cpu frequency by watching the TOD chip rollover twice.
 * Cpu clock rate is determined by computing the ticks added (in tick register)
 * during one second interval on TOD.
 */
uint64_t
todm5819p_rmc_get_cpufrequency(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	M5819P_ADDR_REG = RTC_SEC;
	return (find_cpufrequency(v_rtc_data_reg));
}

/*ARGSUSED*/
static uint_t
todm5819p_rmc_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

static uint_t
todm5819p_rmc_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}
