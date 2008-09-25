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
 * tod driver module for Mostek M48T59 part
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/debug.h>
#include <sys/clock.h>
#include <sys/todmostek.h>
#include <sys/reboot.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>

static timestruc_t	todm_get(void);
static void		todm_set(timestruc_t);
static uint_t		todm_set_watchdog_timer(uint_t);
static uint_t		todm_clear_watchdog_timer(void);
static void		todm_set_power_alarm(timestruc_t);
static void		todm_clear_power_alarm(void);
static uint64_t		todm_get_cpufrequency(void);

static uchar_t watchdog_bits = 0;
static uint_t watchdog_timeout;

extern uint64_t find_cpufrequency(volatile uchar_t *);

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "tod module for Mostek M48T59"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	if (strcmp(tod_module_name, "todmostek") == 0) {
		tod_ops.tod_get = todm_get;
		tod_ops.tod_set = todm_set;
		tod_ops.tod_set_watchdog_timer = todm_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer = todm_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todm_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todm_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todm_get_cpufrequency;

		/*
		 * check if hardware watchdog timer is available and user
		 * enabled it.
		 */
		if (watchdog_enable) {
			if (!watchdog_available) {
			    cmn_err(CE_WARN, "Hardware watchdog unavailable");
			} else if (boothowto & RB_DEBUG) {
			    cmn_err(CE_WARN, "Hardware watchdog disabled"
				" [debugger]");
			}
		}
	}

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	if (strcmp(tod_module_name, "todmostek") == 0)
		return (EBUSY);
	else
		return (mod_remove(&modlinkage));
}

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
todm_get(void)
{
	timestruc_t ts;
#ifndef	MPSAS
	todinfo_t tod;
	int s;

	ASSERT(MUTEX_HELD(&tod_lock));

	s = splhi();

	CLOCK->clk_ctrl |= CLK_CTRL_READ;
	tod.tod_year	= BCD_TO_BYTE(CLOCK->clk_year) + YRBASE;
	tod.tod_month	= BCD_TO_BYTE(CLOCK->clk_month & 0x1f);
	tod.tod_day	= BCD_TO_BYTE(CLOCK->clk_day & 0x3f);
	tod.tod_dow	= BCD_TO_BYTE(CLOCK->clk_weekday & 0x7);
	tod.tod_hour	= BCD_TO_BYTE(CLOCK->clk_hour & 0x3f);
	tod.tod_min	= BCD_TO_BYTE(CLOCK->clk_min & 0x7f);
	tod.tod_sec	= BCD_TO_BYTE(CLOCK->clk_sec & 0x7f);
	CLOCK->clk_ctrl &= ~CLK_CTRL_READ;

	splx(s);

	/*
	 * Apparently the m48t59 doesn't quite do what the spec sheet says.
	 * The spec says reading WRD will reset the timer but that doesn't work.
	 * So we need to reload timeout each time we want to reset the timer.
	 */
	CLOCK->clk_watchdog = watchdog_bits;

	ts.tv_sec = tod_to_utc(tod);
	ts.tv_nsec = 0;
#else
	ts.tv_sec = 0;
	ts.tv_nsec = 0;
#endif
	return (ts);
}

/*
 * Write the specified time into the clock chip.
 * Must be called with tod_lock held.
 */
/* ARGSUSED */
static void
todm_set(timestruc_t ts)
{
#ifndef	MPSAS
	todinfo_t tod = utc_to_tod(ts.tv_sec);

	ASSERT(MUTEX_HELD(&tod_lock));

	CLOCK->clk_ctrl |= CLK_CTRL_WRITE;	/* allow writes */
	CLOCK->clk_year		= BYTE_TO_BCD(tod.tod_year - YRBASE);
	CLOCK->clk_month	= BYTE_TO_BCD(tod.tod_month);
	CLOCK->clk_day		= BYTE_TO_BCD(tod.tod_day);
	CLOCK->clk_weekday	= BYTE_TO_BCD(tod.tod_dow);
	CLOCK->clk_hour		= BYTE_TO_BCD(tod.tod_hour);
	CLOCK->clk_min		= BYTE_TO_BCD(tod.tod_min);
	CLOCK->clk_sec		= BYTE_TO_BCD(tod.tod_sec);
	CLOCK->clk_ctrl &= ~CLK_CTRL_WRITE;	/* load values */
#endif
}


/*
 * Program the watchdog timer shadow register with the specified value.
 * Setting the timer to zero value means no watchdog timeout.
 */
static uint_t
todm_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	if (watchdog_enable == 0 || watchdog_available == 0 ||
		(boothowto & RB_DEBUG))
			return (0);

	watchdog_timeout = timeoutval;
	watchdog_bits = CLK_WATCHDOG_BITS(timeoutval);
	watchdog_activated = 1;

	return (timeoutval);
}

/*
 * Clear the hardware timer register. Also zero out the watchdog timer
 * shadow register.
 */
static uint_t
todm_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	if (watchdog_activated == 0)
		return (0);

#ifndef	MPSAS
	CLOCK->clk_watchdog = 0;
#endif /* MPSAS */

	watchdog_bits = 0;
	watchdog_activated = 0;
	return (watchdog_timeout);
}

/*
 * program the tod registers for alarm to go off at the specified time
 */
static void
todm_set_power_alarm(timestruc_t ts)
{
#ifndef	MPSAS
	todinfo_t	tod;
	uchar_t	c;

	ASSERT(MUTEX_HELD(&tod_lock));
	tod = utc_to_tod(ts.tv_sec);

	c = CLOCK->clk_flags; /* clear alarm intr flag by reading the reg */
#ifdef lint
	CLOCK->clk_flags = c;
#endif
	CLOCK->clk_interrupts &= ~CLK_ALARM_ENABLE; /* disable alarm intr */

	CLOCK->clk_day &= ~CLK_FREQT; /* keep Freqency Test bit cleared */

	CLOCK->clk_alm_day = BYTE_TO_BCD(tod.tod_day);
	CLOCK->clk_alm_hours = BYTE_TO_BCD(tod.tod_hour);
	CLOCK->clk_alm_mins = BYTE_TO_BCD(tod.tod_min);
	CLOCK->clk_alm_secs = BYTE_TO_BCD(tod.tod_sec);

	CLOCK->clk_interrupts |= CLK_ALARM_ENABLE; /* enable alarm intr */
#endif /* MPSAS */
}

/*
 * clear alarm interrupt
 */
static void
todm_clear_power_alarm()
{
#ifndef	MPSAS
	uchar_t	c;

	ASSERT(MUTEX_HELD(&tod_lock));

	c = CLOCK->clk_flags; /* clear alarm intr flag by reading the reg */

#ifdef lint
	CLOCK->clk_flags = c;
#endif

	CLOCK->clk_interrupts &= ~CLK_ALARM_ENABLE; /* disable alarm intr */
#endif /* MPSAS */
}

/*
 * Determine the cpu frequency by watching the TOD chip rollover twice.
 * Cpu clock rate is determined by computing the ticks added (in tick register)
 * during one second interval on TOD.
 */
uint64_t
todm_get_cpufrequency(void)
{
#ifndef	MPSAS
	ASSERT(MUTEX_HELD(&tod_lock));

	return (find_cpufrequency(&(TIMECHECK_CLOCK->clk_sec)));
#else
	return (cpunodes[CPU->cpu_id].clock_freq);
#endif /* MPSAS */
}
