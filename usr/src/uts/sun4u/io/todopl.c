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

/*
 * tod driver module for OPL (implements a soft tod)
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
#include <sys/cmn_err.h>
#include <sys/prom_plat.h>
#include <sys/cpuvar.h>
#include <sys/opl_module.h>

/*
 * Debug stuff
 */
#ifdef DEBUG
int todopl_debug = 0;
#define	TODOPL_DEBUG(args)  if (todopl_debug) cmn_err args
#else
#define	TODOPL_DEBUG(args)
#endif

#define	abs(x)	((x) < 0 ? -(x) : (x))

#define	TODOPL_SET_THRESHOLD	30

static timestruc_t	todopl_get(void);
static void		todopl_set(timestruc_t);
static uint_t		todopl_set_watchdog_timer(uint_t);
static uint_t		todopl_clear_watchdog_timer(void);
static void		todopl_set_power_alarm(timestruc_t);
static void		todopl_clear_power_alarm(void);
static uint64_t		todopl_get_cpufrequency(void);

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "Soft tod module for OPL 1.11"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

/*
 * The TOD OPL logic description.
 *
 * The todopl driver uses promif functions prom_opl_get_tod() and
 * prom_opl_set_diff(). These functions call FJSV,get-tod and
 * FJSV,set-domain-time OBP client services.
 *
 * At the system boot or reboot:
 *
 *    FJSV,tod-get
 * OS  --------->   OBP     SCF I/F
 *                         ----------->  XSCF
 *                         <-----------
 *     <--------            time, diff
 *    time+diff, stick
 *
 * Note that on first powerup domain boot, diff is zero.
 *
 * When system updates the time via date(1):
 *
 *   FJSV,set-domain-time
 * OS   --------->   OBP                      SRAM
 *      diff_delta        diff += diff_delta ------------->  XSCF
 *
 * diff_delta = new time -  current domain time (hrestime)
 *
 *
 * In theory, FJSV,get-tod and FJSV,set-domain-time should never fails.
 * But, if call to FJSV,get-tod fails on boot, the domain will be unable
 * to calculate "diff" properly and synchronization between Domain and
 * SP will be broken. In this particular case, we notify users that
 * "there is no time synchronization" and the logic will attempt to
 * resync with the SP whenever the OS tries to do a TOD update.
 * (e.g. via date(1) or NTP).
 */

static	int enable_time_sync = 1;

int
_init(void)
{
	int64_t	stick;
	time_t	obp_time = 0;
	int64_t obp_stick;

	if (strcmp(tod_module_name, "todopl") == 0) {
		/*
		 * Get TOD time from OBP and adjust it.
		 */
		prom_opl_get_tod(&obp_time, &obp_stick);

		TODOPL_DEBUG((CE_NOTE, "todopl: OBP time 0x%lx stick 0x%lx\n",
			obp_time, obp_stick));

		if (obp_time != 0) {
			/*
			 * adjust OBP time by stick counts
			 */
			stick_timestamp(&stick);
			obp_time += ((stick - obp_stick) / system_clock_freq);

			TODOPL_DEBUG((CE_NOTE,
				"todopl: cpu stick 0x%lx sys_time 0x%lx\n",
				stick, obp_time));
		} else {
			/*
			 * A date of zero causes the root filesystem driver
			 * to try to set the date from the last shutdown.
			 */
			enable_time_sync = 0;
			cmn_err(CE_WARN, "Initial date is invalid.");
			cmn_err(CE_CONT, "Attempting to set the date and time "
				"based on the last shutdown.\n");
			cmn_err(CE_CONT, "The time could not be synchronized "
				"between Domain and Service Processor.\n");
			cmn_err(CE_CONT, "Please inspect the date and time and "
				"correct if necessary.\n");
		}

		hrestime.tv_sec = obp_time;

		/*
		 * Check that the date has not overflowed a 32-bit integer.
		 */
		if (TIMESPEC_OVERFLOW(&hrestime)) {
			cmn_err(CE_WARN, "Date overflow detected.");
			cmn_err(CE_CONT, "Attempting to set the date and time "
				"based on the last shutdown.\n");
			cmn_err(CE_CONT, "Please inspect the date and time and "
				"correct if necessary.\n");

			hrestime.tv_sec = (time_t)0;
		}

		tod_ops.tod_get = todopl_get;
		tod_ops.tod_set = todopl_set;
		tod_ops.tod_set_watchdog_timer = todopl_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer = todopl_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todopl_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todopl_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todopl_get_cpufrequency;

		/*
		 * Flag warning if user tried to use hardware watchdog
		 */
		if (watchdog_enable) {
			cmn_err(CE_WARN, "Hardware watchdog unavailable");
		}
	}

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	if (strcmp(tod_module_name, "todopl") == 0)
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
 * OPL tod_get is simplified to return hrestime
 * Must be called with tod_lock held.
 */
static timestruc_t
todopl_get(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (hrestime);
}

/*
 * Must be called with tod_lock held.
 *
 * When running NTP, tod_set is called at least once per second in order
 * to update the hardware clock. To minimize pressure on SP, we want only
 * to record significant time changes on the SP (when date(1) is run).
 * We have 30 seconds threshold requirement before recording the time change.
 */
/* ARGSUSED */
static void
todopl_set(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	if (abs(ts.tv_sec - hrestime.tv_sec) > TODOPL_SET_THRESHOLD) {
		/*
		 * Send time difference to SP
		 */
		if (enable_time_sync)
			prom_opl_set_diff(ts.tv_sec - hrestime.tv_sec);
		else {
			/*
			 * We did not get a successful initial time
			 * update/sync from the SP via OBP during boot.
			 * Try again here.
			 */
			time_t  obp_time = 0;
			int64_t obp_stick;
			int64_t stick;

			prom_opl_get_tod(&obp_time, &obp_stick);

			if (obp_time != 0) {
				/*
				 * adjust OBP time by stick counts
				 */
				stick_timestamp(&stick);
				obp_time += ((stick - obp_stick) /
					system_clock_freq);

				/*
				 * Sync up by computing the diff using the
				 * newly acquired SP/OBP reference time
				 */
				prom_opl_set_diff(ts.tv_sec - obp_time);

				enable_time_sync = 1;
			}
		}
		TODOPL_DEBUG((CE_NOTE, "todopl_set: new domain time 0x%lx\n",
			ts.tv_sec));
	}
}

/*
 * No watchdog function.
 */
/* ARGSUSED */
static uint_t
todopl_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/*
 * No watchdog function
 */
static uint_t
todopl_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/*
 * Null function.
 */
/* ARGSUSED */
static void
todopl_set_power_alarm(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Null function
 */
static void
todopl_clear_power_alarm()
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Get clock freq from the cpunode.  This function is only called
 * when use_stick = 0, otherwise, system_clock_freq gets used instead.
 */
uint64_t
todopl_get_cpufrequency(void)
{
	return (cpunodes[CPU->cpu_id].clock_freq);
}
