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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * tod driver module for Starcat
 * This module implements a soft tod since
 * starcat has no tod part.
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
#include <sys/promif.h>
#include <sys/cpuvar.h>
#include <sys/sunddi.h>
#include <sys/iosramio.h>
#include <sys/domaind.h>

#define	abs(x)	((x) < 0 ? -(x) : (x))

#define	TODSC_SET_THRESHOLD	30

static timestruc_t	todsc_get(void);
static void		todsc_set(timestruc_t);
static uint_t		todsc_set_watchdog_timer(uint_t);
static uint_t		todsc_clear_watchdog_timer(void);
static void		todsc_set_power_alarm(timestruc_t);
static void		todsc_clear_power_alarm(void);
static uint64_t		todsc_get_cpufrequency(void);

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "Soft tod module for Sun Fire 15000"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static uint32_t heartbeat = 0;

int
_init(void)
{
	if (strcmp(tod_module_name, "todstarcat") == 0) {
		uint32_t ssc_time32 = 0;
		char obp_string[40];

		/*
		 * To obtain the initial start of day time, we use an
		 * OBP callback; this is because the iosram is not yet
		 * accessible from the OS at this early stage of startup.
		 */

		/*
		 * Set the string to pass to OBP
		 * for now, we assume we always get a 32bit value
		 */
		(void) sprintf(obp_string, "h# %p unix-gettod",
			(void *) &ssc_time32);

		prom_interpret(obp_string, 0, 0, 0, 0, 0);

		hrestime.tv_sec = (time_t)ssc_time32;

		/*
		 * A date of zero causes the root filesystem driver
		 * to try to set the date from the last shutdown.
		 */

		/*
		 * Check for a zero date.
		 */
		if (ssc_time32 == 0) {
			cmn_err(CE_WARN, "Initial date is invalid.");
			cmn_err(CE_CONT, "Attempting to set the date and time "
				"based on the last shutdown.\n");
			cmn_err(CE_CONT, "Please inspect the date and time and "
				"correct if necessary.\n");
		}

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

		tod_ops.tod_get = todsc_get;
		tod_ops.tod_set = todsc_set;
		tod_ops.tod_set_watchdog_timer = todsc_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer = todsc_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todsc_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todsc_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todsc_get_cpufrequency;

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
	if (strcmp(tod_module_name, "todstarcat") == 0)
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
 * Starcat tod_get is simplified to return hrestime and to
 * update the domain heartbeat.
 * Must be called with tod_lock held.
 */
static timestruc_t
todsc_get(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	heartbeat++;
	(void) iosram_wr(DOMD_MAGIC, DOMD_HEARTBEAT_OFFSET,
		sizeof (uint32_t), (caddr_t)&heartbeat);
	return (hrestime);
}

/*
 * Must be called with tod_lock held.
 *
 * When running NTP, tod_set is called at least once per second in order
 * to update the hardware clock - for Starcat, we don't want to sync
 * the non-existent hardware clock, and only want to record significant
 * time changes on the SC (i.e. when date(1M) is run).  So, we have a
 * threshold requirement before recording the time change.
 */
/* ARGSUSED */
static void
todsc_set(timestruc_t ts)
{
	char obp_string[40];

	ASSERT(MUTEX_HELD(&tod_lock));

	heartbeat++;
	(void) iosram_wr(DOMD_MAGIC, DOMD_HEARTBEAT_OFFSET,
		sizeof (uint32_t), (caddr_t)&heartbeat);

	if (abs(hrestime.tv_sec - ts.tv_sec) > TODSC_SET_THRESHOLD) {
		/*
		 * Update the SSC with the new UTC domain time
		 */
		(void) sprintf(obp_string, "h# %x unix-settod",
			(int)ts.tv_sec);

		prom_interpret(obp_string, 0, 0, 0, 0, 0);
#ifdef DEBUG
		cmn_err(CE_NOTE, "todsc_set: new domain time 0x%lx\n",
			ts.tv_sec);
#endif
	}
}

/*
 * No watchdog function.
 */
/* ARGSUSED */
static uint_t
todsc_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/*
 * No watchdog function
 */
static uint_t
todsc_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/*
 * Null function.
 */
/* ARGSUSED */
static void
todsc_set_power_alarm(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Null function
 */
static void
todsc_clear_power_alarm()
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Get clock freq from the cpunode.  This function is only called
 * when use_stick = 0, otherwise, system_clock_freq gets used instead.
 */
uint64_t
todsc_get_cpufrequency(void)
{
	return (cpunodes[CPU->cpu_id].clock_freq);
}
