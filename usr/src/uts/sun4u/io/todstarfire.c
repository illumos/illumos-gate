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
 * tod driver module for Starfire
 * This module implements a soft tod since
 * starfire has no tod part.
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
#include <sys/cpu_sgnblk_defs.h>
#include <starfire/sys/cpu_sgn.h>

static timestruc_t	todsf_get(void);
static void		todsf_set(timestruc_t);
static uint_t		todsf_set_watchdog_timer(uint_t);
static uint_t		todsf_clear_watchdog_timer(void);
static void		todsf_set_power_alarm(timestruc_t);
static void		todsf_clear_power_alarm(void);
static uint64_t		todsf_get_cpufrequency(void);

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "Soft tod module for Starfire"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	if (strcmp(tod_module_name, "todstarfire") == 0) {
		int ssp_time32;
		char obp_string[40];

		/* Set the string to pass to OBP */
		(void) sprintf(obp_string, "h# %p unix-gettod",
		    (void *)&ssp_time32);

		/* Get OBP to get TOD from ssp */
		prom_interpret(obp_string, 0, 0, 0, 0, 0);

		hrestime.tv_sec = (time_t)ssp_time32;

		tod_ops.tod_get = todsf_get;
		tod_ops.tod_set = todsf_set;
		tod_ops.tod_set_watchdog_timer = todsf_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer = todsf_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todsf_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todsf_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todsf_get_cpufrequency;

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
	if (strcmp(tod_module_name, "todstarfire") == 0)
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
 * Simply return hrestime value
 * Must be called with tod_lock held.
 */
static timestruc_t
todsf_get(void)
{
	timestruc_t ts;
	extern cpu_sgnblk_t *cpu_sgnblkp[];

	ASSERT(MUTEX_HELD(&tod_lock));

	ts = hrestime;

	/* Update the heartbeat */
	if (cpu_sgnblkp[CPU->cpu_id] != NULL)
		cpu_sgnblkp[CPU->cpu_id]->sigb_heartbeat++;
	return (ts);
}

/*
 * Null function for now.
 * Must be called with tod_lock held.
 */
/* ARGSUSED */
static void
todsf_set(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}


/*
 * No watchdog function.
 */
/* ARGSUSED */
static uint_t
todsf_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/*
 * No watchdog function
 */
static uint_t
todsf_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/*
 * Null function.
 */
/* ARGSUSED */
static void
todsf_set_power_alarm(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Null function
 */
static void
todsf_clear_power_alarm()
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Get clock freq from the cpunode
 */
uint64_t
todsf_get_cpufrequency(void)
{
	return (cpunodes[CPU->cpu_id].clock_freq);
}
