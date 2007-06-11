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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/hsvc.h>
#include <sys/wdt.h>
#include <sys/cmn_err.h>
#include <sys/cyclic.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/hypervisor_api.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>

#define	WDT_ON			1
#define	WDT_OFF			0

/*
 * MILLISEC defines the number of milliseconds in a second.
 */
#define	WDT_DEFAULT_RESOLUTION	(1 * MILLISEC)	/* Default resolution = 1s */
#define	WDT_MIN_TIMEOUT		(1 * MILLISEC)	/* Minimum timeout = 1s */
#define	WDT_REGULAR_TIMEOUT	(10 * MILLISEC)	/* Default timeout = 10s */
#define	WDT_LONG_TIMEOUT	(60 * MILLISEC)	/* Long timeout = 60s */

#define	WDT_MIN_COREAPI_MAJOR	1
#define	WDT_MIN_COREAPI_MINOR	1

static void config_watchdog(uint64_t, int);
static void watchdog_cyclic_init(hrtime_t);

/*
 * Flag used to pat/suspend/resume the watchdog timer.
 */
int watchdog_activated = WDT_OFF;

/*
 * Tuneable to control watchdog functionality. Watchdog can be
 * disabled via /etc/system.
 */
int watchdog_enabled = 1;
static int watchdog_initialized = 0;

/*
 * The following tuneable can be set via /etc/system to control
 * watchdog pat frequency, which is set to approximately 44% of
 * the timeout value.
 */
static uint64_t watchdog_timeout = WDT_REGULAR_TIMEOUT;

static uint64_t watchdog_long_timeout = WDT_LONG_TIMEOUT;
static uint64_t watchdog_resolution = WDT_DEFAULT_RESOLUTION;

void
watchdog_init(void)
{
	int num_nodes;
	int nplat;
	md_t *mdp;
	mde_cookie_t *listp = NULL;
	int listsz;
	uint64_t major;
	uint64_t minor;
	uint64_t watchdog_max_timeout;
	hrtime_t cyclic_interval;

	if (!watchdog_enabled) {
		return;
	}

	if (hsvc_version(HSVC_GROUP_CORE, &major, &minor) != 0 ||
	    major != WDT_MIN_COREAPI_MAJOR ||
	    minor < WDT_MIN_COREAPI_MINOR) {
		cmn_err(CE_NOTE, "Disabling watchdog as watchdog services are "
		    "not available\n");
		watchdog_enabled = 0;
		return;
	}

	/*
	 * Get the watchdog-max-timeout and watchdog-resolution MD properties.
	 */
	if ((mdp = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "Unable to initialize machine description, "
		    "watchdog is disabled.");
		watchdog_enabled = 0;
		return;
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);

	nplat = md_scan_dag(mdp, md_root_node(mdp),
	    md_find_name(mdp, "platform"), md_find_name(mdp, "fwd"), listp);

	ASSERT(nplat == 1);

	if (md_get_prop_val(mdp, listp[0], "watchdog-max-timeout",
	    &watchdog_max_timeout) || watchdog_max_timeout < WDT_MIN_TIMEOUT) {
		cmn_err(CE_WARN, "Invalid watchdog-max-timeout, watchdog "
		    "is disabled.");
		watchdog_enabled = 0;
		kmem_free(listp, listsz);
		(void) md_fini_handle(mdp);
		return;
	}

	/*
	 * Make sure that watchdog timeout value is within limits.
	 */
	if (watchdog_timeout < WDT_MIN_TIMEOUT)
		watchdog_timeout = WDT_MIN_TIMEOUT;
	else if (watchdog_timeout > WDT_LONG_TIMEOUT)
		watchdog_timeout = WDT_LONG_TIMEOUT;

	if (watchdog_timeout > watchdog_max_timeout)
		watchdog_timeout = watchdog_max_timeout;

	if (watchdog_long_timeout > watchdog_max_timeout)
		watchdog_long_timeout = watchdog_max_timeout;

	if (md_get_prop_val(mdp, listp[0], "watchdog-resolution",
	    &watchdog_resolution)) {
		cmn_err(CE_WARN, "Cannot read watchdog-resolution, watchdog "
		    "is disabled.");
		watchdog_enabled = 0;
		kmem_free(listp, listsz);
		(void) md_fini_handle(mdp);
		return;
	}

	if (watchdog_resolution == 0 ||
	    watchdog_resolution > WDT_DEFAULT_RESOLUTION)
		watchdog_resolution = WDT_DEFAULT_RESOLUTION;

	kmem_free(listp, listsz);
	(void) md_fini_handle(mdp);

	/*
	 * round the timeout to the nearest smaller value.
	 */
	watchdog_long_timeout -=
	    watchdog_long_timeout % watchdog_resolution;
	watchdog_timeout -=
	    watchdog_timeout % watchdog_resolution;

	/*
	 * Cyclic need to be fired twice the frequency of regular
	 * watchdog timeout. Pedantic here and setting cyclic
	 * frequency to approximately 44% of watchdog_timeout.
	 */
	cyclic_interval = (watchdog_timeout >> 1) - (watchdog_timeout >> 4);
	/*
	 * Note that regular timeout interval is in millisecond,
	 * therefore to get cyclic interval in nanosecond need to
	 * multiply by MICROSEC.
	 */
	cyclic_interval *= MICROSEC;

	watchdog_cyclic_init(cyclic_interval);
	watchdog_initialized = 1;
	config_watchdog(watchdog_timeout, WDT_ON);
}

/*
 * Pat the watchdog timer periodically using the hypervisor API.
 * Regular pat occurs when the system runs normally.
 * Long pat is when system panics.
 */
void
watchdog_pat()
{
	if (watchdog_enabled && watchdog_activated) {
		if (panicstr)
			config_watchdog(watchdog_long_timeout, WDT_ON);
		else
			config_watchdog(watchdog_timeout, WDT_ON);
	}
}

/*
 * We don't save/restore the remaining watchdog timeout time at present.
 */
void
watchdog_suspend()
{
	if (watchdog_enabled && watchdog_activated) {
		config_watchdog(0, WDT_OFF);
	}
}

/*
 * We don't save/restore the remaining watchdog timeout time at present.
 */
void
watchdog_resume()
{
	if (watchdog_enabled && !watchdog_activated) {
		if (panicstr) {
			config_watchdog(watchdog_long_timeout, WDT_ON);
		} else {
			config_watchdog(watchdog_timeout, WDT_ON);
		}
	}
}

void
watchdog_clear()
{
	if (watchdog_enabled && watchdog_activated) {
		config_watchdog(0, WDT_OFF);
	}
}

static void
config_watchdog(uint64_t timeout, int new_state)
{
	uint64_t time_remaining;
	uint64_t ret;

	if (watchdog_initialized) {
		watchdog_activated = new_state;
		ret = hv_mach_set_watchdog(timeout, &time_remaining);
		if (ret != H_EOK) {
			cmn_err(CE_WARN, "Failed to operate on the watchdog. "
			    "Error = 0x%lx", ret);
			watchdog_enabled = 0;
		}
	}
}

/*
 * Once the watchdog cyclic is initialized, it won't be removed.
 * The only way to not add the watchdog cyclic is to disable the watchdog
 * by setting the watchdog_enabled to 0 in /etc/system file.
 */
static void
watchdog_cyclic_init(hrtime_t wdt_cyclic_interval)
{
	cyc_handler_t hdlr;
	cyc_time_t when;

	hdlr.cyh_func = (cyc_func_t)watchdog_pat;
	hdlr.cyh_level = CY_HIGH_LEVEL;
	hdlr.cyh_arg = NULL;

	when.cyt_when = 0;
	when.cyt_interval = wdt_cyclic_interval;

	mutex_enter(&cpu_lock);
	(void) cyclic_add(&hdlr, &when);
	mutex_exit(&cpu_lock);
}
