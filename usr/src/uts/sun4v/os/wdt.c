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
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/hypervisor_api.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>

#define	WDT_ON			1
#define	WDT_OFF			0
#define	WDT_DEFAULT_RESOLUTION	10		/* 10 milliseconds */
/*
 * MILLISEC defines the number of milliseconds in a second.
 */
#define	WDT_MAX_RESOLUTION	(1 * MILLISEC)	/* 1 second */
#define	WDT_REGULAR_TIMEOUT	(10 * MILLISEC)	/* 10 seconds */
#define	WDT_LONG_TIMEOUT	(60 * MILLISEC)	/* 60 seconds */
#define	WDT_MIN_COREAPI_MAJOR	1
#define	WDT_MIN_COREAPI_MINOR	1
/*
 * The ratio to calculate the watchdog timer pat interval.
 */
#define	WDT_PAT_INTERVAL(x)	((x) / 2)

int watchdog_enabled = 1;

static void set_watchdog_pat_intervals(void);
static void config_watchdog(uint64_t, int);

/*
 * Flag used to pat/suspend/resume the watchdog timer.
 */
int watchdog_activated = WDT_OFF;
static uint64_t watchdog_regular_timeout = WDT_REGULAR_TIMEOUT;
static uint64_t watchdog_long_timeout = 0;
static uint64_t watchdog_resolution = WDT_DEFAULT_RESOLUTION;
static int64_t watchdog_last_pat = 0;	/* The time of last pat. */
static int64_t last_pat_interval = 0;	/* The pat interval of last pat. */
static int64_t watchdog_long_pat_interval = 0;
static int64_t watchdog_regular_pat_interval = 0;

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
		&watchdog_max_timeout)) {
		cmn_err(CE_WARN, "Cannot read watchdog-max-timeout, watchdog "
			"is disabled.");
		watchdog_enabled = 0;
		kmem_free(listp, listsz);
		(void) md_fini_handle(mdp);
		return;
	}

	if (watchdog_max_timeout < WDT_REGULAR_TIMEOUT) {
		cmn_err(CE_WARN, "Invalid watchdog-max-timeout value, watchdog "
			"is disabled.");
		watchdog_enabled = 0;
		kmem_free(listp, listsz);
		(void) md_fini_handle(mdp);
		return;
	}

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
		watchdog_resolution > WDT_MAX_RESOLUTION) {
		watchdog_resolution = WDT_DEFAULT_RESOLUTION;
	}
	kmem_free(listp, listsz);
	(void) md_fini_handle(mdp);

	watchdog_long_timeout = MIN(WDT_LONG_TIMEOUT, watchdog_max_timeout);

	/*
	 * round the timeout to the nearest smaller value.
	 */
	watchdog_long_timeout -=
		watchdog_long_timeout % watchdog_resolution;
	watchdog_regular_timeout -=
		watchdog_regular_timeout % watchdog_resolution;
	set_watchdog_pat_intervals();

	config_watchdog(watchdog_regular_timeout, WDT_ON);
}

/*
 * Pat the watchdog timer periodically, for regular pat in tod_get when
 * the kernel runs normally and long pat in deadman when panicking.
 */
void
watchdog_pat()
{
	int64_t pat_interval;
	int64_t current_lbolt64;
	uint64_t timeout;

	if (watchdog_enabled && watchdog_activated) {
		if (panicstr) {
			/*
			 * long timeout is only used while panicking.
			 */
			timeout = watchdog_long_timeout;
			pat_interval = watchdog_long_pat_interval;
		} else {
			timeout = watchdog_regular_timeout;
			pat_interval = watchdog_regular_pat_interval;
		}

		current_lbolt64 = lbolt64;

		if ((current_lbolt64 - watchdog_last_pat)
			>= last_pat_interval) {
			/*
			 * Pat the watchdog via hv api:
			 */
			config_watchdog(timeout, WDT_ON);

			last_pat_interval = pat_interval;
			watchdog_last_pat = current_lbolt64;
		}
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
			config_watchdog(watchdog_regular_timeout, WDT_ON);
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

/*
 * Set the pat intervals for both regular (when Solaris is running),
 * and long timeout (i.e., when panicking) cases.
 */
static void
set_watchdog_pat_intervals(void)
{
	watchdog_regular_pat_interval =
		MSEC_TO_TICK(WDT_PAT_INTERVAL(watchdog_regular_timeout));
	watchdog_long_pat_interval =
		MSEC_TO_TICK(WDT_PAT_INTERVAL(watchdog_long_timeout));
}

static void
config_watchdog(uint64_t timeout, int new_state)
{
	uint64_t time_remaining;
	uint64_t ret;

	watchdog_activated = new_state;
	ret = hv_mach_set_watchdog(timeout, &time_remaining);
	if (ret != H_EOK) {
		cmn_err(CE_WARN, "Failed to operate on the watchdog. "
			"Error = 0x%lx", ret);
		watchdog_enabled = 0;
	}
}
