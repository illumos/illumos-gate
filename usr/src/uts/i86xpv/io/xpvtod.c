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
#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/time.h>
#include <sys/clock.h>
#include <sys/archsystm.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <sys/hypervisor.h>

/*
 * tod driver module for i86xpv
 */

static timestruc_t
todxen_get(tod_ops_t *top)
{
	todinfo_t tod;
	timestruc_t ts, wcts;
	shared_info_t *si = HYPERVISOR_shared_info;
	uint32_t xen_wc_version;
	hrtime_t now;

	ASSERT(MUTEX_HELD(&tod_lock));

	/*
	 * Pick up the wallclock base time
	 */
	do {
		xen_wc_version = si->wc_version;

		membar_consumer();

		wcts.tv_sec = si->wc_sec;
		wcts.tv_nsec = si->wc_nsec;

		membar_consumer();

	} while ((si->wc_version & 1) | (xen_wc_version ^ si->wc_version));

	/*
	 * Compute the TOD as the wallclock (boot) time plus time-since-boot
	 * (/not/ hrtime!) and normalize.
	 */
	now = xpv_getsystime() +
	    (hrtime_t)wcts.tv_nsec + (hrtime_t)wcts.tv_sec * NANOSEC;
	ts.tv_sec = (time_t)(now / NANOSEC);
	ts.tv_nsec = (long)(now % NANOSEC);

	/*
	 * Apply GMT lag correction from /etc/rtc_config to get UTC time
	 */
	ts.tv_sec += ggmtl();

	/*
	 * Validate the TOD in case of total insanity
	 */
	tod = utc_to_tod(ts.tv_sec);
	if (tod.tod_year < 69) {
		static int range_warn = 1;	/* warn only once */

		if (range_warn) {
			/*
			 * If we're dom0, go invoke the underlying driver; the
			 * routine should complain if it discovers something
			 * wrong.
			 */
			if (DOMAIN_IS_INITDOMAIN(xen_info))
				(void) TODOP_GET(top->tod_next);

			/*
			 * Check the virtual hardware.
			 */
			if (tod.tod_year > 38)
				cmn_err(CE_WARN,
				    "hypervisor wall clock is out "
				    "of range -- time needs to be reset");
			range_warn = 0;
		}
		tod.tod_year += 100;
		ts.tv_sec = tod_to_utc(tod);
	}

	return (ts);
}

/*
 * On dom0, invoke the underlying driver to update the physical RTC,
 * and tell the hypervisor to update its idea of global time.
 *
 * On domU, we don't have permission to update the machine's physical RTC,
 * so quietly ignore the attempt.
 */
static void
todxen_set(tod_ops_t *top, timestruc_t ts)
{
	xen_platform_op_t op;

	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		ASSERT(MUTEX_HELD(&tod_lock));
		TODOP_SET(top->tod_next, ts);

		op.cmd = XENPF_settime;
		op.interface_version = XENPF_INTERFACE_VERSION;
		op.u.settime.secs = ts.tv_sec - ggmtl();
		op.u.settime.nsecs = ts.tv_nsec;
		op.u.settime.system_time = xpv_getsystime();
		(void) HYPERVISOR_platform_op(&op);
	}
}

static tod_ops_t todxen_ops = {
	TOD_OPS_VERSION,
	todxen_get,
	todxen_set,
	NULL
};

static struct modlmisc modlmisc = {
	&mod_miscops,
	"TOD module for i86xpv"
};

static struct modlinkage modl = {
	MODREV_1,
	&modlmisc
};

int
_init(void)
{
	/*
	 * In future we might need to do something more sophisticated
	 * for versioning, i.e. dealing with older hardware TOD modules
	 * underneath us, but for now, anything else but "same" is a
	 * fatal error.
	 */
	if (tod_ops->tod_version != todxen_ops.tod_version)
		panic("TOD module version mismatch");

	/*
	 * Stitch the ops vector linkage together, with this module
	 * sitting on the "front" of the ops list.
	 */
	todxen_ops.tod_next = tod_ops;
	tod_ops = &todxen_ops;

	return (mod_install(&modl));
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfo)
{
	return (mod_info(&modl, modinfo));
}
