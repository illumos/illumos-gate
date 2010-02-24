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

#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/clock.h>
#include <sys/intreg.h>
#include <sys/x_call.h>
#include <sys/cpuvar.h>
#include <sys/promif.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/lockstat.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <sys/intr.h>
#include <sys/ivintr.h>
#include <sys/machsystm.h>
#include <sys/reboot.h>
#include <sys/membar.h>
#include <sys/atomic.h>
#include <sys/cpu_module.h>

uint_t sys_clock_mhz = 0;
uint64_t sys_tick_freq = 0;
uint_t cpu_tick_freq = 0;	/* deprecated, tune sys_tick_freq instead */
uint_t scaled_clock_mhz = 0;
uint_t nsec_per_sys_tick;
uint_t sticks_per_usec;
char clock_started = 0;

/*
 * Hardware watchdog parameters and knobs
 */
int watchdog_enable = 0;		/* user knob */
int watchdog_available = 0;		/* system has a watchdog */
int watchdog_activated = 0;		/* the watchdog is armed */
uint_t watchdog_timeout_seconds = CLK_WATCHDOG_DEFAULT;

/*
 * tod module name and operations
 */
struct tod_ops	tod_ops;
char		*tod_module_name;


void
clkstart(void)
{
	int ret = 0;

	/*
	 * Now is a good time to activate hardware watchdog (if one exists).
	 */
	mutex_enter(&tod_lock);
	if (watchdog_enable)
		ret = tod_ops.tod_set_watchdog_timer(watchdog_timeout_seconds);
	mutex_exit(&tod_lock);
	if (ret != 0)
		printf("Hardware watchdog enabled\n");
}

/*
 * preset the delay constant for drv_usecwait(). This is done for early
 * use of the le or scsi drivers in the kernel. The default contant
 * might be too high early on. We can get a pretty good approximation
 * of this by setting it as:
 *
 * 	sys_clock_mhz = (sys_tick_freq + 500000) / 1000000
 *
 * setcpudelay is called twice during the boot process. The first time
 * is before the TOD driver is loaded so cpu_init_tick_freq cannot
 * calibrate sys_tick_freq but can only set it to the prom value. The
 * first call is also before /etc/system is read.
 *
 * Only call cpu_init_tick_freq the second time around if sys_tick_freq
 * has not been tuned via /etc/system.
 */
void
setcpudelay(void)
{
	static uint64_t sys_tick_freq_save = 0;
	/*
	 * We want to allow cpu_tick_freq to be tunable; we'll only set it
	 * if it hasn't been explicitly tuned.
	 */
	if (cpu_tick_freq != 0) {
		cmn_err(CE_WARN, "cpu_tick_freq is no longer a kernel "
		    "tunable, use sys_tick_freq instead");
		sys_tick_freq = cpu_tick_freq;
	}
	if (sys_tick_freq == sys_tick_freq_save) {
		cpu_init_tick_freq();
		sys_tick_freq_save = sys_tick_freq;
	}
	ASSERT(sys_tick_freq != 0);

	/*
	 * See the comments in clock.h for a full description of
	 * nsec_scale.  The "& ~1" operation below ensures that
	 * nsec_scale is always even, so that for *any* value of
	 * %tick, multiplying by nsec_scale clears NPT for free.
	 */
	nsec_scale = (uint_t)(((u_longlong_t)NANOSEC << (32 - nsec_shift)) /
	    sys_tick_freq) & ~1;

	/*
	 * scaled_clock_mhz is a more accurated (ie not rounded-off)
	 * version of sys_clock_mhz that we used to program the tick
	 * compare register. Just in case sys_tick_freq is like 142.5 Mhz
	 * instead of some whole number like 143
	 */

	scaled_clock_mhz = (sys_tick_freq) / 1000;
	sys_clock_mhz = (sys_tick_freq + 500000) / 1000000;

	nsec_per_sys_tick = NANOSEC / sys_tick_freq;

	/*
	 * Pre-calculate number of sticks per usec for drv_usecwait.
	 */
	sticks_per_usec = MAX((sys_tick_freq + (MICROSEC - 1)) / MICROSEC, 1);

	if (sys_clock_mhz <= 0) {
		cmn_err(CE_WARN, "invalid system frequency");
	}
}

timestruc_t
tod_get(void)
{
	timestruc_t ts = tod_ops.tod_get();
	ts.tv_sec = tod_validate(ts.tv_sec);
	return (ts);
}

extern void tod_set_prev(timestruc_t);

void
tod_set(timestruc_t ts)
{
	tod_set_prev(ts);		/* for tod_validate() */
	tod_ops.tod_set(ts);
	tod_status_set(TOD_SET_DONE);	/* TOD was modified */
}


/*
 * The following wrappers have been added so that locking
 * can be exported to platform-independent clock routines
 * (ie adjtime(), clock_setttime()), via a functional interface.
 */
int
hr_clock_lock(void)
{
	ushort_t s;

	CLOCK_LOCK(&s);
	return (s);
}

void
hr_clock_unlock(int s)
{
	CLOCK_UNLOCK(s);
}

/*
 * We don't share the trap table with the prom, so we don't need
 * to enable/disable its clock.
 */
void
mon_clock_init(void)
{}

void
mon_clock_start(void)
{}

void
mon_clock_stop(void)
{}

void
mon_clock_share(void)
{}

void
mon_clock_unshare(void)
{}
