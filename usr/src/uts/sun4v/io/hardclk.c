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
#include <sys/hypervisor_api.h>
#include <sys/wdt.h>

uint_t sys_clock_mhz = 0;
uint64_t sys_tick_freq = 0;
uint_t cpu_tick_freq = 0;	/* deprecated, tune sys_tick_freq instead */
uint_t scaled_clock_mhz = 0;
uint_t nsec_per_sys_tick;
uint_t sticks_per_usec;
char clock_started = 0;

void
clkstart(void)
{
	/*
	 * Now is a good time to activate hardware watchdog.
	 */
	watchdog_init();
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

/*
 * Hypervisor can return one of two error conditions
 * for the TOD_GET API call. 1) H_ENOTSUPPORTED 2) H_EWOULDBLOCK
 *
 * To handle the H_ENOTSUPPORTED we return 0 seconds and let clkset
 * set tod_broken.
 * To handle the H_EWOULDBLOCK we retry for about 500usec and
 * return hrestime if we can't successfully get a value.
 */
timestruc_t
tod_get(void)
{
	timestruc_t ts;
	uint64_t seconds;
	int i;
	unsigned int spl_old;
	uint64_t ret;

	/*
	 * Make sure we don't get preempted
	 * while getting the tod value.
	 * getting preempted could mean we always
	 * hit the hypervisor during an update
	 * and always get EWOULDBLOCK.
	 */

	spl_old = ddi_enter_critical();
	for (i = 0; i <= HV_TOD_RETRY_THRESH; i++) {
		ret = hv_tod_get(&seconds);

		if (ret != H_EWOULDBLOCK)
			break;
		drv_usecwait(HV_TOD_WAIT_USEC);
	}
	ddi_exit_critical(spl_old);

	ts.tv_nsec = 0;
	if (ret != H_EOK) {

		switch (ret) {
		default:
			cmn_err(CE_WARN,
			    "tod_get: unknown error from hv_tod_get, %lx\n",
			    ret);
			/*FALLTHRU*/
		case H_EWOULDBLOCK:
			/*
			 * We timed out
			 */
			tod_status_set(TOD_GET_FAILED);
			ts.tv_sec = tod_validate(hrestime.tv_sec);
			break;

		case H_ENOTSUPPORTED:
			ts.tv_sec = 0;
			break;
		};
	} else {
		ts.tv_sec = tod_validate(seconds);
	}

	return (ts);
}

extern void tod_set_prev(timestruc_t);

/*ARGSUSED*/
void
tod_set(timestruc_t ts)
{
	int i;
	uint64_t ret;

	/* for tod_validate() */
	tod_set_prev(ts);

	for (i = 0; i <= HV_TOD_RETRY_THRESH; i++) {
		ret = hv_tod_set(ts.tv_sec);
		if (ret != H_EWOULDBLOCK)
			break;
		drv_usecwait(HV_TOD_WAIT_USEC);
	}

	if (ret != H_EOK && ret != H_ENOTSUPPORTED && ret != H_EWOULDBLOCK)
		cmn_err(CE_WARN,
		    "tod_set: Unknown error from hv_tod_set, err %lx", ret);
	else
		/* TOD was modified */
		tod_status_set(TOD_SET_DONE);
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
