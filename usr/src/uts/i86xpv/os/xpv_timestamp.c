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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/clock.h>
#include <sys/panic.h>
#include <sys/atomic.h>
#include <sys/hypervisor.h>

#include <sys/archsystm.h>

/*
 * On the hypervisor, we have a virtualized system time based upon the
 * information provided for each VCPU, which is updated every time it is
 * scheduled onto a real CPU.  Thus, none of the traditional code in
 * i86pc/os/timestamp.c applies, our gethrtime() implementation is run through
 * the PSM, and there is no scaling step to apply.
 *
 * However, the platform does not guarantee monotonicity; thus we have to fake
 * this up, which is a deeply unpleasant thing to have to do.
 *
 * Note that the virtualized interface still relies on the current TSC to
 * calculate the time in nanoseconds since the VCPU was scheduled, and is thus
 * subject to all the problems with that.  For the most part, the hypervisor is
 * supposed to deal with them.
 *
 * Another wrinkle involves suspend/resume/migration.  If we come back and time
 * is apparently less, we may have resumed on a different machine or on the
 * same machine after a reboot.  In this case we need to maintain an addend to
 * ensure time continues reasonably.  Otherwise we could end up taking a very
 * long time to expire cyclics in the heap.  Thus we have two functions:
 *
 * xpv_getsystime()
 *
 *	The unadulterated system time from the hypervisor.  This is only to be
 *	used when programming the hypervisor (setting a timer or calculating
 *	the TOD).
 *
 * xpv_gethrtime()
 *
 *	This is the monotonic hrtime counter to be used by everything else such
 *	as the cyclic subsystem.  We should never pass an hrtime directly into
 *	a hypervisor interface, as hrtime_addend may well be non-zero.
 */

int hrtime_fake_mt = 1;
static volatile hrtime_t hrtime_last;
static hrtime_t hrtime_suspend_time;
static hrtime_t hrtime_addend;

volatile uint32_t hres_lock;
hrtime_t hres_last_tick;
int64_t hrestime_adj;
volatile timestruc_t hrestime;

/*
 * These functions are used in DTrace probe context, and must be removed from
 * fbt consideration.  Currently fbt ignores all weak symbols, so this will
 * achieve that.
 */
#pragma weak xpv_gethrtime = dtrace_xpv_gethrtime
#pragma weak xpv_getsystime = dtrace_xpv_getsystime
#pragma weak dtrace_gethrtime = dtrace_xpv_gethrtime
#pragma weak tsc_read = dtrace_xpv_gethrtime

hrtime_t
dtrace_xpv_getsystime(void)
{
	vcpu_time_info_t *src;
	vcpu_time_info_t __vti, *dst = &__vti;
	uint64_t tsc_delta;
	uint64_t tsc;
	hrtime_t result;
	uint32_t stamp;

	src = &CPU->cpu_m.mcpu_vcpu_info->time;

	/*
	 * Loop until version has not been changed during our update, and a Xen
	 * update is not under way (lowest bit is set).
	 */
	do {
		dst->version = src->version;
		stamp = CPU->cpu_m.mcpu_istamp;

		membar_consumer();

		dst->tsc_timestamp = src->tsc_timestamp;
		dst->system_time = src->system_time;
		dst->tsc_to_system_mul = src->tsc_to_system_mul;
		dst->tsc_shift = src->tsc_shift;

		/*
		 * Note that this use of the -actual- TSC register
		 * should probably be the SOLE one in the system on this
		 * paravirtualized platform.
		 */
		tsc = __rdtsc_insn();
		tsc_delta = tsc - dst->tsc_timestamp;

		membar_consumer();

	} while (((src->version & 1) | (dst->version ^ src->version)) ||
	    CPU->cpu_m.mcpu_istamp != stamp);

	if (dst->tsc_shift >= 0)
		tsc_delta <<= dst->tsc_shift;
	else if (dst->tsc_shift < 0)
		tsc_delta >>= -dst->tsc_shift;

	result = dst->system_time +
	    ((uint64_t)(tsc_delta * (uint64_t)dst->tsc_to_system_mul) >> 32);

	return (result);
}

hrtime_t
dtrace_xpv_gethrtime(void)
{
	hrtime_t result = xpv_getsystime() + hrtime_addend;

	if (hrtime_fake_mt) {
		hrtime_t last;
		do {
			last = hrtime_last;
			if (result < last)
				result = last + 1;
		} while (atomic_cas_64((volatile uint64_t *)&hrtime_last,
		    last, result) != last);
	}

	return (result);
}

void
xpv_time_suspend(void)
{
	hrtime_suspend_time = xpv_getsystime();
}

void
xpv_time_resume(void)
{
	hrtime_t delta = xpv_getsystime() - hrtime_suspend_time;

	if (delta < 0)
		hrtime_addend += -delta;
}
