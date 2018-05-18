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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/time.h>
#include <sys/psm.h>
#include <sys/psm_common.h>
#include <sys/apic.h>
#include <sys/pit.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/cpuvar.h>
#include <sys/clock.h>
#include <sys/apic_timer.h>

/*
 * preferred apic timer mode, allow tuning from the /etc/system file.
 */
int		apic_timer_preferred_mode = APIC_TIMER_MODE_DEADLINE;

int		apic_oneshot = 0;
uint_t		apic_hertz_count;
uint_t		apic_nsec_per_intr = 0;
uint64_t	apic_ticks_per_SFnsecs;		/* # of ticks in SF nsecs */

static int		apic_min_timer_ticks = 1; /* minimum timer tick */
static hrtime_t		apic_nsec_max;

static void	periodic_timer_enable(void);
static void	periodic_timer_disable(void);
static void	periodic_timer_reprogram(hrtime_t);
static void	oneshot_timer_enable(void);
static void	oneshot_timer_disable(void);
static void	oneshot_timer_reprogram(hrtime_t);
static void	deadline_timer_enable(void);
static void	deadline_timer_disable(void);
static void	deadline_timer_reprogram(hrtime_t);

extern int	apic_clkvect;
extern uint32_t	apic_divide_reg_init;

/*
 * apic timer data structure
 */
typedef struct apic_timer {
	int	mode;
	void	(*apic_timer_enable_ops)(void);
	void	(*apic_timer_disable_ops)(void);
	void	(*apic_timer_reprogram_ops)(hrtime_t);
} apic_timer_t;

static apic_timer_t	apic_timer;

/*
 * apic timer initialization
 *
 * For the one-shot mode request case, the function returns the
 * resolution (in nanoseconds) for the hardware timer interrupt.
 * If one-shot mode capability is not available, the return value
 * will be 0.
 */
int
apic_timer_init(int hertz)
{
	int		ret, timer_mode;
	static int	firsttime = 1;

	if (firsttime) {
		/* first time calibrate on CPU0 only */
		apic_ticks_per_SFnsecs = apic_calibrate();

		/* the interval timer initial count is 32 bit max */
		apic_nsec_max = APIC_TICKS_TO_NSECS(APIC_MAXVAL);
		firsttime = 0;
	}

	if (hertz == 0) {
		/* requested one_shot */

		/*
		 * return 0 if TSC is not supported.
		 */
		if (!tsc_gethrtime_enable)
			return (0);
		/*
		 * return 0 if one_shot is not preferred.
		 * here, APIC_TIMER_DEADLINE is also an one_shot mode.
		 */
		if ((apic_timer_preferred_mode != APIC_TIMER_MODE_ONESHOT) &&
		    (apic_timer_preferred_mode != APIC_TIMER_MODE_DEADLINE))
			return (0);

		apic_oneshot = 1;
		ret = (int)APIC_TICKS_TO_NSECS(1);
		if ((apic_timer_preferred_mode == APIC_TIMER_MODE_DEADLINE) &&
		    cpuid_deadline_tsc_supported()) {
			timer_mode = APIC_TIMER_MODE_DEADLINE;
		} else {
			timer_mode = APIC_TIMER_MODE_ONESHOT;
		}
	} else {
		/* periodic */
		apic_nsec_per_intr = NANOSEC / hertz;
		apic_hertz_count = APIC_NSECS_TO_TICKS(apic_nsec_per_intr);

		/* program the local APIC to interrupt at the given frequency */
		apic_reg_ops->apic_write(APIC_INIT_COUNT, apic_hertz_count);
		apic_reg_ops->apic_write(APIC_LOCAL_TIMER,
		    (apic_clkvect + APIC_BASE_VECT) | AV_PERIODIC);
		apic_oneshot = 0;
		timer_mode = APIC_TIMER_MODE_PERIODIC;
		ret = NANOSEC / hertz;
	}

	/*
	 * initialize apic_timer data structure, install the timer ops
	 */
	apic_timer.mode = timer_mode;
	switch (timer_mode) {
	default:
		/* FALLTHROUGH */
	case APIC_TIMER_MODE_ONESHOT:
		apic_timer.apic_timer_enable_ops = oneshot_timer_enable;
		apic_timer.apic_timer_disable_ops = oneshot_timer_disable;
		apic_timer.apic_timer_reprogram_ops = oneshot_timer_reprogram;
		break;

	case APIC_TIMER_MODE_PERIODIC:
		apic_timer.apic_timer_enable_ops = periodic_timer_enable;
		apic_timer.apic_timer_disable_ops = periodic_timer_disable;
		apic_timer.apic_timer_reprogram_ops = periodic_timer_reprogram;
		break;

	case APIC_TIMER_MODE_DEADLINE:
		apic_timer.apic_timer_enable_ops = deadline_timer_enable;
		apic_timer.apic_timer_disable_ops = deadline_timer_disable;
		apic_timer.apic_timer_reprogram_ops = deadline_timer_reprogram;
		break;
	}

	return (ret);
}

/*
 * periodic timer mode ops
 */
/* periodic timer enable */
static void
periodic_timer_enable(void)
{
	apic_reg_ops->apic_write(APIC_LOCAL_TIMER,
	    (apic_clkvect + APIC_BASE_VECT) | AV_PERIODIC);
}

/* periodic timer disable */
static void
periodic_timer_disable(void)
{
	apic_reg_ops->apic_write(APIC_LOCAL_TIMER,
	    (apic_clkvect + APIC_BASE_VECT) | AV_MASK);
}

/* periodic timer reprogram */
static void
periodic_timer_reprogram(hrtime_t time)
{
	uint_t	ticks;
	/* time is the interval for periodic mode */
	ticks = APIC_NSECS_TO_TICKS(time);

	if (ticks < apic_min_timer_ticks)
		ticks = apic_min_timer_ticks;

	apic_reg_ops->apic_write(APIC_INIT_COUNT, ticks);
}

/*
 * oneshot timer mode ops
 */
/* oneshot timer enable */
static void
oneshot_timer_enable(void)
{
	apic_reg_ops->apic_write(APIC_LOCAL_TIMER,
	    (apic_clkvect + APIC_BASE_VECT));
}

/* oneshot timer disable */
static void
oneshot_timer_disable(void)
{
	apic_reg_ops->apic_write(APIC_LOCAL_TIMER,
	    (apic_clkvect + APIC_BASE_VECT) | AV_MASK);
}

/* oneshot timer reprogram */
static void
oneshot_timer_reprogram(hrtime_t time)
{
	hrtime_t	now;
	int64_t		delta;
	uint_t		ticks;

	now = gethrtime();
	delta = time - now;

	if (delta <= 0) {
		/*
		 * requested to generate an interrupt in the past
		 * generate an interrupt as soon as possible
		 */
		ticks = apic_min_timer_ticks;
	} else if (delta > apic_nsec_max) {
		/*
		 * requested to generate an interrupt at a time
		 * further than what we are capable of. Set to max
		 * the hardware can handle
		 */
		ticks = APIC_MAXVAL;
#ifdef DEBUG
		cmn_err(CE_CONT, "apic_timer_reprogram, request at"
		    "  %lld  too far in future, current time"
		    "  %lld \n", time, now);
#endif
	} else {
		ticks = APIC_NSECS_TO_TICKS(delta);
	}

	if (ticks < apic_min_timer_ticks)
		ticks = apic_min_timer_ticks;

	apic_reg_ops->apic_write(APIC_INIT_COUNT, ticks);
}

/*
 * deadline timer mode ops
 */
/* deadline timer enable */
static void
deadline_timer_enable(void)
{
	uint64_t ticks;

	apic_reg_ops->apic_write(APIC_LOCAL_TIMER,
	    (apic_clkvect + APIC_BASE_VECT) | AV_DEADLINE);
	/*
	 * Now we have to serialize this per the SDM.  That is to
	 * say, the above enabling can race in the pipeline with
	 * changes to the MSR.  We need to make sure the above
	 * operation is complete before we proceed to reprogram
	 * the deadline value in reprogram().  The algorithm
	 * recommended by the Intel SDM 3A in 10.5.1.4 is:
	 *
	 * a) write a big value to the deadline register
	 * b) read the register back
	 * c) if it reads zero, go back to a and try again
	 */

	do {
		/* write a really big value */
		wrmsr(IA32_DEADLINE_TSC_MSR, 1ULL << 63);
		ticks = rdmsr(IA32_DEADLINE_TSC_MSR);
	} while (ticks == 0);
}

/* deadline timer disable */
static void
deadline_timer_disable(void)
{
	apic_reg_ops->apic_write(APIC_LOCAL_TIMER,
	    (apic_clkvect + APIC_BASE_VECT) | AV_MASK);
}

/* deadline timer reprogram */
static void
deadline_timer_reprogram(hrtime_t time)
{
	int64_t		delta;
	uint64_t	ticks;

	/*
	 * Note that this entire routine is called with
	 * CBE_HIGH_PIL, so we needn't worry about preemption.
	 */
	delta = time - gethrtime();

	/* The unscalehrtime wants unsigned values. */
	delta = max(delta, 0);

	/* Now we shouldn't be interrupted, we can set the deadline */
	ticks = (uint64_t)tsc_read() + unscalehrtime(delta);
	wrmsr(IA32_DEADLINE_TSC_MSR, ticks);
}

/*
 * This function will reprogram the timer.
 *
 * When in oneshot mode the argument is the absolute time in future to
 * generate the interrupt at.
 *
 * When in periodic mode, the argument is the interval at which the
 * interrupts should be generated. There is no need to support the periodic
 * mode timer change at this time.
 */
void
apic_timer_reprogram(hrtime_t time)
{
	/*
	 * we should be Called from high PIL context (CBE_HIGH_PIL),
	 * so kpreempt is disabled.
	 */
	apic_timer.apic_timer_reprogram_ops(time);
}

/*
 * This function will enable timer interrupts.
 */
void
apic_timer_enable(void)
{
	/*
	 * we should be Called from high PIL context (CBE_HIGH_PIL),
	 * so kpreempt is disabled.
	 */
	apic_timer.apic_timer_enable_ops();
}

/*
 * This function will disable timer interrupts.
 */
void
apic_timer_disable(void)
{
	/*
	 * we should be Called from high PIL context (CBE_HIGH_PIL),
	 * so kpreempt is disabled.
	 */
	apic_timer.apic_timer_disable_ops();
}

/*
 * Set timer far into the future and return timer
 * current count in nanoseconds.
 */
hrtime_t
apic_timer_stop_count(void)
{
	hrtime_t	ns_val;
	int		enable_val, count_val;

	/*
	 * Should be called with interrupts disabled.
	 */
	ASSERT(!interrupts_enabled());

	enable_val = apic_reg_ops->apic_read(APIC_LOCAL_TIMER);
	if ((enable_val & AV_MASK) == AV_MASK)
		return ((hrtime_t)-1);	/* timer is disabled */

	count_val = apic_reg_ops->apic_read(APIC_CURR_COUNT);
	ns_val = APIC_TICKS_TO_NSECS(count_val);

	apic_reg_ops->apic_write(APIC_INIT_COUNT, APIC_MAXVAL);

	return (ns_val);
}

/*
 * Reprogram timer after Deep C-State.
 */
void
apic_timer_restart(hrtime_t time)
{
	apic_timer_reprogram(time);
}
