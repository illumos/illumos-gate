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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/clock.h>
#include <sys/x_call.h>
#include <sys/cpuvar.h>
#include <sys/promif.h>
#include <sys/kmem.h>
#include <sys/machsystm.h>
#include <sys/ivintr.h>
#include <sys/cyclic.h>
#include <sys/cyclic_impl.h>

uint64_t cbe_level14_inum;
cyclic_id_t cbe_hres_cyclic;

static hrtime_t cbe_hrtime_max;
static hrtime_t cbe_suspend_delta = 0;
static hrtime_t cbe_suspend_time = 0;

static uint64_t
hrtime2tick(hrtime_t ts)
{
	hrtime_t q = ts / NANOSEC;
	hrtime_t r = ts - (q * NANOSEC);

	return (q * sys_tick_freq + ((r * sys_tick_freq) / NANOSEC));
}

static uint64_t
unscalehrtime(hrtime_t ts)
{
	uint64_t unscale = 0;
	hrtime_t rescale;
	hrtime_t diff = ts;

	while (diff > nsec_per_sys_tick) {
		unscale += hrtime2tick(diff);
		rescale = unscale;
		scalehrtime(&rescale);
		diff = ts - rescale;
	}

	return (unscale);
}

static int
cbe_level1()
{
	cyclic_softint(CPU, CY_LOW_LEVEL);
	return (1);
}

static int
cbe_level10()
{
	cyclic_softint(CPU, CY_LOCK_LEVEL);
	return (1);
}

/*ARGSUSED*/
static void
cbe_enable(cyb_arg_t arg)
{
	int pstate_save = disable_vec_intr();

	intr_enqueue_req(PIL_14, cbe_level14_inum);
	enable_vec_intr(pstate_save);
}

/*ARGSUSED*/
static void
cbe_disable(cyb_arg_t arg)
{
	int pstate_save = disable_vec_intr();

	tickcmpr_disable();
	intr_dequeue_req(PIL_14, cbe_level14_inum);
	enable_vec_intr(pstate_save);
}

/*ARGSUSED*/
static void
cbe_reprogram(cyb_arg_t arg, hrtime_t time)
{
	if (time >= cbe_hrtime_max)
		time = cbe_hrtime_max;

	tickcmpr_set(unscalehrtime(time));
}

static void
cbe_softint(cyb_arg_t arg, cyc_level_t level)
{
	cbe_data_t *data = (cbe_data_t *)arg;

	switch (level) {
	case CY_LOW_LEVEL:
		setsoftint(data->cbe_level1_inum);
		break;
	case CY_LOCK_LEVEL:
		setsoftint(data->cbe_level10_inum);
		break;
	default:
		panic("cbe_softint: unexpected soft level %d", level);
	}
}

/*ARGSUSED*/
static cyc_cookie_t
cbe_set_level(cyb_arg_t arg, cyc_level_t level)
{
	int ipl;

	switch (level) {
	case CY_LOW_LEVEL:
		ipl = CBE_LOW_PIL;
		break;
	case CY_LOCK_LEVEL:
		ipl = CBE_LOCK_PIL;
		break;
	case CY_HIGH_LEVEL:
		ipl = CBE_HIGH_PIL;
		break;
	default:
		panic("cbe_set_level: unexpected level %d", level);
	}

	return (splr(ipl));
}

/*ARGSUSED*/
static void
cbe_restore_level(cyb_arg_t arg, cyc_cookie_t cookie)
{
	splx(cookie);
}

static void
cbe_xcall_handler(uint64_t arg1, uint64_t arg2)
{
	cyc_func_t func = (cyc_func_t)arg1;
	void *arg = (void *)arg2;

	(*func)(arg);
}

/*ARGSUSED*/
static void
cbe_xcall(cyb_arg_t arg, cpu_t *dest, cyc_func_t func, void *farg)
{
	kpreempt_disable();
	xc_one(dest->cpu_id, cbe_xcall_handler, (uint64_t)func, (uint64_t)farg);
	kpreempt_enable();
}

/*ARGSUSED*/
static cyb_arg_t
cbe_configure(cpu_t *cpu)
{
	cbe_data_t *new_data = kmem_alloc(sizeof (cbe_data_t), KM_SLEEP);

	/*
	 * The setsoftint() code will refuse to post a soft interrupt if
	 * one is already pending for the specified inum.  Given that we
	 * may have disjoint soft interrupts on different CPUs posted
	 * simultaneously, we allocate a new set of inums for each CPU.
	 */
	new_data->cbe_level10_inum = add_softintr(PIL_10,
	    (softintrfunc)cbe_level10, 0, SOFTINT_ST);

	new_data->cbe_level1_inum = add_softintr(PIL_1,
	    (softintrfunc)cbe_level1, 0, SOFTINT_ST);

	return (new_data);
}

static void
cbe_unconfigure(cyb_arg_t arg)
{
	cbe_data_t *data = (cbe_data_t *)arg;

	(void) rem_softintr(data->cbe_level10_inum);
	(void) rem_softintr(data->cbe_level1_inum);

	kmem_free(data, sizeof (cbe_data_t));
}

/*ARGSUSED*/
static void
cbe_suspend(cyb_arg_t arg)
{
	cbe_suspend_time = gethrtime_unscaled();
	cbe_suspend_delta = 0;
}

/*ARGSUSED*/
static void
cbe_resume(cyb_arg_t arg)
{
	hrtime_t now;

	/*
	 * If we're actually on a CPU which has apparently had %tick zeroed,
	 * we want to add cbe_suspend_delta to %tick.
	 */
	if ((now = gethrtime_unscaled()) < cbe_suspend_time) {

		if (cbe_suspend_delta == 0) {
			/*
			 * We're the first CPU to be resumed.  We want %tick
			 * to be close to %tick when we suspended the system,
			 * so we'll figure out the delta which needs to be
			 * written to the register.  All subsequent resumed
			 * CPUs will write the same delta.
			 */
			cbe_suspend_delta = cbe_suspend_time - now;
		}

		tick_write_delta(cbe_suspend_delta);
	}
}

void
cbe_hres_tick(void)
{
	dtrace_hres_tick();
	hres_tick();
}

void
cbe_init_pre(void)
{
	/* Nothing to do on sparc */
}

void
cbe_init(void)
{
	cyc_handler_t hdlr;
	cyc_time_t when;
	hrtime_t resolution = NANOSEC / sys_tick_freq;

	cyc_backend_t cbe = {
		cbe_configure,		/* cyb_configure */
		cbe_unconfigure,	/* cyb_unconfigure */
		cbe_enable,		/* cyb_enable */
		cbe_disable,		/* cyb_disable */
		cbe_reprogram,		/* cyb_reprogram */
		cbe_softint,		/* cyb_softint */
		cbe_set_level,		/* cyb_set_level */
		cbe_restore_level,	/* cyb_restore_level */
		cbe_xcall,		/* cyb_xcall */
		cbe_suspend,		/* cyb_suspend */
		cbe_resume		/* cyb_resume */
	};

	cbe_level14_inum = add_softintr(CBE_HIGH_PIL,
	    (softintrfunc)cbe_level14, 0, SOFTINT_MT);
	cbe_hrtime_max = gethrtime_max();

	/*
	 * If sys_tick_freq > NANOSEC (i.e. we're on a CPU with a clock rate
	 * which exceeds 1 GHz), we'll specify the minimum resolution,
	 * 1 nanosecond.
	 */
	if (resolution == 0)
		resolution = 1;

	mutex_enter(&cpu_lock);
	cyclic_init(&cbe, resolution);

	/*
	 * Initialize hrtime_base and hres_last_tick to reasonable starting
	 * values.
	 */
	hrtime_base = gethrtime();
	hres_last_tick = gethrtime_unscaled();

	hdlr.cyh_level = CY_HIGH_LEVEL;
	hdlr.cyh_func = (cyc_func_t)cbe_hres_tick;
	hdlr.cyh_arg = NULL;

	when.cyt_when = 0;
	when.cyt_interval = nsec_per_tick;

	cbe_hres_cyclic = cyclic_add(&hdlr, &when);

	mutex_exit(&cpu_lock);

	clkstart();
}
