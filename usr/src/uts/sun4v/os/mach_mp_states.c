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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpuvar.h>
#include <sys/cpu_module.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/prom_plat.h>
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>

extern uint64_t xc_tick_limit;
extern uint64_t xc_tick_jump_limit;

extern void cpu_intrq_unregister_powerdown(uint64_t doneflag_va);

/*
 * set_idle_cpu is called from idle() when a CPU becomes idle.
 */
/*ARGSUSED*/
void
set_idle_cpu(int cpun)
{
}

/*
 * unset_idle_cpu is called from idle() when a CPU is no longer idle.
 */
/*ARGSUSED*/
void
unset_idle_cpu(int cpun)
{
}

/*
 * Stop a CPU based on its cpuid, using the cpu_stop hypervisor call.
 * Since this requires that the hypervisor force a remote CPU to stop,
 * the assumption is made that this should take roughly the same amount
 * of time as a executing a cross-call.  Consequently, the xcall
 * timeout is used to determine when to give up waiting for the CPU to
 * stop.
 *
 * Attempts to stop a CPU already in the stopped or error state will
 * silently succeed. Zero is returned on success and a non-negative
 * errno value is returned on failure.
 */
int
stopcpu_bycpuid(int cpuid)
{
	uint64_t	loop_cnt;
	uint64_t	state;
	uint64_t	rv;
	uint64_t	major = 0;
	uint64_t	minor = 0;
	uint64_t	cpu_stop_time_limit;
	extern uint64_t	xc_func_time_limit;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Check the state of the CPU up front to see if an
	 * attempt to stop it is even necessary.
	 */
	if (hv_cpu_state(cpuid, &state) != H_EOK)
		return (EINVAL);

	/* treat stopped and error state the same */
	if (state != CPU_STATE_RUNNING) {
		/* nothing to do */
		return (0);
	}

	/*
	 * The HV API to stop a CPU is only supported in
	 * version 1.1 and later of the core group. If an
	 * older version of the HV is in use, return not
	 * supported.
	 */
	if (hsvc_version(HSVC_GROUP_CORE, &major, &minor) != 0)
		return (EINVAL);

	ASSERT(major != 0);

	if ((major == 1) && (minor < 1))
		return (ENOTSUP);

	/* use the mondo timeout if it has been initialized */
	cpu_stop_time_limit = xc_func_time_limit;

	/*
	 * If called early in boot before the mondo time limit
	 * is set, use a reasonable timeout based on the the
	 * clock frequency of the current CPU.
	 */
	if (cpu_stop_time_limit == 0)
		cpu_stop_time_limit = cpunodes[CPU->cpu_id].clock_freq;

	/* should only fail if called too early in boot */
	ASSERT(cpu_stop_time_limit > 0);

	loop_cnt = 0;

	/*
	 * Attempt to stop the CPU, retrying if it is busy.
	 */
	while (loop_cnt++ < cpu_stop_time_limit) {

		if ((rv = hv_cpu_stop(cpuid)) != H_EWOULDBLOCK)
			break;
	}

	if (loop_cnt == cpu_stop_time_limit)
		return (ETIMEDOUT);

	if (rv != H_EOK)
		return (EINVAL);

	/*
	 * Verify that the CPU has reached the stopped state.
	 */
	while (loop_cnt++ < cpu_stop_time_limit) {

		if (hv_cpu_state(cpuid, &state) != H_EOK)
			return (EINVAL);

		/* treat stopped and error state the same */
		if (state != CPU_STATE_RUNNING)
			break;
	}

	return ((loop_cnt == cpu_stop_time_limit) ? ETIMEDOUT : 0);
}

/*
 * X-trap to the target to unregister its interrupt and error queues
 * and put it in a safe place just before the CPU is stopped. After
 * unregistering its queues, the target CPU must not return from the
 * trap to priv or user context. Ensure that the interrupt CPU unregister
 * succeeded.
 */
void
xt_cpu_unreg_powerdown(struct cpu *cpup)
{
	uint8_t volatile not_done;
	uint64_t starttick, endtick, tick, lasttick;
	processorid_t cpuid = cpup->cpu_id;

	kpreempt_disable();

	/*
	 * Sun4v uses a queue for receiving mondos. Successful
	 * transmission of a mondo only indicates that the mondo
	 * has been written into the queue.
	 *
	 * Set the not_done flag to 1 before sending the cross
	 * trap and wait until the other cpu resets it to 0.
	 */

	not_done = 1;

	xt_one_unchecked(cpuid, (xcfunc_t *)cpu_intrq_unregister_powerdown,
	    (uint64_t)&not_done, 0);

	starttick = lasttick = gettick();
	endtick = starttick + xc_tick_limit;

	while (not_done) {

		tick = gettick();

		/*
		 * If there is a big jump between the current tick
		 * count and lasttick, we have probably hit a break
		 * point. Adjust endtick accordingly to avoid panic.
		 */
		if (tick > (lasttick + xc_tick_jump_limit)) {
			endtick += (tick - lasttick);
		}

		lasttick = tick;
		if (tick > endtick) {
			cmn_err(CE_CONT, "Cross trap timeout at cpu id %x\n",
			    cpuid);
			cmn_err(CE_WARN, "xt_intrq_unreg_powerdown: timeout");
		}
	}

	kpreempt_enable();
}

int
plat_cpu_poweroff(struct cpu *cp)
{
	int		rv = 0;
	int		status;
	processorid_t	cpuid = cp->cpu_id;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Capture all CPUs (except for detaching proc) to prevent
	 * crosscalls to the detaching proc until it has cleared its
	 * bit in cpu_ready_set.
	 *
	 * The CPU's remain paused and the prom_mutex is known to be free.
	 * This prevents the x-trap victim from blocking when doing prom
	 * IEEE-1275 calls at a high PIL level.
	 */
	promsafe_pause_cpus();

	/*
	 * Quiesce interrupts on the target CPU. We do this by setting
	 * the CPU 'not ready'- (i.e. removing the CPU from cpu_ready_set)
	 * to prevent it from receiving cross calls and cross traps. This
	 * prevents the processor from receiving any new soft interrupts.
	 */
	mp_cpu_quiesce(cp);

	/*
	 * Send a cross trap to the cpu to unregister its interrupt
	 * error queues.
	 */
	xt_cpu_unreg_powerdown(cp);

	cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_POWEROFF;

	/* call into the Hypervisor to stop the CPU */
	if ((status = stopcpu_bycpuid(cpuid)) != 0) {
		rv = -1;
	}

	start_cpus();

	if (rv != 0) {
		cmn_err(CE_WARN, "failed to stop cpu %d (%d)", cpuid, status);
		/* mark the CPU faulted so that it cannot be onlined */
		cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_FAULTED;
	}

	return (rv);
}

int
plat_cpu_poweron(struct cpu *cp)
{
	extern void	restart_other_cpu(int);

	ASSERT(MUTEX_HELD(&cpu_lock));

	cp->cpu_flags &= ~CPU_POWEROFF;

	restart_other_cpu(cp->cpu_id);

	return (0);
}
