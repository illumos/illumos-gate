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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/uadmin.h>
#include <sys/panic.h>
#include <sys/reboot.h>
#include <sys/autoconf.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/membar.h>
#include <vm/hat_sfmmu.h>
#include <sys/cpu_module.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/intreg.h>
#include <sys/consdev.h>
#include <sys/kdi_impl.h>
#include <sys/callb.h>
#include <sys/dumphdr.h>

#ifdef	TRAPTRACE
#include <sys/traptrace.h>
u_longlong_t panic_tick;
#endif /* TRAPTRACE */

extern u_longlong_t	gettick();
static void reboot_machine(char *);
int disable_watchdog_on_exit = 0;
extern uint64_t		cpc_level15_inum;

/*
 * Machine dependent code to reboot.
 * "mdep" is interpreted as a character pointer; if non-null, it is a pointer
 * to a string to be used as the argument string when rebooting.
 *
 * "invoke_cb" is a boolean. It is set to true when mdboot() can safely
 * invoke CB_CL_MDBOOT callbacks before shutting the system down, i.e. when
 * we are in a normal shutdown sequence (interrupts are not blocked, the
 * system is not panic'ing or being suspended).
 */
/*ARGSUSED*/
void
mdboot(int cmd, int fcn, char *bootstr, boolean_t invoke_cb)
{
	extern void pm_cfb_check_and_powerup(void);

	/*
	 * Disable the hw watchdog timer.
	 */
	if (disable_watchdog_on_exit && watchdog_activated) {
		mutex_enter(&tod_lock);
		(void) tod_ops.tod_clear_watchdog_timer();
		mutex_exit(&tod_lock);
	}

	/*
	 * XXX - rconsvp is set to NULL to ensure that output messages
	 * are sent to the underlying "hardware" device using the
	 * monitor's printf routine since we are in the process of
	 * either rebooting or halting the machine.
	 */
	rconsvp = NULL;

	/*
	 * At a high interrupt level we can't:
	 *	1) bring up the console
	 * or
	 *	2) wait for pending interrupts prior to redistribution
	 *	   to the current CPU
	 *
	 * so we do them now.
	 */
	pm_cfb_check_and_powerup();

	/* make sure there are no more changes to the device tree */
	devtree_freeze();

	if (invoke_cb)
		(void) callb_execute_class(CB_CL_MDBOOT, 0);

	/*
	 * Clear any unresolved UEs from memory.
	 */
	page_retire_mdboot();

	/*
	 * stop other cpus which also raise our priority. since there is only
	 * one active cpu after this, and our priority will be too high
	 * for us to be preempted, we're essentially single threaded
	 * from here on out.
	 */
	stop_other_cpus();

	/*
	 * try and reset leaf devices.  reset_leaves() should only
	 * be called when there are no other threads that could be
	 * accessing devices
	 */
	reset_leaves();

	if (fcn == AD_HALT) {
		halt((char *)NULL);
	} else if (fcn == AD_POWEROFF) {
		power_down(NULL);
	} else {
		if (bootstr == NULL) {
			switch (fcn) {

			case AD_FASTREBOOT:
			case AD_BOOT:
				bootstr = "";
				break;

			case AD_IBOOT:
				bootstr = "-a";
				break;

			case AD_SBOOT:
				bootstr = "-s";
				break;

			case AD_SIBOOT:
				bootstr = "-sa";
				break;
			default:
				cmn_err(CE_WARN,
				    "mdboot: invalid function %d", fcn);
				bootstr = "";
				break;
			}
		}
		if (fcn == AD_FASTREBOOT) {
			pnode_t onode;
			int dllen;
			onode = prom_optionsnode();
			if ((onode == OBP_NONODE) || (onode == OBP_BADNODE)) {
				cmn_err(CE_WARN, "Unable to set diag level for"
				    " quick reboot");
			} else {
				dllen = prom_getproplen(onode, "diag-level");
				if (dllen != -1) {
					char *newstr = kmem_alloc(strlen(
					    bootstr) + dllen + 5, KM_NOSLEEP);
					if (newstr != NULL) {
						int newstrlen;
						(void) strcpy(newstr, bootstr);
						(void) strcat(newstr, " -f ");
						newstrlen = strlen(bootstr) + 4;
						(void) prom_getprop(onode,
						    "diag-level",
						    (caddr_t)
						    &(newstr[newstrlen]));
						newstr[newstrlen + dllen] =
						    '\0';
						bootstr = newstr;
						(void) prom_setprop(onode,
						    "diag-level",
						    "off", 4);
					}
				}
			}
		}
		reboot_machine(bootstr);
	}
	/* MAYBE REACHED */
}

/* mdpreboot - may be called prior to mdboot while root fs still mounted */
/*ARGSUSED*/
void
mdpreboot(int cmd, int fcn, char *bootstr)
{
}

/*
 * Halt the machine and then reboot with the device
 * and arguments specified in bootstr.
 */
static void
reboot_machine(char *bootstr)
{
	flush_windows();
	stop_other_cpus();		/* send stop signal to other CPUs */
	prom_printf("rebooting...\n");
	/*
	 * For platforms that use CPU signatures, we
	 * need to set the signature block to OS and
	 * the state to exiting for all the processors.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_REBOOT, -1);
	prom_reboot(bootstr);
	/*NOTREACHED*/
}

/*
 * We use the x-trap mechanism and idle_stop_xcall() to stop the other CPUs.
 * Once in panic_idle() they raise spl, record their location, and spin.
 */
static void
panic_idle(void)
{
	cpu_async_panic_callb(); /* check for async errors */

	(void) spl7();

	debug_flush_windows();
	(void) setjmp(&curthread->t_pcb);

	CPU->cpu_m.in_prom = 1;
	membar_stld();

	dumpsys_helper();

	for (;;)
		continue;
}

/*
 * Force the other CPUs to trap into panic_idle(), and then remove them
 * from the cpu_ready_set so they will no longer receive cross-calls.
 */
/*ARGSUSED*/
void
panic_stopcpus(cpu_t *cp, kthread_t *t, int spl)
{
	cpuset_t cps;
	int i;

	(void) splzs();
	CPUSET_ALL_BUT(cps, cp->cpu_id);
	xt_some(cps, (xcfunc_t *)idle_stop_xcall, (uint64_t)&panic_idle, 0);

	for (i = 0; i < NCPU; i++) {
		if (i != cp->cpu_id && CPU_XCALL_READY(i)) {
			int ntries = 0x10000;

			while (!cpu[i]->cpu_m.in_prom && ntries) {
				DELAY(50);
				ntries--;
			}

			if (!cpu[i]->cpu_m.in_prom)
				printf("panic: failed to stop cpu%d\n", i);

			cpu[i]->cpu_flags &= ~CPU_READY;
			cpu[i]->cpu_flags |= CPU_QUIESCED;
			CPUSET_DEL(cpu_ready_set, cpu[i]->cpu_id);
		}
	}
}

/*
 * Platform callback following each entry to panicsys().  If we've panicked at
 * level 14, we examine t_panic_trap to see if a fatal trap occurred.  If so,
 * we disable further %tick_cmpr interrupts.  If not, an explicit call to panic
 * was made and so we re-enqueue an interrupt request structure to allow
 * further level 14 interrupts to be processed once we lower PIL.  This allows
 * us to handle panics from the deadman() CY_HIGH_LEVEL cyclic.
 *
 * In case we panic at level 15, ensure that the cpc handler has been
 * reinstalled otherwise we could run the risk of hitting a missing interrupt
 * handler when this thread drops PIL and the cpc counter overflows.
 */
void
panic_enter_hw(int spl)
{
	uint_t opstate;

	if (spl == ipltospl(PIL_14)) {
		opstate = disable_vec_intr();

		if (curthread->t_panic_trap != NULL) {
			tickcmpr_disable();
			intr_dequeue_req(PIL_14, cbe_level14_inum);
		} else {
			if (!tickcmpr_disabled())
				intr_enqueue_req(PIL_14, cbe_level14_inum);
			/*
			 * Clear SOFTINT<14>, SOFTINT<0> (TICK_INT)
			 * and SOFTINT<16> (STICK_INT) to indicate
			 * that the current level 14 has been serviced.
			 */
			wr_clr_softint((1 << PIL_14) |
			    TICK_INT_MASK | STICK_INT_MASK);
		}

		enable_vec_intr(opstate);
	} else if (spl == ipltospl(PIL_15)) {
		opstate = disable_vec_intr();
		intr_enqueue_req(PIL_15, cpc_level15_inum);
		wr_clr_softint(1 << PIL_15);
		enable_vec_intr(opstate);
	}
}

/*
 * Miscellaneous hardware-specific code to execute after panicstr is set
 * by the panic code: we also print and record PTL1 panic information here.
 */
/*ARGSUSED*/
void
panic_quiesce_hw(panic_data_t *pdp)
{
	extern uint_t getpstate(void);
	extern void setpstate(uint_t);

#ifdef TRAPTRACE
	/*
	 * Turn off TRAPTRACE and save the current %tick value in panic_tick.
	 */
	if (!panic_tick)
		panic_tick = gettick();
	TRAPTRACE_FREEZE;
#endif
	/*
	 * For Platforms that use CPU signatures, we
	 * need to set the signature block to OS, the state to
	 * exiting, and the substate to panic for all the processors.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_PANIC, -1);

	/*
	 * De-activate ECC functions and disable the watchdog timer now that
	 * we've made it through the critical part of the panic code.
	 */
	if (watchdog_enable)
		(void) tod_ops.tod_clear_watchdog_timer();

	/*
	 * Disable further ECC errors from the CPU module and the bus nexus.
	 */
	cpu_disable_errors();
	(void) bus_func_invoke(BF_TYPE_ERRDIS);

	/*
	 * Redirect all interrupts to the current CPU.
	 */
	intr_redist_all_cpus_shutdown();

	/*
	 * This call exists solely to support dumps to network
	 * devices after sync from OBP.
	 *
	 * If we came here via the sync callback, then on some
	 * platforms, interrupts may have arrived while we were
	 * stopped in OBP.  OBP will arrange for those interrupts to
	 * be redelivered if you say "go", but not if you invoke a
	 * client callback like 'sync'.	 For some dump devices
	 * (network swap devices), we need interrupts to be
	 * delivered in order to dump, so we have to call the bus
	 * nexus driver to reset the interrupt state machines.
	 */
	(void) bus_func_invoke(BF_TYPE_RESINTR);

	setpstate(getpstate() | PSTATE_IE);
}

/*
 * Platforms that use CPU signatures need to set the signature block to OS and
 * the state to exiting for all CPUs. PANIC_CONT indicates that we're about to
 * write the crash dump, which tells the SSP/SMS to begin a timeout routine to
 * reboot the machine if the dump never completes.
 */
/*ARGSUSED*/
void
panic_dump_hw(int spl)
{
	CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_DUMP, -1);
}

/*
 * for ptl1_panic
 */
void
ptl1_init_cpu(struct cpu *cpu)
{
	ptl1_state_t *pstate = &cpu->cpu_m.ptl1_state;

	/*CONSTCOND*/
	if (sizeof (struct cpu) + PTL1_SSIZE > CPU_ALLOC_SIZE) {
		panic("ptl1_init_cpu: not enough space left for ptl1_panic "
		    "stack, sizeof (struct cpu) = %lu", sizeof (struct cpu));
	}

	pstate->ptl1_stktop = (uintptr_t)cpu + CPU_ALLOC_SIZE;
	cpu_pa[cpu->cpu_id] = va_to_pa(cpu);
}

void
ptl1_panic_handler(ptl1_state_t *pstate)
{
	static const char *ptl1_reasons[] = {
#ifdef	PTL1_PANIC_DEBUG
		"trap for debug purpose",	/* PTL1_BAD_DEBUG */
#else
		"unknown trap",			/* PTL1_BAD_DEBUG */
#endif
		"register window trap",		/* PTL1_BAD_WTRAP */
		"kernel MMU miss",		/* PTL1_BAD_KMISS */
		"kernel protection fault",	/* PTL1_BAD_KPROT_FAULT */
		"ISM MMU miss",			/* PTL1_BAD_ISM */
		"kernel MMU trap",		/* PTL1_BAD_MMUTRAP */
		"kernel trap handler state",	/* PTL1_BAD_TRAP */
		"floating point trap",		/* PTL1_BAD_FPTRAP */
#ifdef	DEBUG
		"pointer to intr_vec",		/* PTL1_BAD_INTR_VEC */
#else
		"unknown trap",			/* PTL1_BAD_INTR_VEC */
#endif
#ifdef	TRAPTRACE
		"TRACE_PTR state",		/* PTL1_BAD_TRACE_PTR */
#else
		"unknown trap",			/* PTL1_BAD_TRACE_PTR */
#endif
		"stack overflow",		/* PTL1_BAD_STACK */
		"DTrace flags",			/* PTL1_BAD_DTRACE_FLAGS */
		"attempt to steal locked ctx",  /* PTL1_BAD_CTX_STEAL */
		"CPU ECC error loop",		/* PTL1_BAD_ECC */
		"non-kernel context in sys/priv_trap() below or",
						/* PTL1_BAD_CTX */
		"error raising a TSB exception", /* PTL1_BAD_RAISE_TSBEXCP */
		"missing shared TSB"    /* PTL1_NO_SCDTSB8K */
	};

	uint_t reason = pstate->ptl1_regs.ptl1_g1;
	uint_t tl = pstate->ptl1_regs.ptl1_trap_regs[0].ptl1_tl;
	struct panic_trap_info ti = { 0 };

	/*
	 * Use trap_info for a place holder to call panic_savetrap() and
	 * panic_showtrap() to save and print out ptl1_panic information.
	 */
	if (curthread->t_panic_trap == NULL)
		curthread->t_panic_trap = &ti;

	if (reason < sizeof (ptl1_reasons) / sizeof (ptl1_reasons[0]))
		panic("bad %s at TL %u", ptl1_reasons[reason], tl);
	else
		panic("ptl1_panic reason 0x%x at TL %u", reason, tl);
}

void
clear_watchdog_on_exit()
{
	/*
	 * Only shut down an active hardware watchdog timer if the platform
	 * has expressed an interest to.
	 */
	if (disable_watchdog_on_exit && watchdog_activated) {
		prom_printf("Debugging requested; hardware watchdog "
		    "disabled; reboot to re-enable.\n");
		cmn_err(CE_WARN, "!Debugging requested; hardware watchdog "
		    "disabled; reboot to re-enable.");
		mutex_enter(&tod_lock);
		(void) tod_ops.tod_clear_watchdog_timer();
		mutex_exit(&tod_lock);
	}
}

/*
 * This null routine is only used by sun4v watchdog timer support.
 */
void
restore_watchdog_on_entry(void)
{
}

int
kdi_watchdog_disable(void)
{
	if (watchdog_activated) {
		mutex_enter(&tod_lock);
		(void) tod_ops.tod_clear_watchdog_timer();
		mutex_exit(&tod_lock);
	}

	return (watchdog_activated);
}

void
kdi_watchdog_restore(void)
{
	if (watchdog_enable) {
		mutex_enter(&tod_lock);
		(void) tod_ops.tod_set_watchdog_timer(watchdog_timeout_seconds);
		mutex_exit(&tod_lock);
	}
}

/*ARGSUSED*/
void
mach_dump_buffer_init(void)
{
	/*
	 * setup dump buffer to store extra crash information
	 * not applicable to sun4u
	 */
}

/*
 * xt_sync - wait for previous x-traps to finish
 */
void
xt_sync(cpuset_t cpuset)
{
	kpreempt_disable();
	CPUSET_DEL(cpuset, CPU->cpu_id);
	CPUSET_AND(cpuset, cpu_ready_set);
	xt_some(cpuset, (xcfunc_t *)xt_sync_tl1, 0, 0);
	kpreempt_enable();
}

/*
 * mach_soft_state_init() - dummy routine for sun4v soft state
 */
void
mach_soft_state_init(void)
{}
