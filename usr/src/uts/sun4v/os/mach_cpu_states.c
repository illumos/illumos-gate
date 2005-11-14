/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
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
#include <sys/hypervisor_api.h>
#include <sys/vmsystm.h>
#include <sys/dtrace.h>
#include <sys/xc_impl.h>
#include <sys/callb.h>

/*
 * hvdump_buf_va is a pointer to the currently-configured hvdump_buf.
 * A value of NULL indicates that this area is not configured.
 * hvdump_buf_sz is tunable but will be clamped to HVDUMP_SIZE_MAX.
 */

caddr_t hvdump_buf_va;
uint64_t hvdump_buf_sz = HVDUMP_SIZE_DEFAULT;
static uint64_t hvdump_buf_pa;


#ifdef	TRAPTRACE
#include <sys/traptrace.h>
#include <sys/hypervisor_api.h>
u_longlong_t panic_tick;
#endif /* TRAPTRACE */

extern u_longlong_t	gettick();
static void reboot_machine(char *);
static void update_hvdump_buffer(void);

/*
 * For xt_sync synchronization.
 */
extern uint64_t xc_tick_limit;
extern uint64_t xc_tick_jump_limit;

/*
 * We keep our own copies, used for cache flushing, because we can be called
 * before cpu_fiximpl().
 */
static int kdi_dcache_size;
static int kdi_dcache_linesize;
static int kdi_icache_size;
static int kdi_icache_linesize;

/*
 * Assembly support for generic modules in sun4v/ml/mach_xc.s
 */
extern void init_mondo_nocheck(xcfunc_t *func, uint64_t arg1, uint64_t arg2);
extern void kdi_flush_idcache(int, int, int, int);
extern uint64_t get_cpuaddr(uint64_t, uint64_t);

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
	page_t *first, *pp;
	extern void pm_cfb_check_and_powerup(void);

	/*
	 * Clear any unresolved UEs from memory.  We rely on the fact that on
	 * sun4u, pagezero() will always clear UEs.  Since we're rebooting, we
	 * just force p_selock to appear locked so pagezero()'s assert works.
	 *
	 * Pages that were retired successfully due to multiple CEs will
	 * also be cleared.
	 */
	if (memsegs != NULL) {
		pp = first = page_first();
		do {
			if (page_isretired(pp) || page_istoxic(pp)) {
				/* pagezero asserts PAGE_LOCKED */
				pp->p_selock = -1;
				pagezero(pp, 0, PAGESIZE);
			}
		} while ((pp = page_next(pp)) != first);
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
		(void) callb_execute_class(CB_CL_MDBOOT, NULL);

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
	(void) spl7();

	debug_flush_windows();
	(void) setjmp(&curthread->t_pcb);

	CPU->cpu_m.in_prom = 1;
	membar_stld();

	for (;;);
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
	xt_some(cps, (xcfunc_t *)idle_stop_xcall, (uint64_t)&panic_idle, NULL);

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
 */
void
panic_enter_hw(int spl)
{
#ifdef TRAPTRACE
	if (!panic_tick) {
		uint64_t prev_freeze;

		panic_tick = gettick();
		/*  there are no possible error codes for this hcall */
		(void) hv_ttrace_freeze((uint64_t)TRAP_TFREEZE_ALL,
			&prev_freeze);
		TRAPTRACE_FREEZE;
	}
#endif

	if (spl == ipltospl(PIL_14)) {
		uint_t opstate = disable_vec_intr();

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
	uint64_t prev_freeze;
	/*
	 * Turn off TRAPTRACE and save the current %tick value in panic_tick.
	 */
	if (!panic_tick)
		panic_tick = gettick();
	/*  there are no possible error codes for this hcall */
	(void) hv_ttrace_freeze((uint64_t)TRAP_TFREEZE_ALL, &prev_freeze);
	TRAPTRACE_FREEZE;
#endif
	/*
	 * For Platforms that use CPU signatures, we
	 * need to set the signature block to OS, the state to
	 * exiting, and the substate to panic for all the processors.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_PANIC, -1);

	update_hvdump_buffer();

	/*
	 * Disable further ECC errors from the bus nexus.
	 */
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
		    "stack, sizeof (struct cpu) = %lu",
		    (unsigned long)sizeof (struct cpu));
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
		"pointer to intr_req",		/* PTL1_BAD_INTR_REQ */
#else
		"unknown trap",			/* PTL1_BAD_INTR_REQ */
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
		"unexpected error from hypervisor call", /* PTL1_BAD_HCALL */
		"unexpected global level(%gl)", /* PTL1_BAD_GL */
	};

	uint_t reason = pstate->ptl1_regs.ptl1_gregs[0].ptl1_g1;
	uint_t tl = pstate->ptl1_regs.ptl1_trap_regs[0].ptl1_tl;
	struct trap_info ti = { 0 };

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
clear_watchdog_on_exit(void)
{
}

void
clear_watchdog_timer(void)
{
}

int
kdi_watchdog_disable(void)
{
	return (0);	/* sun4v has no watchdog */
}

void
kdi_watchdog_restore(void)
{
	/* nothing to do -- no watchdog to re-enable */
}

void
mach_dump_buffer_init(void)
{
	uint64_t  ret, minsize = 0;

	if (hvdump_buf_sz > HVDUMP_SIZE_MAX)
		hvdump_buf_sz = HVDUMP_SIZE_MAX;

	hvdump_buf_va = contig_mem_alloc_align(hvdump_buf_sz, PAGESIZE);
	if (hvdump_buf_va == NULL)
		return;

	hvdump_buf_pa = va_to_pa(hvdump_buf_va);

	ret = hv_dump_buf_update(hvdump_buf_pa, hvdump_buf_sz,
	    &minsize);

	if (ret != H_EOK) {
		contig_mem_free(hvdump_buf_va, hvdump_buf_sz);
		hvdump_buf_va = NULL;
		cmn_err(CE_NOTE, "!Error in setting up hvstate"
		    "dump buffer. Error = 0x%lx, size = 0x%lx,"
		    "buf_pa = 0x%lx", ret, hvdump_buf_sz,
		    hvdump_buf_pa);

		if (ret == H_EINVAL) {
			cmn_err(CE_NOTE, "!Buffer size too small."
			    "Available buffer size = 0x%lx,"
			    "Minimum buffer size required = 0x%lx",
			    hvdump_buf_sz, minsize);
		}
	}
}


static void
update_hvdump_buffer(void)
{
	uint64_t ret, dummy_val;

	if (hvdump_buf_va == NULL)
		return;

	ret = hv_dump_buf_update(hvdump_buf_pa, hvdump_buf_sz,
	    &dummy_val);
	if (ret != H_EOK) {
		cmn_err(CE_NOTE, "!Cannot update hvstate dump"
		    "buffer. Error = 0x%lx", ret);
	}
}


static int
getintprop(pnode_t node, char *name, int deflt)
{
	int	value;

	switch (prom_getproplen(node, name)) {
	case 0:
		value = 1;	/* boolean properties */
		break;

	case sizeof (int):
		(void) prom_getprop(node, name, (caddr_t)&value);
		break;

	default:
		value = deflt;
		break;
	}

	return (value);
}

/*
 * Called by setcpudelay
 */
void
cpu_init_tick_freq(void)
{
	sys_tick_freq = cpunodes[CPU->cpu_id].clock_freq;
}

int shipit(int n, uint64_t cpu_list_ra);
extern uint64_t xc_tick_limit;
extern uint64_t xc_tick_jump_limit;

#ifdef DEBUG
#define	SEND_MONDO_STATS	1
#endif

#ifdef SEND_MONDO_STATS
uint32_t x_one_stimes[64];
uint32_t x_one_ltimes[16];
uint32_t x_set_stimes[64];
uint32_t x_set_ltimes[16];
uint32_t x_set_cpus[NCPU];
#endif

void
send_one_mondo(int cpuid)
{
	int retries, stat;
	uint64_t starttick, endtick, tick, lasttick;
	struct machcpu	*mcpup = &(CPU->cpu_m);

	CPU_STATS_ADDQ(CPU, sys, xcalls, 1);
	starttick = lasttick = gettick();
	mcpup->cpu_list[0] = (uint16_t)cpuid;
	stat = shipit(1, mcpup->cpu_list_ra);
	endtick = starttick + xc_tick_limit;
	retries = 0;
	while (stat != 0) {
		ASSERT(stat == H_EWOULDBLOCK);
		tick = gettick();
		/*
		 * If there is a big jump between the current tick
		 * count and lasttick, we have probably hit a break
		 * point.  Adjust endtick accordingly to avoid panic.
		 */
		if (tick > (lasttick + xc_tick_jump_limit))
			endtick += (tick - lasttick);
		lasttick = tick;
		if (tick > endtick) {
			if (panic_quiesce)
				return;
			cmn_err(CE_PANIC, "send mondo timeout "
			    "(target 0x%x) [retries: 0x%x hvstat: 0x%x]",
			    cpuid, retries, stat);
		}
		drv_usecwait(1);
		stat = shipit(1, mcpup->cpu_list_ra);
		retries++;
	}
#ifdef SEND_MONDO_STATS
	{
		int n = gettick() - starttick;
		if (n < 8192)
			x_one_stimes[n >> 7]++;
		else if (n < 16*8192)
			x_one_ltimes[(n >> 13) & 0xf]++;
		else
			x_one_ltimes[0xf]++;
	}
#endif
}

void
send_mondo_set(cpuset_t set)
{
	uint64_t starttick, endtick, tick, lasttick;
	int i, retries, stat, fcpuid, lcpuid;
	int ncpuids = 0;
	int shipped = 0;
	struct machcpu	*mcpup = &(CPU->cpu_m);

	ASSERT(!CPUSET_ISNULL(set));
	starttick = lasttick = gettick();
	endtick = starttick + xc_tick_limit;

	fcpuid = -1;
	for (i = 0; i < NCPU; i++) {
		if (CPU_IN_SET(set, i)) {
			ncpuids++;
			mcpup->cpu_list[0] = (uint16_t)i;
			stat = shipit(1, mcpup->cpu_list_ra);
			if (stat != 0) {
				ASSERT(stat == H_EWOULDBLOCK);
				if (fcpuid < 0)
					fcpuid = i;
				lcpuid = i;
				continue;
			}
			shipped++;
			CPUSET_DEL(set, i);
			if (CPUSET_ISNULL(set))
				break;
		}
	}

	retries = 0;
	while (shipped < ncpuids) {
		ASSERT(fcpuid >= 0 && fcpuid <= lcpuid && lcpuid < NCPU);
		tick = gettick();
		/*
		 * If there is a big jump between the current tick
		 * count and lasttick, we have probably hit a break
		 * point.  Adjust endtick accordingly to avoid panic.
		 */
		if (tick > (lasttick + xc_tick_jump_limit))
			endtick += (tick - lasttick);
		lasttick = tick;
		if (tick > endtick) {
			if (panic_quiesce)
				return;
			cmn_err(CE_CONT, "send mondo timeout "
			    "[retries: 0x%x]  cpuids: ", retries);
			for (i = fcpuid; i <= lcpuid; i++) {
				if (CPU_IN_SET(set, i))
					cmn_err(CE_CONT, " 0x%x", i);
			}
			cmn_err(CE_CONT, "\n");
			cmn_err(CE_PANIC, "send_mondo_set: timeout");
		}

		/* adjust fcpuid to the first CPU in set */
		for (; fcpuid <= lcpuid; fcpuid++)
			if (CPU_IN_SET(set, fcpuid))
				break;

		/* adjust lcpuid to the last CPU in set */
		for (; lcpuid >= fcpuid; lcpuid--)
			if (CPU_IN_SET(set, lcpuid))
				break;

		/* resend undelivered mondo */
		for (i = fcpuid; i <= lcpuid; i++) {
			if (CPU_IN_SET(set, i)) {
				mcpup->cpu_list[0] = (uint16_t)i;
				stat = shipit(1, mcpup->cpu_list_ra);
				if (stat != 0) {
					ASSERT(stat == H_EWOULDBLOCK);
					continue;
				}
				shipped++;
				CPUSET_DEL(set, i);
				if (shipped == ncpuids)
					break;
			}
		}
		if (shipped == ncpuids)
			break;

		while (gettick() < (tick + sys_clock_mhz))
			;
		retries++;
	}

#ifdef SEND_MONDO_STATS
	{
		int n = gettick() - starttick;
		if (n < 8192)
			x_set_stimes[n >> 7]++;
		else if (n < 16*8192)
			x_set_ltimes[(n >> 13) & 0xf]++;
		else
			x_set_ltimes[0xf]++;
	}
	x_set_cpus[shipped]++;
#endif
}

void
syncfpu(void)
{
}

void
cpu_flush_ecache(void)
{
}

void
sticksync_slave(void)
{}

void
sticksync_master(void)
{}

void
cpu_init_cache_scrub(void)
{}

int
dtrace_blksuword32_err(uintptr_t addr, uint32_t *data)
{
	int ret, watched;

	watched = watch_disable_addr((void *)addr, 4, S_WRITE);
	ret = dtrace_blksuword32(addr, data, 0);
	if (watched)
		watch_enable_addr((void *)addr, 4, S_WRITE);

	return (ret);
}

int
dtrace_blksuword32(uintptr_t addr, uint32_t *data, int tryagain)
{
	if (suword32((void *)addr, *data) == -1)
		return (tryagain ? dtrace_blksuword32_err(addr, data) : -1);
	dtrace_flush_sec(addr);

	return (0);
}

/*ARGSUSED*/
void
cpu_faulted_enter(struct cpu *cp)
{
}

/*ARGSUSED*/
void
cpu_faulted_exit(struct cpu *cp)
{
}

static int
kdi_cpu_ready_iter(int (*cb)(int, void *), void *arg)
{
	int rc, i;

	for (rc = 0, i = 0; i < NCPU; i++) {
		if (CPU_IN_SET(cpu_ready_set, i))
			rc += cb(i, arg);
	}

	return (rc);
}

/*
 * Sends a cross-call to a specified processor.  The caller assumes
 * responsibility for repetition of cross-calls, as appropriate (MARSA for
 * debugging).
 */
static int
kdi_xc_one(int cpuid, void (*func)(uintptr_t, uintptr_t), uintptr_t arg1,
    uintptr_t arg2)
{
	int stat;
	struct machcpu	*mcpup;
	uint64_t cpuaddr_reg = 0, cpuaddr_scr = 0;

	mcpup = &(((cpu_t *)get_cpuaddr(cpuaddr_reg, cpuaddr_scr))->cpu_m);

	/*
	 * if (idsr_busy())
	 *	return (KDI_XC_RES_ERR);
	 */

	init_mondo_nocheck((xcfunc_t *)func, arg1, arg2);

	mcpup->cpu_list[0] = (uint16_t)cpuid;
	stat = shipit(1, mcpup->cpu_list_ra);

	if (stat == 0)
		return (KDI_XC_RES_OK);
	else
		return (KDI_XC_RES_NACK);
}

static void
kdi_tickwait(clock_t nticks)
{
	clock_t endtick = gettick() + nticks;

	while (gettick() < endtick);
}

static void
kdi_cpu_init(int dcache_size, int dcache_linesize, int icache_size,
    int icache_linesize)
{
	kdi_dcache_size = dcache_size;
	kdi_dcache_linesize = dcache_linesize;
	kdi_icache_size = icache_size;
	kdi_icache_linesize = icache_linesize;
}

/* used directly by kdi_read/write_phys */
void
kdi_flush_caches(void)
{
	/* Not required on sun4v architecture. */
}

/*ARGSUSED*/
int
kdi_get_stick(uint64_t *stickp)
{
	return (-1);
}

void
cpu_kdi_init(kdi_t *kdi)
{
	kdi->kdi_flush_caches = kdi_flush_caches;
	kdi->mkdi_cpu_init = kdi_cpu_init;
	kdi->mkdi_cpu_ready_iter = kdi_cpu_ready_iter;
	kdi->mkdi_xc_one = kdi_xc_one;
	kdi->mkdi_tickwait = kdi_tickwait;
	kdi->mkdi_get_stick = kdi_get_stick;
}

/*
 * Routine to return memory information associated
 * with a physical address and syndrome.
 */
/* ARGSUSED */
int
cpu_get_mem_info(uint64_t synd, uint64_t afar,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp)
{
	return (ENOTSUP);
}

/*
 * This routine returns the size of the kernel's FRU name buffer.
 */
size_t
cpu_get_name_bufsize()
{
	return (UNUM_NAMLEN);
}

/*
 * This routine is a more generic interface to cpu_get_mem_unum(),
 * that may be used by other modules (e.g. mm).
 */
/* ARGSUSED */
int
cpu_get_mem_name(uint64_t synd, uint64_t *afsr, uint64_t afar,
    char *buf, int buflen, int *lenp)
{
	return (ENOTSUP);
}

/*
 * xt_sync - wait for previous x-traps to finish
 */
void
xt_sync(cpuset_t cpuset)
{
	union {
		uint8_t volatile byte[NCPU];
		uint64_t volatile xword[NCPU / 8];
	} cpu_sync;
	uint64_t starttick, endtick, tick, lasttick;
	int i;

	kpreempt_disable();
	CPUSET_DEL(cpuset, CPU->cpu_id);
	CPUSET_AND(cpuset, cpu_ready_set);

	/*
	 * Sun4v uses a queue for receiving mondos. Successful
	 * transmission of a mondo only indicates that the mondo
	 * has been written into the queue.
	 *
	 * We use an array of bytes to let each cpu to signal back
	 * to the cross trap sender that the cross trap has been
	 * executed. Set the byte to 1 before sending the cross trap
	 * and wait until other cpus reset it to 0.
	 */
	bzero((void *)&cpu_sync, NCPU);
	for (i = 0; i < NCPU; i++)
		if (CPU_IN_SET(cpuset, i))
			cpu_sync.byte[i] = 1;

	xt_some(cpuset, (xcfunc_t *)xt_sync_tl1,
	    (uint64_t)cpu_sync.byte, 0);

	starttick = lasttick = gettick();
	endtick = starttick + xc_tick_limit;

	for (i = 0; i < (NCPU / 8); i ++) {
		while (cpu_sync.xword[i] != 0) {
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
				if (panic_quiesce)
					goto out;
				cmn_err(CE_CONT, "Cross trap sync timeout "
				    "at cpu_sync.xword[%d]: 0x%lx\n",
				    i, cpu_sync.xword[i]);
				cmn_err(CE_PANIC, "xt_sync: timeout");
			}
		}
	}

out:
	kpreempt_enable();
}
