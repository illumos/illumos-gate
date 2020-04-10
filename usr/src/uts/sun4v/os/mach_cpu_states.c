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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <sys/traptrace.h>
#include <sys/hypervisor_api.h>
#include <sys/vmsystm.h>
#include <sys/dtrace.h>
#include <sys/xc_impl.h>
#include <sys/callb.h>
#include <sys/mdesc.h>
#include <sys/mach_descrip.h>
#include <sys/wdt.h>
#include <sys/soft_state.h>
#include <sys/promimpl.h>
#include <sys/hsvc.h>
#include <sys/ldoms.h>
#include <sys/kldc.h>
#include <sys/clock_impl.h>
#include <sys/suspend.h>
#include <sys/dumphdr.h>

/*
 * hvdump_buf_va is a pointer to the currently-configured hvdump_buf.
 * A value of NULL indicates that this area is not configured.
 * hvdump_buf_sz is tunable but will be clamped to HVDUMP_SIZE_MAX.
 */

caddr_t hvdump_buf_va;
uint64_t hvdump_buf_sz = HVDUMP_SIZE_DEFAULT;
static uint64_t hvdump_buf_pa;

u_longlong_t panic_tick;

extern u_longlong_t gettick();
static void reboot_machine(char *);
static void update_hvdump_buffer(void);

/*
 * For xt_sync synchronization.
 */
extern uint64_t xc_tick_limit;
extern uint64_t xc_tick_jump_limit;
extern uint64_t xc_sync_tick_limit;

/*
 * Bring in the cpc PIL_15 handler for panic_enter_hw.
 */
extern uint64_t	cpc_level15_inum;

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


#define	BOOT_CMD_MAX_LEN	256	/* power of 2 & 16-byte aligned */
#define	BOOT_CMD_BASE		"boot "

/*
 * In an LDoms system we do not save the user's boot args in NVRAM
 * as is done on legacy systems.  Instead, we format and send a
 * 'reboot-command' variable to the variable service.  The contents
 * of the variable are retrieved by OBP and used verbatim for
 * the next boot.
 */
static void
store_boot_cmd(char *args, boolean_t add_boot_str, boolean_t invoke_cb)
{
	static char	*cmd_buf;
	size_t		len = 1;
	pnode_t		node;
	size_t		base_len = 0;
	size_t		args_len;
	size_t		args_max;
	uint64_t	majornum;
	uint64_t	minornum;
	uint64_t	buf_pa;
	uint64_t	status;

	status = hsvc_version(HSVC_GROUP_REBOOT_DATA, &majornum, &minornum);

	/*
	 * invoke_cb is set to true when we are in a normal shutdown sequence
	 * (interrupts are not blocked, the system is not panicking or being
	 * suspended). In that case, we can use any method to store the boot
	 * command. Otherwise storing the boot command can not be done using
	 * a domain service because it can not be safely used in that context.
	 */
	if ((status != H_EOK) && (invoke_cb == B_FALSE))
		return;

	cmd_buf = contig_mem_alloc(BOOT_CMD_MAX_LEN);
	if (cmd_buf == NULL)
		return;

	if (add_boot_str) {
		(void) strcpy(cmd_buf, BOOT_CMD_BASE);

		base_len = strlen(BOOT_CMD_BASE);
		len = base_len + 1;
	}

	if (args != NULL) {
		args_len = strlen(args);
		args_max = BOOT_CMD_MAX_LEN - len;

		if (args_len > args_max) {
			cmn_err(CE_WARN, "Reboot command too long (%ld), "
			    "truncating command arguments", len + args_len);

			args_len = args_max;
		}

		len += args_len;
		(void) strncpy(&cmd_buf[base_len], args, args_len);
	}

	/*
	 * Save the reboot-command with HV, if reboot data group is
	 * negotiated. Else save the reboot-command via vars-config domain
	 * services on the SP.
	 */
	if (status == H_EOK) {
		buf_pa = va_to_pa(cmd_buf);
		status = hv_reboot_data_set(buf_pa, len);
		if (status != H_EOK) {
			cmn_err(CE_WARN, "Unable to store boot command for "
			    "use on reboot with HV: error = 0x%lx", status);
		}
	} else {
		node = prom_optionsnode();
		if ((node == OBP_NONODE) || (node == OBP_BADNODE) ||
		    prom_setprop(node, "reboot-command", cmd_buf, len) == -1)
			cmn_err(CE_WARN, "Unable to store boot command for "
			    "use on reboot");
	}
}


/*
 * Machine dependent code to reboot.
 *
 * "bootstr", when non-null, points to a string to be used as the
 * argument string when rebooting.
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
	 * XXX - rconsvp is set to NULL to ensure that output messages
	 * are sent to the underlying "hardware" device using the
	 * monitor's printf routine since we are in the process of
	 * either rebooting or halting the machine.
	 */
	rconsvp = NULL;

	switch (fcn) {
	case AD_HALT:
		/*
		 * LDoms: By storing a no-op command
		 * in the 'reboot-command' variable we cause OBP
		 * to ignore the setting of 'auto-boot?' after
		 * it completes the reset.  This causes the system
		 * to stop at the ok prompt.
		 */
		if (domaining_enabled())
			store_boot_cmd("noop", B_FALSE, invoke_cb);
		break;

	case AD_POWEROFF:
		break;

	default:
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

		/*
		 * If LDoms is running, we must save the boot string
		 * before we enter restricted mode.  This is possible
		 * only if we are not being called from panic.
		 */
		if (domaining_enabled())
			store_boot_cmd(bootstr, B_TRUE, invoke_cb);
	}

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

	watchdog_clear();

	if (fcn == AD_HALT) {
		mach_set_soft_state(SIS_TRANSITION,
		    &SOLARIS_SOFT_STATE_HALT_MSG);
		halt((char *)NULL);
	} else if (fcn == AD_POWEROFF) {
		mach_set_soft_state(SIS_TRANSITION,
		    &SOLARIS_SOFT_STATE_POWER_MSG);
		power_down(NULL);
	} else {
		mach_set_soft_state(SIS_TRANSITION,
		    &SOLARIS_SOFT_STATE_REBOOT_MSG);
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

	dumpsys_helper();

	for (;;)
		;
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

	if (!panic_tick) {
		panic_tick = gettick();
		if (mach_htraptrace_enable) {
			uint64_t prev_freeze;

			/*  there are no possible error codes for this hcall */
			(void) hv_ttrace_freeze((uint64_t)TRAP_TFREEZE_ALL,
			    &prev_freeze);
		}
#ifdef TRAPTRACE
		TRAPTRACE_FREEZE;
#endif
	}

	mach_set_soft_state(SIS_TRANSITION, &SOLARIS_SOFT_STATE_PANIC_MSG);

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

	/*
	 * Turn off TRAPTRACE and save the current %tick value in panic_tick.
	 */
	if (!panic_tick) {
		panic_tick = gettick();
		if (mach_htraptrace_enable) {
			uint64_t prev_freeze;

			/*  there are no possible error codes for this hcall */
			(void) hv_ttrace_freeze((uint64_t)TRAP_TFREEZE_ALL,
			    &prev_freeze);
		}
#ifdef TRAPTRACE
		TRAPTRACE_FREEZE;
#endif
	}
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
		"unexpected error from hypervisor call", /* PTL1_BAD_HCALL */
		"unexpected global level(%gl)", /* PTL1_BAD_GL */
		"Watchdog Reset",		/* PTL1_BAD_WATCHDOG */
		"unexpected RED mode trap",	/* PTL1_BAD_RED */
		"return value EINVAL from hcall: "\
		    "UNMAP_PERM_ADDR",	/* PTL1_BAD_HCALL_UNMAP_PERM_EINVAL */
		"return value ENOMAP from hcall: "\
		    "UNMAP_PERM_ADDR", /* PTL1_BAD_HCALL_UNMAP_PERM_ENOMAP */
		"error raising a TSB exception", /* PTL1_BAD_RAISE_TSBEXCP */
		"missing shared TSB"	/* PTL1_NO_SCDTSB8K */
	};

	uint_t reason = pstate->ptl1_regs.ptl1_gregs[0].ptl1_g1;
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
clear_watchdog_on_exit(void)
{
	if (watchdog_enabled && watchdog_activated) {
		prom_printf("Debugging requested; hardware watchdog "
		    "suspended.\n");
		(void) watchdog_suspend();
	}
}

/*
 * Restore the watchdog timer when returning from a debugger
 * after a panic or L1-A and resume watchdog pat.
 */
void
restore_watchdog_on_entry()
{
	watchdog_resume();
}

int
kdi_watchdog_disable(void)
{
	watchdog_suspend();

	return (0);
}

void
kdi_watchdog_restore(void)
{
	watchdog_resume();
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
	md_t *mdp;
	mde_cookie_t rootnode;
	int		listsz;
	mde_cookie_t	*listp = NULL;
	int	num_nodes;
	uint64_t stick_prop;

	if (broken_md_flag) {
		sys_tick_freq = cpunodes[CPU->cpu_id].clock_freq;
		return;
	}

	if ((mdp = md_get_handle()) == NULL)
		panic("stick_frequency property not found in MD");

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	num_nodes = md_node_count(mdp);

	ASSERT(num_nodes > 0);
	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = (mde_cookie_t *)prom_alloc((caddr_t)0, listsz, 0);

	if (listp == NULL)
		panic("cannot allocate list for MD properties");

	num_nodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "platform"),
	    md_find_name(mdp, "fwd"), listp);

	ASSERT(num_nodes == 1);

	if (md_get_prop_val(mdp, *listp, "stick-frequency", &stick_prop) != 0)
		panic("stick_frequency property not found in MD");

	sys_tick_freq = stick_prop;

	prom_free((caddr_t)listp, listsz);
	(void) md_fini_handle(mdp);
}

int shipit(int n, uint64_t cpu_list_ra);

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
	while (stat != H_EOK) {
		if (stat != H_EWOULDBLOCK) {
			if (panic_quiesce)
				return;
			if (stat == H_ECPUERROR)
				cmn_err(CE_PANIC, "send_one_mondo: "
				    "cpuid: 0x%x has been marked in "
				    "error", cpuid);
			else
				cmn_err(CE_PANIC, "send_one_mondo: "
				    "unexpected hypervisor error 0x%x "
				    "while sending a mondo to cpuid: "
				    "0x%x", stat, cpuid);
		}
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
		uint64_t n = gettick() - starttick;
		if (n < 8192)
			x_one_stimes[n >> 7]++;
		else if (n < 15*8192)
			x_one_ltimes[n >> 13]++;
		else
			x_one_ltimes[0xf]++;
	}
#endif
}

void
send_mondo_set(cpuset_t set)
{
	uint64_t starttick, endtick, tick, lasttick;
	uint_t largestid, smallestid;
	int i, j;
	int ncpuids = 0;
	int shipped = 0;
	int retries = 0;
	struct machcpu	*mcpup = &(CPU->cpu_m);

	ASSERT(!CPUSET_ISNULL(set));
	CPUSET_BOUNDS(set, smallestid, largestid);
	if (smallestid == CPUSET_NOTINSET) {
		return;
	}

	starttick = lasttick = gettick();
	endtick = starttick + xc_tick_limit;

	/*
	 * Assemble CPU list for HV argument. We already know
	 * smallestid and largestid are members of set.
	 */
	mcpup->cpu_list[ncpuids++] = (uint16_t)smallestid;
	if (largestid != smallestid) {
		for (i = smallestid+1; i <= largestid-1; i++) {
			if (CPU_IN_SET(set, i)) {
				mcpup->cpu_list[ncpuids++] = (uint16_t)i;
			}
		}
		mcpup->cpu_list[ncpuids++] = (uint16_t)largestid;
	}

	do {
		int stat;

		stat = shipit(ncpuids, mcpup->cpu_list_ra);
		if (stat == H_EOK) {
			shipped += ncpuids;
			break;
		}

		/*
		 * Either not all CPU mondos were sent, or an
		 * error occurred. CPUs that were sent mondos
		 * have their CPU IDs overwritten in cpu_list.
		 * Reset cpu_list so that it only holds those
		 * CPU IDs that still need to be sent.
		 */
		for (i = 0, j = 0; i < ncpuids; i++) {
			if (mcpup->cpu_list[i] == HV_SEND_MONDO_ENTRYDONE) {
				shipped++;
			} else {
				mcpup->cpu_list[j++] = mcpup->cpu_list[i];
			}
		}
		ncpuids = j;

		/*
		 * Now handle possible errors returned
		 * from hypervisor.
		 */
		if (stat == H_ECPUERROR) {
			int errorcpus;

			if (!panic_quiesce)
				cmn_err(CE_CONT, "send_mondo_set: cpuid(s) ");

			/*
			 * Remove any CPUs in the error state from
			 * cpu_list. At this point cpu_list only
			 * contains the CPU IDs for mondos not
			 * succesfully sent.
			 */
			for (i = 0, errorcpus = 0; i < ncpuids; i++) {
				uint64_t state = CPU_STATE_INVALID;
				uint16_t id = mcpup->cpu_list[i];

				(void) hv_cpu_state(id, &state);
				if (state == CPU_STATE_ERROR) {
					if (!panic_quiesce)
						cmn_err(CE_CONT, "0x%x ", id);
					errorcpus++;
				} else if (errorcpus > 0) {
					mcpup->cpu_list[i - errorcpus] =
					    mcpup->cpu_list[i];
				}
			}
			ncpuids -= errorcpus;

			if (!panic_quiesce) {
				if (errorcpus == 0) {
					cmn_err(CE_CONT, "<none> have been "
					    "marked in error\n");
					cmn_err(CE_PANIC, "send_mondo_set: "
					    "hypervisor returned "
					    "H_ECPUERROR but no CPU in "
					    "cpu_list in error state");
				} else {
					cmn_err(CE_CONT, "have been marked in "
					    "error\n");
					cmn_err(CE_PANIC, "send_mondo_set: "
					    "CPU(s) in error state");
				}
			}
		} else if (stat != H_EWOULDBLOCK) {
			if (panic_quiesce)
				return;
			/*
			 * For all other errors, panic.
			 */
			cmn_err(CE_CONT, "send_mondo_set: unexpected "
			    "hypervisor error 0x%x while sending a "
			    "mondo to cpuid(s):", stat);
			for (i = 0; i < ncpuids; i++) {
				cmn_err(CE_CONT, " 0x%x", mcpup->cpu_list[i]);
			}
			cmn_err(CE_CONT, "\n");
			cmn_err(CE_PANIC, "send_mondo_set: unexpected "
			    "hypervisor error");
		}

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
			for (i = 0; i < ncpuids; i++)
				cmn_err(CE_CONT, " 0x%x", mcpup->cpu_list[i]);
			cmn_err(CE_CONT, "\n");
			cmn_err(CE_PANIC, "send_mondo_set: timeout");
		}

		while (gettick() < (tick + sys_clock_mhz))
			;
		retries++;
	} while (ncpuids > 0);

	CPU_STATS_ADDQ(CPU, sys, xcalls, shipped);

#ifdef SEND_MONDO_STATS
	{
		uint64_t n = gettick() - starttick;
		if (n < 8192)
			x_set_stimes[n >> 7]++;
		else if (n < 15*8192)
			x_set_ltimes[n >> 13]++;
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
sticksync_slave(void)
{
	suspend_sync_tick_stick_npt();
}

void
sticksync_master(void)
{}

void
cpu_init_cache_scrub(void)
{
	mach_set_soft_state(SIS_NORMAL, &SOLARIS_SOFT_STATE_RUN_MSG);
}

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

	while (gettick() < endtick)
		;
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

uint64_t	soft_state_message_ra[SOLARIS_SOFT_STATE_MSG_CNT];
static uint64_t	soft_state_saved_state = (uint64_t)-1;
static int	soft_state_initialized = 0;
static uint64_t soft_state_sup_minor;		/* Supported minor number */
static hsvc_info_t soft_state_hsvc = {
			HSVC_REV_1, NULL, HSVC_GROUP_SOFT_STATE, 1, 0, NULL };


static void
sun4v_system_claim(void)
{
	lbolt_debug_entry();

	watchdog_suspend();
	kldc_debug_enter();
	/*
	 * For "mdb -K", set soft state to debugging
	 */
	if (soft_state_saved_state == -1) {
		mach_get_soft_state(&soft_state_saved_state,
		    &SOLARIS_SOFT_STATE_SAVED_MSG);
	}
	/*
	 * check again as the read above may or may not have worked and if
	 * it didn't then soft state will still be -1
	 */
	if (soft_state_saved_state != -1) {
		mach_set_soft_state(SIS_TRANSITION,
		    &SOLARIS_SOFT_STATE_DEBUG_MSG);
	}
}

static void
sun4v_system_release(void)
{
	watchdog_resume();
	/*
	 * For "mdb -K", set soft_state state back to original state on exit
	 */
	if (soft_state_saved_state != -1) {
		mach_set_soft_state(soft_state_saved_state,
		    &SOLARIS_SOFT_STATE_SAVED_MSG);
		soft_state_saved_state = -1;
	}

	lbolt_debug_return();
}

void
plat_kdi_init(kdi_t *kdi)
{
	kdi->pkdi_system_claim = sun4v_system_claim;
	kdi->pkdi_system_release = sun4v_system_release;
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

/* ARGSUSED */
int
cpu_get_mem_sid(char *unum, char *buf, int buflen, int *lenp)
{
	return (ENOTSUP);
}

/* ARGSUSED */
int
cpu_get_mem_addr(char *unum, char *sid, uint64_t offset, uint64_t *addrp)
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
	uint64_t starttick, endtick, tick, lasttick, traptrace_id;
	uint_t largestid, smallestid;
	int i, j;

	kpreempt_disable();
	CPUSET_DEL(cpuset, CPU->cpu_id);
	CPUSET_AND(cpuset, cpu_ready_set);

	CPUSET_BOUNDS(cpuset, smallestid, largestid);
	if (smallestid == CPUSET_NOTINSET)
		goto out;

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
	cpu_sync.byte[smallestid] = 1;
	if (largestid != smallestid) {
		for (i = (smallestid + 1); i <= (largestid - 1); i++)
			if (CPU_IN_SET(cpuset, i))
				cpu_sync.byte[i] = 1;
		cpu_sync.byte[largestid] = 1;
	}

	/*
	 * To help debug xt_sync panic, each mondo is uniquely identified
	 * by passing the tick value, traptrace_id as the second mondo
	 * argument to xt_some which is logged in CPU's mondo queue,
	 * traptrace buffer and the panic message.
	 */
	traptrace_id = gettick();
	xt_some(cpuset, (xcfunc_t *)xt_sync_tl1,
	    (uint64_t)cpu_sync.byte, traptrace_id);

	starttick = lasttick = gettick();
	endtick = starttick + xc_sync_tick_limit;

	for (i = (smallestid / 8); i <= (largestid / 8); i++) {
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
				cmn_err(CE_CONT, "Cross trap sync timeout:  "
				    "at cpu_sync.xword[%d]: 0x%lx "
				    "cpu_sync.byte: 0x%lx "
				    "starttick: 0x%lx endtick: 0x%lx "
				    "traptrace_id = 0x%lx\n",
				    i, cpu_sync.xword[i],
				    (uint64_t)cpu_sync.byte,
				    starttick, endtick, traptrace_id);
				cmn_err(CE_CONT, "CPUIDs:");
				for (j = (i * 8); j <= largestid; j++) {
					if (cpu_sync.byte[j] != 0)
						cmn_err(CE_CONT, " 0x%x", j);
				}
				cmn_err(CE_PANIC, "xt_sync: timeout");
			}
		}
	}

out:
	kpreempt_enable();
}

#define	QFACTOR		200
/*
 * Recalculate the values of the cross-call timeout variables based
 * on the value of the 'inter-cpu-latency' property of the platform node.
 * The property sets the number of nanosec to wait for a cross-call
 * to be acknowledged.  Other timeout variables are derived from it.
 *
 * N.B. This implementation is aware of the internals of xc_init()
 * and updates many of the same variables.
 */
void
recalc_xc_timeouts(void)
{
	typedef union {
		uint64_t whole;
		struct {
			uint_t high;
			uint_t low;
		} half;
	} u_number;

	/* See x_call.c for descriptions of these extern variables. */
	extern uint64_t xc_tick_limit_scale;
	extern uint64_t xc_mondo_time_limit;
	extern uint64_t xc_func_time_limit;
	extern uint64_t xc_scale;
	extern uint64_t xc_mondo_multiplier;
	extern uint_t   nsec_shift;

	/* Temp versions of the target variables */
	uint64_t tick_limit;
	uint64_t tick_jump_limit;
	uint64_t mondo_time_limit;
	uint64_t func_time_limit;
	uint64_t scale;

	uint64_t latency;	/* nanoseconds */
	uint64_t maxfreq;
	uint64_t tick_limit_save = xc_tick_limit;
	uint64_t sync_tick_limit_save = xc_sync_tick_limit;
	uint_t   tick_scale;
	uint64_t top;
	uint64_t bottom;
	u_number tk;

	md_t *mdp;
	int nrnode;
	mde_cookie_t *platlist;

	/*
	 * Look up the 'inter-cpu-latency' (optional) property in the
	 * platform node of the MD.  The units are nanoseconds.
	 */
	if ((mdp = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "recalc_xc_timeouts: "
		    "Unable to initialize machine description");
		return;
	}

	nrnode = md_alloc_scan_dag(mdp,
	    md_root_node(mdp), "platform", "fwd", &platlist);

	ASSERT(nrnode == 1);
	if (nrnode < 1) {
		cmn_err(CE_WARN, "recalc_xc_timeouts: platform node missing");
		goto done;
	}
	if (md_get_prop_val(mdp, platlist[0],
	    "inter-cpu-latency", &latency) == -1)
		goto done;

	/*
	 * clock.h defines an assembly-language macro
	 * (NATIVE_TIME_TO_NSEC_SCALE) to convert from %stick
	 * units to nanoseconds.  Since the inter-cpu-latency
	 * units are nanoseconds and the xc_* variables require
	 * %stick units, we need the inverse of that function.
	 * The trick is to perform the calculation without
	 * floating point, but also without integer truncation
	 * or overflow.  To understand the calculation below,
	 * please read the discussion of the macro in clock.h.
	 * Since this new code will be invoked infrequently,
	 * we can afford to implement it in C.
	 *
	 * tick_scale is the reciprocal of nsec_scale which is
	 * calculated at startup in setcpudelay().  The calc
	 * of tick_limit parallels that of NATIVE_TIME_TO_NSEC_SCALE
	 * except we use tick_scale instead of nsec_scale and
	 * C instead of assembler.
	 */
	tick_scale = (uint_t)(((u_longlong_t)sys_tick_freq
	    << (32 - nsec_shift)) / NANOSEC);

	tk.whole = latency;
	top = ((uint64_t)tk.half.high << 4) * tick_scale;
	bottom = (((uint64_t)tk.half.low << 4) * (uint64_t)tick_scale) >> 32;
	tick_limit = top + bottom;

	/*
	 * xc_init() calculated 'maxfreq' by looking at all the cpus,
	 * and used it to derive some of the timeout variables that we
	 * recalculate below.  We can back into the original value by
	 * using the inverse of one of those calculations.
	 */
	maxfreq = xc_mondo_time_limit / xc_scale;

	/*
	 * Don't allow the new timeout (xc_tick_limit) to fall below
	 * the system tick frequency (stick).  Allowing the timeout
	 * to be set more tightly than this empirically determined
	 * value may cause panics.
	 */
	tick_limit = tick_limit < sys_tick_freq ? sys_tick_freq : tick_limit;

	tick_jump_limit = tick_limit / 32;
	tick_limit *= xc_tick_limit_scale;

	/*
	 * Recalculate xc_scale since it is used in a callback function
	 * (xc_func_timeout_adj) to adjust two of the timeouts dynamically.
	 * Make the change in xc_scale proportional to the change in
	 * xc_tick_limit.
	 */
	scale = (xc_scale * tick_limit + sys_tick_freq / 2) / tick_limit_save;
	if (scale == 0)
		scale = 1;

	mondo_time_limit = maxfreq * scale;
	func_time_limit = mondo_time_limit * xc_mondo_multiplier;

	/*
	 * Don't modify the timeouts if nothing has changed.  Else,
	 * stuff the variables with the freshly calculated (temp)
	 * variables.  This minimizes the window where the set of
	 * values could be inconsistent.
	 */
	if (tick_limit != xc_tick_limit) {
		xc_tick_limit = tick_limit;
		xc_tick_jump_limit = tick_jump_limit;
		xc_scale = scale;
		xc_mondo_time_limit = mondo_time_limit;
		xc_func_time_limit = func_time_limit;
	}

done:
	/*
	 * Increase the timeout limit for xt_sync() cross calls.
	 */
	xc_sync_tick_limit = xc_tick_limit * (cpu_q_entries / QFACTOR);
	xc_sync_tick_limit = xc_sync_tick_limit < xc_tick_limit ?
	    xc_tick_limit : xc_sync_tick_limit;

	/*
	 * Force the new values to be used for future cross calls.
	 * This is necessary only when we increase the timeouts.
	 */
	if ((xc_tick_limit > tick_limit_save) || (xc_sync_tick_limit >
	    sync_tick_limit_save)) {
		cpuset_t cpuset = cpu_ready_set;
		xt_sync(cpuset);
	}

	if (nrnode > 0)
		md_free_scan_dag(mdp, &platlist);
	(void) md_fini_handle(mdp);
}

void
mach_soft_state_init(void)
{
	int		i;
	uint64_t	ra;

	/*
	 * Try to register soft_state api. If it fails, soft_state api has not
	 * been implemented in the firmware, so do not bother to setup
	 * soft_state in the kernel.
	 */
	if ((i = hsvc_register(&soft_state_hsvc, &soft_state_sup_minor)) != 0) {
		return;
	}
	for (i = 0; i < SOLARIS_SOFT_STATE_MSG_CNT; i++) {
		ASSERT(strlen((const char *)(void *)
		    soft_state_message_strings + i) < SSM_SIZE);
		if ((ra = va_to_pa(
		    (void *)(soft_state_message_strings + i))) == -1ll) {
			return;
		}
		soft_state_message_ra[i] = ra;
	}
	/*
	 * Tell OBP that we are supporting Guest State
	 */
	prom_sun4v_soft_state_supported();
	soft_state_initialized = 1;
}

void
mach_set_soft_state(uint64_t state, uint64_t *string_ra)
{
	uint64_t	rc;

	if (soft_state_initialized && *string_ra) {
		rc = hv_soft_state_set(state, *string_ra);
		if (rc != H_EOK) {
			cmn_err(CE_WARN,
			    "hv_soft_state_set returned %ld\n", rc);
		}
	}
}

void
mach_get_soft_state(uint64_t *state, uint64_t *string_ra)
{
	uint64_t	rc;

	if (soft_state_initialized && *string_ra) {
		rc = hv_soft_state_get(*string_ra, state);
		if (rc != H_EOK) {
			cmn_err(CE_WARN,
			    "hv_soft_state_get returned %ld\n", rc);
			*state = -1;
		}
	}
}
