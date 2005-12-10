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
#include <sys/machsystm.h>
#include <sys/disp.h>
#include <sys/autoconf.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/clock.h>
#include <sys/pte.h>
#include <sys/scb.h>
#include <sys/cpu.h>
#include <sys/stack.h>
#include <sys/intreg.h>
#include <sys/ivintr.h>
#include <vm/as.h>
#include <vm/hat_sfmmu.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include <sys/vtrace.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/privregs.h>
#include <sys/machpcb.h>
#include <sys/proc.h>
#include <sys/cpupart.h>
#include <sys/pset.h>
#include <sys/cpu_module.h>
#include <sys/copyops.h>
#include <sys/panic.h>
#include <sys/bootconf.h>	/* for bootops */
#include <sys/chip.h>
#include <sys/kdi.h>
#include <sys/fpras.h>

#include <sys/prom_debug.h>
#include <sys/debug.h>

#include <sys/sunddi.h>
#include <sys/lgrp.h>
#include <sys/traptrace.h>
/*
 * External Routines:
 */
extern void map_wellknown_devices(void);

int	dcache_size;
int	dcache_linesize;
int	icache_size;
int	icache_linesize;
int	ecache_size;
int	ecache_alignsize;
int	ecache_associativity;
int	ecache_setsize;			/* max possible e$ setsize */
int	cpu_setsize;			/* max e$ setsize of configured cpus */
int	dcache_line_mask;		/* spitfire only */
int	vac_size;			/* cache size in bytes */
uint_t	vac_mask;			/* VAC alignment consistency mask */
int	vac_shift;			/* log2(vac_size) for ppmapout() */
int	vac = 0;	/* virtual address cache type (none == 0) */

/*
 * fpRAS.  An individual sun4* machine class (or perhaps subclass,
 * eg sun4u/cheetah) must set fpras_implemented to indicate that it implements
 * the fpRAS feature.  The feature can be suppressed by setting fpras_disable
 * or the mechanism can be disabled for individual copy operations with
 * fpras_disableids.  All these are checked in post_startup() code so
 * fpras_disable and fpras_disableids can be set in /etc/system.
 * If/when fpRAS is implemented on non-sun4 architectures these
 * definitions will need to move up to the common level.
 */
int	fpras_implemented;
int	fpras_disable;
int	fpras_disableids;

/*
 * Static Routines:
 */
static void kern_splr_preprom(void);
static void kern_splx_postprom(void);

/*
 * Setup routine called right before main(). Interposing this function
 * before main() allows us to call it in a machine-independent fashion.
 */

void
mlsetup(struct regs *rp, void *cif, kfpu_t *fp)
{
	struct machpcb *mpcb;

	extern char t0stack[];
	extern struct classfuncs sys_classfuncs;
	extern disp_t cpu0_disp;
	unsigned long long pa;

#ifdef TRAPTRACE
	TRAP_TRACE_CTL *ctlp;
#endif /* TRAPTRACE */

	/*
	 * initialize cpu_self
	 */
	cpu0.cpu_self = &cpu0;

	/*
	 * initialize t0
	 */
	t0.t_stk = (caddr_t)rp - REGOFF;
	/* Can't use va_to_pa here - wait until prom_ initialized */
	t0.t_stkbase = t0stack;
	t0.t_pri = maxclsyspri - 3;
	t0.t_schedflag = TS_LOAD | TS_DONT_SWAP;
	t0.t_procp = &p0;
	t0.t_plockp = &p0lock.pl_lock;
	t0.t_lwp = &lwp0;
	t0.t_forw = &t0;
	t0.t_back = &t0;
	t0.t_next = &t0;
	t0.t_prev = &t0;
	t0.t_cpu = &cpu0;			/* loaded by _start */
	t0.t_disp_queue = &cpu0_disp;
	t0.t_bind_cpu = PBIND_NONE;
	t0.t_bind_pset = PS_NONE;
	t0.t_cpupart = &cp_default;
	t0.t_clfuncs = &sys_classfuncs.thread;
	t0.t_copyops = NULL;
	THREAD_ONPROC(&t0, CPU);

	lwp0.lwp_thread = &t0;
	lwp0.lwp_procp = &p0;
	lwp0.lwp_regs = (void *)rp;
	t0.t_tid = p0.p_lwpcnt = p0.p_lwprcnt = p0.p_lwpid = 1;

	mpcb = lwptompcb(&lwp0);
	mpcb->mpcb_fpu = fp;
	mpcb->mpcb_fpu->fpu_q = mpcb->mpcb_fpu_q;
	mpcb->mpcb_thread = &t0;
	lwp0.lwp_fpu = (void *)mpcb->mpcb_fpu;

	p0.p_exec = NULL;
	p0.p_stat = SRUN;
	p0.p_flag = SSYS;
	p0.p_tlist = &t0;
	p0.p_stksize = 2*PAGESIZE;
	p0.p_stkpageszc = 0;
	p0.p_as = &kas;
	p0.p_lockp = &p0lock;
	p0.p_utraps = NULL;
	p0.p_brkpageszc = 0;
	sigorset(&p0.p_ignore, &ignoredefault);

	CPU->cpu_thread = &t0;
	CPU->cpu_dispthread = &t0;
	bzero(&cpu0_disp, sizeof (disp_t));
	CPU->cpu_disp = &cpu0_disp;
	CPU->cpu_disp->disp_cpu = CPU;
	CPU->cpu_idle_thread = &t0;
	CPU->cpu_flags = CPU_RUNNING;
	CPU->cpu_id = getprocessorid();
	CPU->cpu_dispatch_pri = t0.t_pri;

	/*
	 * Initialize thread/cpu microstate accounting here
	 */
	init_mstate(&t0, LMS_SYSTEM);
	init_cpu_mstate(CPU, CMS_SYSTEM);

	/*
	 * Initialize lists of available and active CPUs.
	 */
	cpu_list_init(CPU);

	cpu_vm_data_init(CPU);

	prom_init("kernel", cif);
	(void) prom_set_preprom(kern_splr_preprom);
	(void) prom_set_postprom(kern_splx_postprom);

	PRM_INFO("mlsetup: now ok to call prom_printf");

	mpcb->mpcb_pa = va_to_pa(t0.t_stk);

	/*
	 * Claim the physical and virtual resources used by panicbuf,
	 * then map panicbuf.  This operation removes the phys and
	 * virtual addresses from the free lists.
	 */
	if (prom_claim_virt(PANICBUFSIZE, panicbuf) != panicbuf)
		prom_panic("Can't claim panicbuf virtual address");

	if (prom_retain("panicbuf", PANICBUFSIZE, MMU_PAGESIZE, &pa) != 0)
		prom_panic("Can't allocate retained panicbuf physical address");

	if (prom_map_phys(-1, PANICBUFSIZE, panicbuf, pa) != 0)
		prom_panic("Can't map panicbuf");

	PRM_DEBUG(panicbuf);
	PRM_DEBUG(pa);

#ifdef TRAPTRACE
	/*
	 * initialize the trap trace buffer for the boot cpu
	 * XXX todo, dynamically allocate this buffer too
	 */
	ctlp = &trap_trace_ctl[CPU->cpu_id];
	ctlp->d.vaddr_base = trap_tr0;
	ctlp->d.offset = ctlp->d.last_offset = 0;
	ctlp->d.limit = TRAP_TSIZE;		/* XXX dynamic someday */
	ctlp->d.paddr_base = va_to_pa(trap_tr0);
#endif /* TRAPTRACE */
	/*
	 * initialize HV trap trace buffer for the boot cpu
	 */
	mach_htraptrace_setup(CPU->cpu_id);
	mach_htraptrace_configure(CPU->cpu_id);

	/*
	 * lgroup framework initialization. This must be done prior
	 * to devices being mapped.
	 */
	lgrp_init();

	cpu_setup();

	if (boothowto & RB_HALT) {
		prom_printf("unix: kernel halted by -h flag\n");
		prom_enter_mon();
	}

	setcputype();
	map_wellknown_devices();
	setcpudelay();

	/*
	 * Associate the boot cpu with a physical processor.
	 * This needs to be done after devices are mapped, since
	 * we need to know what type of physical processor this is.
	 * (CMP for example)
	 */
	chip_cpu_init(CPU);
	chip_cpu_assign(CPU);
}

/*
 * These routines are called immediately before and
 * immediately after calling into the firmware.  The
 * firmware is significantly confused by preemption -
 * particularly on MP machines - but also on UP's too.
 */

static int saved_spl;

static void
kern_splr_preprom(void)
{
	saved_spl = spl7();
}

static void
kern_splx_postprom(void)
{
	splx(saved_spl);
}
