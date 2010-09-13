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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/cpu.h>
#include <sys/elf_SPARC.h>
#include <vm/hat_sfmmu.h>
#include <vm/page.h>
#include <vm/vm_dep.h>
#include <sys/cpuvar.h>
#include <sys/async.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/cpu_module.h>
#include <sys/prom_debug.h>
#include <sys/vmsystm.h>
#include <sys/prom_plat.h>
#include <sys/sysmacros.h>
#include <sys/intreg.h>
#include <sys/machtrap.h>
#include <sys/ontrap.h>
#include <sys/ivintr.h>
#include <sys/atomic.h>
#include <sys/panic.h>
#include <sys/dtrace.h>
#include <vm/seg_spt.h>
#include <sys/simulate.h>
#include <sys/fault.h>


uint_t root_phys_addr_lo_mask = 0xffffffffU;

void
cpu_setup(void)
{
	extern int mmu_exported_pagesize_mask;
	char *generic_isa_set[] = {
	    "sparcv9+vis",
	    "sparcv8plus+vis",
	    NULL
	};

	/*
	 * The setup common to all CPU modules is done in cpu_setup_common
	 * routine.
	 */
	cpu_setup_common(generic_isa_set);

	cache |= (CACHE_PTAG | CACHE_IOCOHERENT);

	if (broken_md_flag) {
		/*
		 * Turn on the missing bits supported by sun4v architecture in
		 * MMU pagesize mask returned by MD.
		 */
		mmu_exported_pagesize_mask |= DEFAULT_SUN4V_MMU_PAGESIZE_MASK;
	} else {
		/*
		 * According to sun4v architecture each processor must
		 * support 8K, 64K and 4M page sizes. If any of the page
		 * size is missing from page size mask, then panic.
		 */
		if ((mmu_exported_pagesize_mask &
		    DEFAULT_SUN4V_MMU_PAGESIZE_MASK) !=
		    DEFAULT_SUN4V_MMU_PAGESIZE_MASK)
			cmn_err(CE_PANIC, "machine description"
			    " does not have required sun4v page sizes"
			    " 8K, 64K and 4M: MD mask is 0x%x",
			    mmu_exported_pagesize_mask);
	}

	/*
	 * If processor supports the subset of full 64-bit virtual
	 * address space, then set VA hole accordingly.
	 */
	if (va_bits < VA_ADDRESS_SPACE_BITS) {
		hole_start = (caddr_t)(1ull << (va_bits - 1));
		hole_end = (caddr_t)(0ull - (1ull << (va_bits - 1)));
	} else {
		hole_start = hole_end = 0;
	}
}

void
cpu_fiximp(struct cpu_node *cpunode)
{
	/*
	 * The Cache node is optional in MD. Therefore in case "Cache"
	 * does not exists in MD, set the default L2 cache associativity,
	 * size, linesize for generic CPU module.
	 */
	if (cpunode->ecache_size == 0)
		cpunode->ecache_size = 0x100000;
	if (cpunode->ecache_linesize == 0)
		cpunode->ecache_linesize = 64;
	if (cpunode->ecache_associativity == 0)
		cpunode->ecache_associativity = 1;
}

void
dtrace_flush_sec(uintptr_t addr)
{
	pfn_t pfn;
	proc_t *procp = ttoproc(curthread);
	page_t *pp;
	caddr_t va;

	pfn = hat_getpfnum(procp->p_as->a_hat, (void *)addr);
	if (pfn != -1) {
		ASSERT(pf_is_memory(pfn));
		pp = page_numtopp_noreclaim(pfn, SE_SHARED);
		if (pp != NULL) {
			va = ppmapin(pp, PROT_READ | PROT_WRITE, (void *)addr);
			/* sparc needs 8-byte align */
			doflush((caddr_t)((uintptr_t)va & -8l));
			ppmapout(va);
			page_unlock(pp);
		}
	}
}

void
cpu_map_exec_units(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * The cpu_ipipe and cpu_fpu fields are initialized based on
	 * the execution unit sharing information from the MD. They
	 * default to the CPU id in the absence of such information.
	 */
	cp->cpu_m.cpu_ipipe = cpunodes[cp->cpu_id].exec_unit_mapping;
	if (cp->cpu_m.cpu_ipipe == NO_EU_MAPPING_FOUND)
		cp->cpu_m.cpu_ipipe = (id_t)(cp->cpu_id);

	cp->cpu_m.cpu_fpu = cpunodes[cp->cpu_id].fpu_mapping;
	if (cp->cpu_m.cpu_fpu == NO_EU_MAPPING_FOUND)
		cp->cpu_m.cpu_fpu = (id_t)(cp->cpu_id);

	/*
	 * The cpu_chip field is initialized based on the information
	 * in the MD and assume that all cpus within a chip
	 * share the same L2 cache. If no such info is available, we
	 * set the cpu to belong to the defacto chip 0.
	 */
	cp->cpu_m.cpu_mpipe = cpunodes[cp->cpu_id].l2_cache_mapping;
	if (cp->cpu_m.cpu_mpipe == NO_L2_CACHE_MAPPING_FOUND)
		cp->cpu_m.cpu_mpipe = CPU_L2_CACHEID_INVALID;

	cp->cpu_m.cpu_core = (id_t)(cp->cpu_id);

	/*
	 * The cpu_chip field is set to invalid(unknown) for generic cpu.
	 */
	cp->cpu_m.cpu_chip = CPU_CHIPID_INVALID;
}

void
cpu_init_private(struct cpu *cp)
{
	cpu_map_exec_units(cp);
}

/*ARGSUSED*/
void
cpu_uninit_private(struct cpu *cp)
{}

/*
 * Invalidate a TSB. Since this needs to work on all sun4v
 * architecture compliant processors, we use the old method of
 * walking the TSB, setting each tag to TSBTAG_INVALID.
 */
void
cpu_inv_tsb(caddr_t tsb_base, uint_t tsb_bytes)
{
	struct tsbe *tsbaddr;

	for (tsbaddr = (struct tsbe *)(uintptr_t)tsb_base;
	    (uintptr_t)tsbaddr < (uintptr_t)(tsb_base + tsb_bytes);
	    tsbaddr++) {
		tsbaddr->tte_tag.tag_inthi = TSBTAG_INVALID;
	}
}

/*
 * Sun4v kernel must emulate code a generic sun4v processor may not support
 * i.e. VIS1 and VIS2.
 */
#define	IS_FLOAT(i) (((i) & 0x1000000) != 0)
#define	IS_IBIT_SET(x)	(x & 0x2000)
#define	IS_VIS1(op, op3)(op == 2 && op3 == 0x36)
#define	IS_PARTIAL_OR_SHORT_FLOAT_LD_ST(op, op3, asi)		\
		(op == 3 && (op3 == IOP_V8_LDDFA ||		\
		op3 == IOP_V8_STDFA) &&	asi > ASI_SNFL)
int
vis1_partial_support(struct regs *rp, k_siginfo_t *siginfo, uint_t *fault)
{
	char *badaddr;
	int instr;
	uint_t	optype, op3, asi;
	uint_t	ignor;

	if (!USERMODE(rp->r_tstate))
		return (-1);

	instr = fetch_user_instr((caddr_t)rp->r_pc);

	optype = (instr >> 30) & 0x3;
	op3 = (instr >> 19) & 0x3f;
	ignor = (instr >> 5) & 0xff;
	if (IS_IBIT_SET(instr)) {
		asi = (uint32_t)((rp->r_tstate >> TSTATE_ASI_SHIFT) &
		    TSTATE_ASI_MASK);
	} else {
		asi = ignor;
	}

	if (!IS_VIS1(optype, op3) &&
	    !IS_PARTIAL_OR_SHORT_FLOAT_LD_ST(optype, op3, asi)) {
		return (-1);
	}
	switch (simulate_unimp(rp, &badaddr)) {
	case SIMU_RETRY:
		break;	/* regs are already set up */
		/*NOTREACHED*/

	case SIMU_SUCCESS:
		/*
		 * skip the successfully
		 * simulated instruction
		 */
		rp->r_pc = rp->r_npc;
		rp->r_npc += 4;
		break;
		/*NOTREACHED*/

	case SIMU_FAULT:
		siginfo->si_signo = SIGSEGV;
		siginfo->si_code = SEGV_MAPERR;
		siginfo->si_addr = badaddr;
		*fault = FLTBOUNDS;
		break;

	case SIMU_DZERO:
		siginfo->si_signo = SIGFPE;
		siginfo->si_code = FPE_INTDIV;
		siginfo->si_addr = (caddr_t)rp->r_pc;
		*fault = FLTIZDIV;
		break;

	case SIMU_UNALIGN:
		siginfo->si_signo = SIGBUS;
		siginfo->si_code = BUS_ADRALN;
		siginfo->si_addr = badaddr;
		*fault = FLTACCESS;
		break;

	case SIMU_ILLEGAL:
	default:
		siginfo->si_signo = SIGILL;
		op3 = (instr >> 19) & 0x3F;
		if ((IS_FLOAT(instr) && (op3 == IOP_V8_STQFA) ||
		    (op3 == IOP_V8_STDFA)))
			siginfo->si_code = ILL_ILLADR;
		else
			siginfo->si_code = ILL_ILLOPC;
		siginfo->si_addr = (caddr_t)rp->r_pc;
		*fault = FLTILL;
		break;
	}
	return (0);
}

/*
 * Trapstat support for generic sun4v processor
 */
int
cpu_trapstat_conf(int cmd)
{
	int status;

	switch (cmd) {
	case CPU_TSTATCONF_INIT:
	case CPU_TSTATCONF_FINI:
	case CPU_TSTATCONF_ENABLE:
	case CPU_TSTATCONF_DISABLE:
		status = ENOTSUP;
		break;

	default:
		status = EINVAL;
		break;
	}
	return (status);
}

/*ARGSUSED*/
void
cpu_trapstat_data(void *buf, uint_t tstat_pgszs)
{
}
