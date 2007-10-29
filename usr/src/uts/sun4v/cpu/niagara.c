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
#include <sys/simulate.h>
#include <sys/fault.h>
#include <sys/niagararegs.h>
#include <sys/trapstat.h>
#include <sys/hsvc.h>

#define	NI_MMU_PAGESIZE_MASK	((1 << TTE8K) | (1 << TTE64K) | (1 << TTE4M) \
				    | (1 << TTE256M))

uint_t root_phys_addr_lo_mask = 0xffffffffU;
static niagara_mmustat_t *cpu_tstat_va;		/* VA of mmustat buffer */
static uint64_t cpu_tstat_pa;			/* PA of mmustat buffer */
char cpu_module_name[] = "SUNW,UltraSPARC-T1";

/*
 * Hypervisor services information for the NIAGARA CPU module
 */
static boolean_t niagara_hsvc_available = B_TRUE;
static uint64_t niagara_sup_minor;		/* Supported minor number */
static hsvc_info_t niagara_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_NIAGARA_CPU, 1, 0, cpu_module_name
};

void
cpu_setup(void)
{
	extern int mmu_exported_pagesize_mask;
	extern int cpc_has_overflow_intr;
	int status;
	char *ni_isa_set[] = {
	    "sparcv9+vis",
	    "sparcv9+vis2",
	    "sparcv8plus+vis",
	    "sparcv8plus+vis2",
	    NULL
	};

	/*
	 * Negotiate the API version for Niagara specific hypervisor
	 * services.
	 */
	status = hsvc_register(&niagara_hsvc, &niagara_sup_minor);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: cannot negotiate hypervisor services "
		    "group: 0x%lx major: 0x%lx minor: 0x%lx errno: %d\n",
		    niagara_hsvc.hsvc_modname, niagara_hsvc.hsvc_group,
		    niagara_hsvc.hsvc_major, niagara_hsvc.hsvc_minor, status);
		niagara_hsvc_available = B_FALSE;
	}

	/*
	 * The setup common to all CPU modules is done in cpu_setup_common
	 * routine.
	 */
	cpu_setup_common(ni_isa_set);

	cache |= (CACHE_PTAG | CACHE_IOCOHERENT);

	if (broken_md_flag) {
		/*
		 * Turn on the missing bits supported by Niagara CPU in
		 * MMU pagesize mask returned by MD.
		 */
		mmu_exported_pagesize_mask |= NI_MMU_PAGESIZE_MASK;
	} else {
		if ((mmu_exported_pagesize_mask &
		    DEFAULT_SUN4V_MMU_PAGESIZE_MASK) !=
		    DEFAULT_SUN4V_MMU_PAGESIZE_MASK)
			cmn_err(CE_PANIC, "machine description"
			    " does not have required sun4v page sizes"
			    " 8K, 64K and 4M: MD mask is 0x%x",
			    mmu_exported_pagesize_mask);
	}

	cpu_hwcap_flags |= AV_SPARC_ASI_BLK_INIT;

	/*
	 * Niagara supports a 48-bit subset of the full 64-bit virtual
	 * address space. Virtual addresses between 0x0000800000000000
	 * and 0xffff.7fff.ffff.ffff inclusive lie within a "VA Hole"
	 * and must never be mapped. In addition, software must not use
	 * pages within 4GB of the VA hole as instruction pages to
	 * avoid problems with prefetching into the VA hole.
	 */
	hole_start = (caddr_t)((1ull << (va_bits - 1)) - (1ull << 32));
	hole_end = (caddr_t)((0ull - (1ull << (va_bits - 1))) + (1ull << 32));

	/*
	 * Niagara has a performance counter overflow interrupt
	 */
	cpc_has_overflow_intr = 1;

	shctx_on = 0;
}

#define	MB(n)	((n) * 1024 * 1024)
/*
 * Set the magic constants of the implementation.
 */
void
cpu_fiximp(struct cpu_node *cpunode)
{
	/*
	 * The Cache node is optional in MD. Therefore in case "Cache"
	 * node does not exists in MD, set the default L2 cache associativity,
	 * size, linesize.
	 */
	if (cpunode->ecache_size == 0)
		cpunode->ecache_size = MB(3);
	if (cpunode->ecache_linesize == 0)
		cpunode->ecache_linesize = 64;
	if (cpunode->ecache_associativity == 0)
		cpunode->ecache_associativity = 12;
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
	 * Niagara defines the the core to be at the ipipe level
	 */
	cp->cpu_m.cpu_core = cp->cpu_m.cpu_ipipe;

	/*
	 * Niagara systems just have one chip. Therefore, the chip id
	 * mpipe id are always 0.
	 */
	cp->cpu_m.cpu_chip = 0;
	cp->cpu_m.cpu_mpipe = 0;
}

static int niagara_cpucnt;

void
cpu_init_private(struct cpu *cp)
{
	extern void niagara_kstat_init(void);

	ASSERT(MUTEX_HELD(&cpu_lock));

	cpu_map_exec_units(cp);

	if ((niagara_cpucnt++ == 0) && (niagara_hsvc_available == B_TRUE))
		niagara_kstat_init();
}

/*ARGSUSED*/
void
cpu_uninit_private(struct cpu *cp)
{
	extern void niagara_kstat_fini(void);

	ASSERT(MUTEX_HELD(&cpu_lock));

	if ((--niagara_cpucnt == 0) && (niagara_hsvc_available == B_TRUE))
		niagara_kstat_fini();
}

/*
 * On Niagara, any flush will cause all preceding stores to be
 * synchronized wrt the i$, regardless of address or ASI.  In fact,
 * the address is ignored, so we always flush address 0.
 */
/*ARGSUSED*/
void
dtrace_flush_sec(uintptr_t addr)
{
	doflush(0);
}

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
 * Trapstat support for Niagara processor
 */
int
cpu_trapstat_conf(int cmd)
{
	size_t len;
	uint64_t mmustat_pa, hvret;
	int status = 0;

	if (niagara_hsvc_available == B_FALSE)
		return (ENOTSUP);

	switch (cmd) {
	case CPU_TSTATCONF_INIT:
		ASSERT(cpu_tstat_va == NULL);
		len = (NCPU+1) * sizeof (niagara_mmustat_t);
		cpu_tstat_va = contig_mem_alloc_align(len,
		    sizeof (niagara_mmustat_t));
		if (cpu_tstat_va == NULL)
			status = EAGAIN;
		else {
			bzero(cpu_tstat_va, len);
			cpu_tstat_pa = va_to_pa(cpu_tstat_va);
		}
		break;

	case CPU_TSTATCONF_FINI:
		if (cpu_tstat_va) {
			len = (NCPU+1) * sizeof (niagara_mmustat_t);
			contig_mem_free(cpu_tstat_va, len);
			cpu_tstat_va = NULL;
			cpu_tstat_pa = 0;
		}
		break;

	case CPU_TSTATCONF_ENABLE:
		hvret = hv_niagara_mmustat_conf((cpu_tstat_pa +
		    (CPU->cpu_id+1) * sizeof (niagara_mmustat_t)),
		    (uint64_t *)&mmustat_pa);
		if (hvret != H_EOK)
			status = EINVAL;
		break;

	case CPU_TSTATCONF_DISABLE:
		hvret = hv_niagara_mmustat_conf(0, (uint64_t *)&mmustat_pa);
		if (hvret != H_EOK)
			status = EINVAL;
		break;

	default:
		status = EINVAL;
		break;
	}
	return (status);
}

void
cpu_trapstat_data(void *buf, uint_t tstat_pgszs)
{
	niagara_mmustat_t	*mmustatp;
	tstat_pgszdata_t	*tstatp = (tstat_pgszdata_t *)buf;
	int	i;

	if (cpu_tstat_va == NULL)
		return;

	mmustatp = &((niagara_mmustat_t *)cpu_tstat_va)[CPU->cpu_id+1];
	if (tstat_pgszs > NIAGARA_MMUSTAT_PGSZS)
		tstat_pgszs = NIAGARA_MMUSTAT_PGSZS;

	for (i = 0; i < tstat_pgszs; i++, tstatp++) {
		tstatp->tpgsz_kernel.tmode_itlb.ttlb_tlb.tmiss_count =
		    mmustatp->kitsb[i].tsbhit_count;
		tstatp->tpgsz_kernel.tmode_itlb.ttlb_tlb.tmiss_time =
		    mmustatp->kitsb[i].tsbhit_time;
		tstatp->tpgsz_user.tmode_itlb.ttlb_tlb.tmiss_count =
		    mmustatp->uitsb[i].tsbhit_count;
		tstatp->tpgsz_user.tmode_itlb.ttlb_tlb.tmiss_time =
		    mmustatp->uitsb[i].tsbhit_time;
		tstatp->tpgsz_kernel.tmode_dtlb.ttlb_tlb.tmiss_count =
		    mmustatp->kdtsb[i].tsbhit_count;
		tstatp->tpgsz_kernel.tmode_dtlb.ttlb_tlb.tmiss_time =
		    mmustatp->kdtsb[i].tsbhit_time;
		tstatp->tpgsz_user.tmode_dtlb.ttlb_tlb.tmiss_count =
		    mmustatp->udtsb[i].tsbhit_count;
		tstatp->tpgsz_user.tmode_dtlb.ttlb_tlb.tmiss_time =
		    mmustatp->udtsb[i].tsbhit_time;
	}
}
