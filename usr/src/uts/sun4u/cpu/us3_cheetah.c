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
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/archsystm.h>
#include <sys/vmsystm.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/machthread.h>
#include <sys/cpu.h>
#include <sys/cmp.h>
#include <sys/elf_SPARC.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kmem.h>
#include <sys/cpuvar.h>
#include <sys/cheetahregs.h>
#include <sys/us3_module.h>
#include <sys/async.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/dditypes.h>
#include <sys/prom_debug.h>
#include <sys/prom_plat.h>
#include <sys/cpu_module.h>
#include <sys/sysmacros.h>
#include <sys/intreg.h>
#include <sys/clock.h>
#include <sys/platform_module.h>
#include <sys/machtrap.h>
#include <sys/ontrap.h>
#include <sys/panic.h>
#include <sys/memlist.h>
#include <sys/bootconf.h>
#include <sys/ivintr.h>
#include <sys/atomic.h>
#include <sys/fm/protocol.h>
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <vm/vm_dep.h>

#ifdef	CHEETAHPLUS_ERRATUM_25
#include <sys/cyclic.h>
#endif	/* CHEETAHPLUS_ERRATUM_25 */

/*
 * Note that 'Cheetah PRM' refers to:
 *   SPARC V9 JPS1 Implementation Supplement: Sun UltraSPARC-III
 */

/*
 * Setup trap handlers.
 */
void
cpu_init_trap(void)
{
	CH_SET_TRAP(pil15_epilogue, ch_pil15_interrupt_instr);

	CH_SET_TRAP(tt0_fecc, fecc_err_instr);
	CH_SET_TRAP(tt1_fecc, fecc_err_tl1_instr);
	CH_SET_TRAP(tt1_swtrap0, fecc_err_tl1_cont_instr);
}

static int
getintprop(pnode_t node, char *name, int deflt)
{
	int	value;

	switch (prom_getproplen(node, name)) {
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
 * Set the magic constants of the implementation.
 */
/*ARGSUSED*/
void
cpu_fiximp(pnode_t dnode)
{
	int i, a;

	static struct {
		char	*name;
		int	*var;
		int	defval;
	} prop[] = {
		"dcache-size", &dcache_size, CH_DCACHE_SIZE,
		"dcache-line-size", &dcache_linesize, CH_DCACHE_LSIZE,
		"icache-size", &icache_size, CH_ICACHE_SIZE,
		"icache-line-size", &icache_linesize, CH_ICACHE_LSIZE,
		"ecache-size", &ecache_size, CH_ECACHE_MAX_SIZE,
		"ecache-line-size", &ecache_alignsize, CH_ECACHE_MAX_LSIZE,
		"ecache-associativity", &ecache_associativity, CH_ECACHE_NWAY
	};

	for (i = 0; i < sizeof (prop) / sizeof (prop[0]); i++)
		*prop[i].var = getintprop(dnode, prop[i].name, prop[i].defval);

	ecache_setsize = ecache_size / ecache_associativity;

	vac_size = CH_VAC_SIZE;
	vac_mask = MMU_PAGEMASK & (vac_size - 1);
	i = 0; a = vac_size;
	while (a >>= 1)
		++i;
	vac_shift = i;
	shm_alignment = vac_size;
	vac = 1;

	/*
	 * Cheetah's large page support has problems with large numbers of
	 * large pages, so just disable large pages out-of-the-box.
	 * Note that the other defaults are set in sun4u/vm/mach_vm_dep.c.
	 */
	max_uheap_lpsize = MMU_PAGESIZE;
	max_ustack_lpsize = MMU_PAGESIZE;
	max_privmap_lpsize = MMU_PAGESIZE;
	max_utext_lpsize = MMU_PAGESIZE;
	max_shm_lpsize = MMU_PAGESIZE;
	max_bootlp_tteszc = TTE8K;
}

void
send_mondo_set(cpuset_t set)
{
	int lo, busy, nack, shipped = 0;
	uint16_t i, cpuids[IDSR_BN_SETS];
	uint64_t idsr, nackmask = 0, busymask, curnack, curbusy;
	uint64_t starttick, endtick, tick, lasttick;
#if (NCPU > IDSR_BN_SETS)
	int index = 0;
	int ncpuids = 0;
#endif
#ifdef	CHEETAHPLUS_ERRATUM_25
	int recovered = 0;
	int cpuid;
#endif

	ASSERT(!CPUSET_ISNULL(set));
	starttick = lasttick = gettick();

#if (NCPU <= IDSR_BN_SETS)
	for (i = 0; i < NCPU; i++)
		if (CPU_IN_SET(set, i)) {
			shipit(i, shipped);
			nackmask |= IDSR_NACK_BIT(shipped);
			cpuids[shipped++] = i;
			CPUSET_DEL(set, i);
			if (CPUSET_ISNULL(set))
				break;
		}
	CPU_STATS_ADDQ(CPU, sys, xcalls, shipped);
#else
	for (i = 0; i < NCPU; i++)
		if (CPU_IN_SET(set, i)) {
			ncpuids++;

			/*
			 * Ship only to the first (IDSR_BN_SETS) CPUs.  If we
			 * find we have shipped to more than (IDSR_BN_SETS)
			 * CPUs, set "index" to the highest numbered CPU in
			 * the set so we can ship to other CPUs a bit later on.
			 */
			if (shipped < IDSR_BN_SETS) {
				shipit(i, shipped);
				nackmask |= IDSR_NACK_BIT(shipped);
				cpuids[shipped++] = i;
				CPUSET_DEL(set, i);
				if (CPUSET_ISNULL(set))
					break;
			} else
				index = (int)i;
		}

	CPU_STATS_ADDQ(CPU, sys, xcalls, ncpuids);
#endif

	busymask = IDSR_NACK_TO_BUSY(nackmask);
	busy = nack = 0;
	endtick = starttick + xc_tick_limit;
	for (;;) {
		idsr = getidsr();
#if (NCPU <= IDSR_BN_SETS)
		if (idsr == 0)
			break;
#else
		if (idsr == 0 && shipped == ncpuids)
			break;
#endif
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
#ifdef	CHEETAHPLUS_ERRATUM_25
			cpuid = -1;
			for (i = 0; i < IDSR_BN_SETS; i++) {
				if (idsr & (IDSR_NACK_BIT(i) |
				    IDSR_BUSY_BIT(i))) {
					cpuid = cpuids[i];
					break;
				}
			}
			if (cheetah_sendmondo_recover && cpuid != -1 &&
			    recovered == 0) {
				if (mondo_recover(cpuid, i)) {
					/*
					 * We claimed the whole memory or
					 * full scan is disabled.
					 */
					recovered++;
				}
				tick = gettick();
				endtick = tick + xc_tick_limit;
				lasttick = tick;
				/*
				 * Recheck idsr
				 */
				continue;
			} else
#endif	/* CHEETAHPLUS_ERRATUM_25 */
			{
				cmn_err(CE_CONT, "send mondo timeout "
				    "[%d NACK %d BUSY]\nIDSR 0x%"
				    "" PRIx64 "  cpuids:", nack, busy, idsr);
				for (i = 0; i < IDSR_BN_SETS; i++) {
					if (idsr & (IDSR_NACK_BIT(i) |
					    IDSR_BUSY_BIT(i))) {
						cmn_err(CE_CONT, " 0x%x",
						    cpuids[i]);
					}
				}
				cmn_err(CE_CONT, "\n");
				cmn_err(CE_PANIC, "send_mondo_set: timeout");
			}
		}
		curnack = idsr & nackmask;
		curbusy = idsr & busymask;
#if (NCPU > IDSR_BN_SETS)
		if (shipped < ncpuids) {
			uint64_t cpus_left;
			uint16_t next = (uint16_t)index;

			cpus_left = ~(IDSR_NACK_TO_BUSY(curnack) | curbusy) &
			    busymask;

			if (cpus_left) {
				do {
					/*
					 * Sequence through and ship to the
					 * remainder of the CPUs in the system
					 * (e.g. other than the first
					 * (IDSR_BN_SETS)) in reverse order.
					 */
					lo = lowbit(cpus_left) - 1;
					i = IDSR_BUSY_IDX(lo);
					shipit(next, i);
					shipped++;
					cpuids[i] = next;

					/*
					 * If we've processed all the CPUs,
					 * exit the loop now and save
					 * instructions.
					 */
					if (shipped == ncpuids)
						break;

					for ((index = ((int)next - 1));
					    index >= 0; index--)
						if (CPU_IN_SET(set, index)) {
							next = (uint16_t)index;
							break;
						}

					cpus_left &= ~(1ull << lo);
				} while (cpus_left);
#ifdef	CHEETAHPLUS_ERRATUM_25
				/*
				 * Clear recovered because we are sending to
				 * a new set of targets.
				 */
				recovered = 0;
#endif
				continue;
			}
		}
#endif
		if (curbusy) {
			busy++;
			continue;
		}

#ifdef SEND_MONDO_STATS
		{
			int n = gettick() - starttick;
			if (n < 8192)
				x_nack_stimes[n >> 7]++;
		}
#endif
		while (gettick() < (tick + sys_clock_mhz))
			;
		do {
			lo = lowbit(curnack) - 1;
			i = IDSR_NACK_IDX(lo);
			shipit(cpuids[i], i);
			curnack &= ~(1ull << lo);
		} while (curnack);
		nack++;
		busy = 0;
	}
#ifdef SEND_MONDO_STATS
	{
		int n = gettick() - starttick;
		if (n < 8192)
			x_set_stimes[n >> 7]++;
		else
			x_set_ltimes[(n >> 13) & 0xf]++;
	}
	x_set_cpus[shipped]++;
#endif
}

/*
 * Handles error logging for implementation specific error types.
 */
/*ARGSUSED*/
int
cpu_impl_async_log_err(void *flt, errorq_elem_t *eqep)
{
	/* There aren't any error types which are specific to cheetah only */
	return (CH_ASYNC_LOG_UNKNOWN);
}

/*
 * Figure out if Ecache is direct-mapped (Cheetah or Cheetah+ with Ecache
 * control ECCR_ASSOC bit off or 2-way (Cheetah+ with ECCR_ASSOC on).
 * We need to do this on the fly because we may have mixed Cheetah+'s with
 * both direct and 2-way Ecaches.
 */
int
cpu_ecache_nway(void)
{
	return (CH_ECACHE_NWAY);
}

/*
 * Note that these are entered into the table: Fatal Errors (PERR, IERR,
 * ISAP, EMU) first, orphaned UCU/UCC, AFAR Overwrite policy, finally IVU, IVC.
 * Afar overwrite policy is:
 *   UCU,UCC > UE,EDU,WDU,CPU > CE,EDC,EMC,WDC,CPC > TO,BERR
 */
ecc_type_to_info_t ecc_type_to_info[] = {

	/* Fatal Errors */
	C_AFSR_PERR,	"PERR ",	ECC_ALL_TRAPS,	CPU_FATAL,
		"PERR Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM2,
		FM_EREPORT_CPU_USIII_PERR,
	C_AFSR_IERR,	"IERR ", 	ECC_ALL_TRAPS,	CPU_FATAL,
		"IERR Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM2,
		FM_EREPORT_CPU_USIII_IERR,
	C_AFSR_ISAP,	"ISAP ",	ECC_ALL_TRAPS,	CPU_FATAL,
		"ISAP Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_ISAP,
	C_AFSR_EMU,	"EMU ",		ECC_ASYNC_TRAPS, CPU_FATAL,
		"EMU Fatal",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_EMU,

	/* Orphaned UCC/UCU Errors */
	C_AFSR_UCU,	"OUCU ",	ECC_ORPH_TRAPS, CPU_ORPH,
		"Orphaned UCU",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_UCU,
	C_AFSR_UCC,	"OUCC ",	ECC_ORPH_TRAPS, CPU_ORPH,
		"Orphaned UCC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_UCC,

	/* UCU, UCC */
	C_AFSR_UCU,	"UCU ",		ECC_F_TRAP,	CPU_UE_ECACHE,
		"UCU",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_UCU,
	C_AFSR_UCC,	"UCC ",		ECC_F_TRAP,	CPU_CE_ECACHE,
		"UCC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_UCC,

	/* UE, EDU:ST, EDU:BLD, WDU, CPU */
	C_AFSR_UE,	"UE ",		ECC_ASYNC_TRAPS, CPU_UE,
		"Uncorrectable system bus (UE)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_UE,
	C_AFSR_EDU,	"EDU ",		ECC_C_TRAP,	CPU_UE_ECACHE_RETIRE,
		"EDU:ST",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_EDUST,
	C_AFSR_EDU,	"EDU ",		ECC_D_TRAP,	CPU_UE_ECACHE_RETIRE,
		"EDU:BLD",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_EDUBL,
	C_AFSR_WDU,	"WDU ",		ECC_C_TRAP,	CPU_UE_ECACHE_RETIRE,
		"WDU",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_WDU,
	C_AFSR_CPU,	"CPU ",		ECC_C_TRAP,	CPU_UE_ECACHE,
		"CPU",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_CPU,

	/* CE, EDC, EMC, WDC, CPC */
	C_AFSR_CE,	"CE ",		ECC_C_TRAP,	CPU_CE,
		"Corrected system bus (CE)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_CE,
	C_AFSR_EDC,	"EDC ",		ECC_C_TRAP,	CPU_CE_ECACHE,
		"EDC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_EDC,
	C_AFSR_EMC,	"EMC ",		ECC_C_TRAP,	CPU_EMC,
		"EMC",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_EMC,
	C_AFSR_WDC,	"WDC ",		ECC_C_TRAP,	CPU_CE_ECACHE,
		"WDC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_WDC,
	C_AFSR_CPC,	"CPC ",		ECC_C_TRAP,	CPU_CE_ECACHE,
		"CPC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_CPC,

	/* TO, BERR */
	C_AFSR_TO,	"TO ",		ECC_ASYNC_TRAPS, CPU_TO,
		"Timeout (TO)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_TO,
	C_AFSR_BERR,	"BERR ",	ECC_ASYNC_TRAPS, CPU_BERR,
		"Bus Error (BERR)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_BERR,

	/* IVU, IVC */
	C_AFSR_IVU,	"IVU ",		ECC_C_TRAP,	CPU_IV,
		"IVU",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_IVU,
	C_AFSR_IVC,	"IVC ",		ECC_C_TRAP,	CPU_IV,
		"IVC",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_IVC,

	0,		NULL,		0,		0,
		NULL,
		FM_EREPORT_PAYLOAD_UNKNOWN,
		FM_EREPORT_CPU_USIII_UNKNOWN,
};

/*
 * Prioritized list of Error bits for AFAR overwrite.
 * See Cheetah PRM P.6.1
 *   Class 4:  UCC, UCU
 *   Class 3:  UE, EDU, EMU, WDU, CPU
 *   Class 2:  CE, EDC, EMC, WDC, CPC
 *   Class 1:  TO, BERR
 */
uint64_t afar_overwrite[] = {
	C_AFSR_UCC | C_AFSR_UCU,
	C_AFSR_UE | C_AFSR_EDU | C_AFSR_EMU | C_AFSR_WDU | C_AFSR_CPU,
	C_AFSR_CE | C_AFSR_EDC | C_AFSR_EMC | C_AFSR_WDC | C_AFSR_CPC,
	C_AFSR_TO | C_AFSR_BERR,
	0
};

/*
 * Prioritized list of Error bits for ESYND overwrite.
 * See Cheetah PRM P.6.2
 *   Class 2:  UE, IVU, EDU, WDU, UCU, CPU
 *   Class 1:  CE, IVC, EDC, WDC, UCC, CPC
 */
uint64_t esynd_overwrite[] = {
	C_AFSR_UE | C_AFSR_IVU | C_AFSR_EDU | C_AFSR_WDU | C_AFSR_UCU |
	    C_AFSR_CPU,
	C_AFSR_CE | C_AFSR_IVC | C_AFSR_EDC | C_AFSR_WDC | C_AFSR_UCC |
	    C_AFSR_CPC,
	0
};

/*
 * Prioritized list of Error bits for MSYND overwrite.
 * See Cheetah PRM P.6.3
 *   Class 2:  EMU
 *   Class 1:  EMC
 */
uint64_t msynd_overwrite[] = {
	C_AFSR_EMU,
	C_AFSR_EMC,
	0
};

/*
 * change cpu speed bits -- new speed will be normal-speed/divisor.
 *
 * The Jalapeno memory controllers are required to drain outstanding
 * memory transactions within 32 JBus clocks in order to be ready
 * to enter Estar mode.  In some corner cases however, that time
 * fell short.
 *
 * A safe software solution is to force MCU to act like in Estar mode,
 * then delay 1us (in ppm code) prior to assert J_CHNG_L signal.
 * To reverse the effect, upon exiting Estar, software restores the
 * MCU to its original state.
 */
/* ARGSUSED1 */
void
cpu_change_speed(uint64_t divisor, uint64_t arg2)
{
	bus_config_eclk_t	*bceclk;
	uint64_t		reg;
	processor_info_t	*pi = &(CPU->cpu_type_info);

	for (bceclk = bus_config_eclk; bceclk->divisor; bceclk++) {
		if (bceclk->divisor != divisor)
			continue;
		reg = get_safari_config();
		reg &= ~SAFARI_CONFIG_ECLK_MASK;
		reg |= bceclk->mask;
		set_safari_config(reg);
		CPU->cpu_m.divisor = (uchar_t)divisor;
		cpu_set_curr_clock(((uint64_t)pi->pi_clock * 1000000) /
		    divisor);
		return;
	}
	/*
	 * We will reach here only if OBP and kernel don't agree on
	 * the speeds supported by the CPU.
	 */
	cmn_err(CE_WARN, "cpu_change_speed: bad divisor %" PRIu64, divisor);
}

/*
 * Cpu private initialization.  This includes allocating the cpu_private
 * data structure, initializing it, and initializing the scrubber for this
 * cpu.  This function calls cpu_init_ecache_scrub_dr to init the scrubber.
 * We use kmem_cache_create for the cheetah private data structure because
 * it needs to be allocated on a PAGESIZE (8192) byte boundary.
 */
void
cpu_init_private(struct cpu *cp)
{
	cheetah_private_t *chprp;
	int i;

	ASSERT(CPU_PRIVATE(cp) == NULL);

	/* LINTED: E_TRUE_LOGICAL_EXPR */
	ASSERT((offsetof(cheetah_private_t, chpr_tl1_err_data) +
	    sizeof (ch_err_tl1_data_t) * CH_ERR_TL1_TLMAX) <= PAGESIZE);

	/*
	 * Running with a Cheetah+, Jaguar, or Panther on a Cheetah CPU
	 * machine is not a supported configuration. Attempting to do so
	 * may result in unpredictable failures (e.g. running Cheetah+
	 * CPUs with Cheetah E$ disp flush) so don't allow it.
	 *
	 * This is just defensive code since this configuration mismatch
	 * should have been caught prior to OS execution.
	 */
	if (!IS_CHEETAH(cpunodes[cp->cpu_id].implementation)) {
		cmn_err(CE_PANIC, "CPU%d: UltraSPARC-III+/IV/IV+ not"
		    " supported on UltraSPARC-III code\n", cp->cpu_id);
	}

	/*
	 * If the ch_private_cache has not been created, create it.
	 */
	if (ch_private_cache == NULL) {
		ch_private_cache = kmem_cache_create("ch_private_cache",
		    sizeof (cheetah_private_t), PAGESIZE, NULL, NULL,
		    NULL, NULL, static_arena, 0);
	}

	chprp = CPU_PRIVATE(cp) = kmem_cache_alloc(ch_private_cache, KM_SLEEP);

	bzero(chprp, sizeof (cheetah_private_t));
	chprp->chpr_fecctl0_logout.clo_data.chd_afar = LOGOUT_INVALID;
	chprp->chpr_cecc_logout.clo_data.chd_afar = LOGOUT_INVALID;
	chprp->chpr_async_logout.clo_data.chd_afar = LOGOUT_INVALID;
	for (i = 0; i < CH_ERR_TL1_TLMAX; i++)
		chprp->chpr_tl1_err_data[i].ch_err_tl1_logout.clo_data.chd_afar
		    = LOGOUT_INVALID;

	chprp->chpr_icache_size = CH_ICACHE_SIZE;
	chprp->chpr_icache_linesize = CH_ICACHE_LSIZE;

	cpu_init_ecache_scrub_dr(cp);

	chprp->chpr_ec_set_size = cpunodes[cp->cpu_id].ecache_size /
	    cpu_ecache_nway();

	adjust_hw_copy_limits(cpunodes[cp->cpu_id].ecache_size);
	ch_err_tl1_paddrs[cp->cpu_id] = va_to_pa(chprp);
	ASSERT(ch_err_tl1_paddrs[cp->cpu_id] != -1);
}

/*
 * Clear the error state registers for this CPU.
 * For Cheetah, just clear the AFSR
 */
void
set_cpu_error_state(ch_cpu_errors_t *cpu_error_regs)
{
	set_asyncflt(cpu_error_regs->afsr & ~C_AFSR_FATAL_ERRS);
}

/*
 * For Cheetah, the error recovery code uses an alternate flush area in the
 * TL>0 fast ECC handler.  ecache_tl1_flushaddr is the physical address of
 * this exclusive displacement flush area.
 */
uint64_t ecache_tl1_flushaddr = (uint64_t)-1; /* physaddr for E$ flushing */

/*
 * Allocate and initialize the exclusive displacement flush area.
 */
caddr_t
ecache_init_scrub_flush_area(caddr_t alloc_base)
{
	unsigned size = 2 * CH_ECACHE_8M_SIZE;
	caddr_t tmp_alloc_base = alloc_base;
	caddr_t flush_alloc_base =
	    (caddr_t)roundup((uintptr_t)alloc_base, size);
	caddr_t ecache_tl1_virtaddr;

	/*
	 * Allocate the physical memory for the exclusive flush area
	 *
	 * Need to allocate an exclusive flush area that is twice the
	 * largest supported E$ size, physically contiguous, and
	 * aligned on twice the largest E$ size boundary.
	 *
	 * Memory allocated via prom_alloc is included in the "cage"
	 * from the DR perspective and due to this, its physical
	 * address will never change and the memory will not be
	 * removed.
	 *
	 * prom_alloc takes 3 arguments: bootops, virtual address hint,
	 * size of the area to allocate, and alignment of the area to
	 * allocate. It returns zero if the allocation fails, or the
	 * virtual address for a successful allocation. Memory prom_alloc'd
	 * is physically contiguous.
	 */
	if ((ecache_tl1_virtaddr =
	    prom_alloc(flush_alloc_base, size, size)) != NULL) {

		tmp_alloc_base =
		    (caddr_t)roundup((uintptr_t)(ecache_tl1_virtaddr + size),
		    ecache_alignsize);

		/*
		 * get the physical address of the exclusive flush area
		 */
		ecache_tl1_flushaddr = va_to_pa(ecache_tl1_virtaddr);

	} else {
		ecache_tl1_virtaddr = (caddr_t)-1;
		cmn_err(CE_NOTE, "!ecache_init_scrub_flush_area failed\n");
	}

	return (tmp_alloc_base);
}

/*
 * Update cpu_offline_set so the scrubber knows which cpus are offline
 */
/*ARGSUSED*/
int
cpu_scrub_cpu_setup(cpu_setup_t what, int cpuid, void *arg)
{
	switch (what) {
	case CPU_ON:
	case CPU_INIT:
		CPUSET_DEL(cpu_offline_set, cpuid);
		break;
	case CPU_OFF:
		CPUSET_ADD(cpu_offline_set, cpuid);
		break;
	default:
		break;
	}
	return (0);
}
