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
#include <sys/fm/util.h>
#include <sys/pghw.h>

#ifdef	CHEETAHPLUS_ERRATUM_25
#include <sys/cyclic.h>
#endif	/* CHEETAHPLUS_ERRATUM_25 */

/*
 * See comment above cpu_scrub_cpu_setup() for description
 */
#define	SCRUBBER_NEITHER_CORE_ONLINE	0x0
#define	SCRUBBER_CORE_0_ONLINE		0x1
#define	SCRUBBER_CORE_1_ONLINE		0x2
#define	SCRUBBER_BOTH_CORES_ONLINE	(SCRUBBER_CORE_0_ONLINE | \
					SCRUBBER_CORE_1_ONLINE)

static int pn_matching_valid_l2_line(uint64_t faddr, ch_ec_data_t *clo_l2_data);
static void cpu_async_log_tlb_parity_err(void *flt);
static cpu_t *cpu_get_sibling_core(cpu_t *cpup);


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

	CH_SET_TRAP(tt0_dperr, dcache_parity_instr);
	CH_SET_TRAP(tt1_dperr, dcache_parity_tl1_instr);
	CH_SET_TRAP(tt1_swtrap1, dcache_parity_tl1_cont_instr);

	CH_SET_TRAP(tt0_iperr, icache_parity_instr);
	CH_SET_TRAP(tt1_iperr, icache_parity_tl1_instr);
	CH_SET_TRAP(tt1_swtrap2, icache_parity_tl1_cont_instr);
}

/*
 * Set the magic constants of the implementation.
 */
/*ARGSUSED*/
void
cpu_fiximp(pnode_t dnode)
{
	int i, a;
	extern int vac_size, vac_shift;
	extern uint_t vac_mask;

	dcache_size = CH_DCACHE_SIZE;
	dcache_linesize = CH_DCACHE_LSIZE;

	icache_size = CHP_ICACHE_MAX_SIZE;
	icache_linesize = CHP_ICACHE_MIN_LSIZE;

	ecache_size = CH_ECACHE_MAX_SIZE;
	ecache_alignsize = CH_ECACHE_MAX_LSIZE;
	ecache_associativity = CHP_ECACHE_MIN_NWAY;

	/*
	 * ecache_setsize needs to maximum of all cpu ecache setsizes
	 */
	ecache_setsize = CHP_ECACHE_MAX_SETSIZE;
	ASSERT(ecache_setsize >= (ecache_size / ecache_associativity));

	vac_size = CH_VAC_SIZE;
	vac_mask = MMU_PAGEMASK & (vac_size - 1);
	i = 0; a = vac_size;
	while (a >>= 1)
		++i;
	vac_shift = i;
	shm_alignment = vac_size;
	vac = 1;
}

/*
 * Use Panther values for Panther-only domains.
 * See Panther PRM, 1.5.4 Cache Hierarchy
 */
void
cpu_fix_allpanther(void)
{
	/* dcache same as Ch+ */
	icache_size = PN_ICACHE_SIZE;
	icache_linesize = PN_ICACHE_LSIZE;
	ecache_size = PN_L3_SIZE;
	ecache_alignsize = PN_L3_LINESIZE;
	ecache_associativity = PN_L3_NWAYS;
	ecache_setsize = PN_L3_SET_SIZE;
	ASSERT(ecache_setsize >= (ecache_size / ecache_associativity));
	/* vac same as Ch+ */
	/* fix hwcaps for USIV+-only domains */
	cpu_hwcap_flags |= AV_SPARC_POPC;
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
 * Handles error logging for implementation specific error types
 */
/*ARGSUSED1*/
int
cpu_impl_async_log_err(void *flt, errorq_elem_t *eqep)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)flt;
	struct async_flt *aflt = (struct async_flt *)flt;

	switch (ch_flt->flt_type) {

	case CPU_IC_PARITY:
		cpu_async_log_ic_parity_err(flt);
		return (CH_ASYNC_LOG_DONE);

	case CPU_DC_PARITY:
		cpu_async_log_dc_parity_err(flt);
		return (CH_ASYNC_LOG_DONE);

	case CPU_DUE:
		cpu_log_err(aflt);
		cpu_page_retire(ch_flt);
		return (CH_ASYNC_LOG_DONE);

	case CPU_ITLB_PARITY:
	case CPU_DTLB_PARITY:
		cpu_async_log_tlb_parity_err(flt);
		return (CH_ASYNC_LOG_DONE);

	/* report the error and continue */
	case CPU_L3_ADDR_PE:
		cpu_log_err(aflt);
		return (CH_ASYNC_LOG_DONE);

	default:
		return (CH_ASYNC_LOG_UNKNOWN);
	}
}

/*
 * Figure out if Ecache is direct-mapped (Cheetah or Cheetah+ with Ecache
 * control ECCR_ASSOC bit off or 2-way (Cheetah+ with ECCR_ASSOC on).
 * We need to do this on the fly because we may have mixed Cheetah+'s with
 * both direct and 2-way Ecaches. Panther only supports 4-way L3$.
 */
int
cpu_ecache_nway(void)
{
	if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation))
		return (PN_L3_NWAYS);
	return ((get_ecache_ctrl() & ECCR_ASSOC) ? 2 : 1);
}

/*
 * Note that these are entered into the table: Fatal Errors (PERR, IERR, ISAP,
 * EMU, IMU) first, orphaned UCU/UCC, AFAR Overwrite policy, finally IVU, IVC.
 * Afar overwrite policy is:
 *   Class 4:
 *      AFSR     -- UCC, UCU, TUE, TSCE, TUE_SH
 *      AFSR_EXT -- L3_UCC, L3_UCU, L3_TUE, L3_TUE_SH
 *   Class 3:
 *      AFSR     -- UE, DUE, EDU, WDU, CPU
 *      AFSR_EXT -- L3_EDU, L3_WDU, L3_CPU
 *   Class 2:
 *      AFSR     -- CE, EDC, EMC, WDC, CPC, THCE
 *      AFSR_EXT -- L3_EDC, L3_WDC, L3_CPC, L3_THCE
 *   Class 1:
 *      AFSR     -- TO, DTO, BERR, DBERR
 */
ecc_type_to_info_t ecc_type_to_info[] = {

	/* Fatal Errors */
	C_AFSR_PERR,		"PERR ",	ECC_ALL_TRAPS,
		CPU_FATAL,	"PERR Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM2,
		FM_EREPORT_CPU_USIII_PERR,
	C_AFSR_IERR,		"IERR ", 	ECC_ALL_TRAPS,
		CPU_FATAL,	"IERR Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM2,
		FM_EREPORT_CPU_USIII_IERR,
	C_AFSR_ISAP,		"ISAP ",	ECC_ALL_TRAPS,
		CPU_FATAL,	"ISAP Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_ISAP,
	C_AFSR_L3_TUE_SH,	"L3_TUE_SH ", 	ECC_C_TRAP,
		CPU_FATAL,	"L3_TUE_SH Fatal",
		FM_EREPORT_PAYLOAD_L3_TAG_ECC,
		FM_EREPORT_CPU_USIII_L3_TUE_SH,
	C_AFSR_L3_TUE,		"L3_TUE ", 	ECC_C_TRAP,
		CPU_FATAL,	"L3_TUE Fatal",
		FM_EREPORT_PAYLOAD_L3_TAG_ECC,
		FM_EREPORT_CPU_USIII_L3_TUE,
	C_AFSR_TUE_SH,		"TUE_SH ", 	ECC_C_TRAP,
		CPU_FATAL,	"TUE_SH Fatal",
		FM_EREPORT_PAYLOAD_L2_TAG_ECC,
		FM_EREPORT_CPU_USIII_TUE_SH,
	C_AFSR_TUE,		"TUE ", 	ECC_ALL_TRAPS,
		CPU_FATAL,	"TUE Fatal",
		FM_EREPORT_PAYLOAD_L2_TAG_ECC,
		FM_EREPORT_CPU_USIII_TUE,
	C_AFSR_EMU,		"EMU ",		ECC_ASYNC_TRAPS,
		CPU_FATAL,	"EMU Fatal",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_EMU,
	C_AFSR_IMU,		"IMU ",		ECC_C_TRAP,
		CPU_FATAL,	"IMU Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_IMU,

	/* L3$ Address parity errors are reported via the MECC bit */
	C_AFSR_L3_MECC,		"L3_MECC ",	ECC_MECC_TRAPS,
		CPU_L3_ADDR_PE,	"L3 Address Parity",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_MECC,

	/* Orphaned UCC/UCU Errors */
	C_AFSR_L3_UCU,		"L3_OUCU ",	ECC_ORPH_TRAPS,
		CPU_ORPH,	"Orphaned L3_UCU",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_UCU,
	C_AFSR_L3_UCC,		"L3_OUCC ",	ECC_ORPH_TRAPS,
		CPU_ORPH,	"Orphaned L3_UCC",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_UCC,
	C_AFSR_UCU,		"OUCU ",	ECC_ORPH_TRAPS,
		CPU_ORPH,	"Orphaned UCU",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_UCU,
	C_AFSR_UCC,		"OUCC ",	ECC_ORPH_TRAPS,
		CPU_ORPH,	"Orphaned UCC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_UCC,

	/* UCU, UCC */
	C_AFSR_L3_UCU,		"L3_UCU ",	ECC_F_TRAP,
		CPU_UE_ECACHE,	"L3_UCU",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_UCU,
	C_AFSR_L3_UCC,		"L3_UCC ",	ECC_F_TRAP,
		CPU_CE_ECACHE,	"L3_UCC",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_UCC,
	C_AFSR_UCU,		"UCU ",		ECC_F_TRAP,
		CPU_UE_ECACHE,	"UCU",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_UCU,
	C_AFSR_UCC,		"UCC ",		ECC_F_TRAP,
		CPU_CE_ECACHE,	"UCC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_UCC,
	C_AFSR_TSCE,		"TSCE ",	ECC_F_TRAP,
		CPU_CE_ECACHE,	"TSCE",
		FM_EREPORT_PAYLOAD_L2_TAG_ECC,
		FM_EREPORT_CPU_USIII_TSCE,

	/* UE, EDU:ST, EDU:BLD, WDU, CPU */
	C_AFSR_UE,		"UE ",		ECC_ASYNC_TRAPS,
		CPU_UE,		"Uncorrectable system bus (UE)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_UE,
	C_AFSR_L3_EDU,		"L3_EDU ",	ECC_C_TRAP,
		CPU_UE_ECACHE_RETIRE,	"L3_EDU:ST",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_EDUST,
	C_AFSR_L3_EDU,		"L3_EDU ",	ECC_D_TRAP,
		CPU_UE_ECACHE_RETIRE,	"L3_EDU:BLD",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_EDUBL,
	C_AFSR_L3_WDU,		"L3_WDU ",	ECC_C_TRAP,
		CPU_UE_ECACHE_RETIRE,	"L3_WDU",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_WDU,
	C_AFSR_L3_CPU,		"L3_CPU ",	ECC_C_TRAP,
		CPU_UE_ECACHE,	"L3_CPU",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_CPU,
	C_AFSR_EDU,		"EDU ",		ECC_C_TRAP,
		CPU_UE_ECACHE_RETIRE,	"EDU:ST",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_EDUST,
	C_AFSR_EDU,		"EDU ",		ECC_D_TRAP,
		CPU_UE_ECACHE_RETIRE,	"EDU:BLD",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_EDUBL,
	C_AFSR_WDU,		"WDU ",		ECC_C_TRAP,
		CPU_UE_ECACHE_RETIRE,	"WDU",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_WDU,
	C_AFSR_CPU,		"CPU ",		ECC_C_TRAP,
		CPU_UE_ECACHE,	"CPU",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_CPU,
	C_AFSR_DUE,		"DUE ",		ECC_C_TRAP,
		CPU_DUE,	"DUE",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_DUE,

	/* CE, EDC, EMC, WDC, CPC */
	C_AFSR_CE,		"CE ",		ECC_C_TRAP,
		CPU_CE,		"Corrected system bus (CE)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_CE,
	C_AFSR_L3_EDC,		"L3_EDC ",	ECC_C_TRAP,
		CPU_CE_ECACHE,	"L3_EDC",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_EDC,
	C_AFSR_EDC,		"EDC ",		ECC_C_TRAP,
		CPU_CE_ECACHE,	"EDC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_EDC,
	C_AFSR_EMC,		"EMC ",		ECC_C_TRAP,
		CPU_EMC,	"EMC",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_EMC,
	C_AFSR_L3_WDC,		"L3_WDC ",	ECC_C_TRAP,
		CPU_CE_ECACHE,	"L3_WDC",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_WDC,
	C_AFSR_L3_CPC,		"L3_CPC ",	ECC_C_TRAP,
		CPU_CE_ECACHE,	"L3_CPC",
		FM_EREPORT_PAYLOAD_L3_DATA,
		FM_EREPORT_CPU_USIII_L3_CPC,
	C_AFSR_L3_THCE,		"L3_THCE ",	ECC_C_TRAP,
		CPU_CE_ECACHE,	"L3_THCE",
		FM_EREPORT_PAYLOAD_L3_TAG_ECC,
		FM_EREPORT_CPU_USIII_L3_THCE,
	C_AFSR_WDC,		"WDC ",		ECC_C_TRAP,
		CPU_CE_ECACHE,	"WDC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_WDC,
	C_AFSR_CPC,		"CPC ",		ECC_C_TRAP,
		CPU_CE_ECACHE,	"CPC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_CPC,
	C_AFSR_THCE,		"THCE ",	ECC_C_TRAP,
		CPU_CE_ECACHE,	"THCE",
		FM_EREPORT_PAYLOAD_L2_TAG_ECC,
		FM_EREPORT_CPU_USIII_THCE,

	/* TO, BERR */
	C_AFSR_TO,		"TO ",		ECC_ASYNC_TRAPS,
		CPU_TO,		"Timeout (TO)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_TO,
	C_AFSR_BERR,		"BERR ",	ECC_ASYNC_TRAPS,
		CPU_BERR,	"Bus Error (BERR)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_BERR,
	C_AFSR_DTO,		"DTO ",		ECC_C_TRAP,
		CPU_TO,		"Disrupting Timeout (DTO)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_DTO,
	C_AFSR_DBERR,		"DBERR ",	ECC_C_TRAP,
		CPU_BERR,	"Disrupting Bus Error (DBERR)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_DBERR,

	/* IVU, IVC, IMC */
	C_AFSR_IVU,		"IVU ",		ECC_C_TRAP,
		CPU_IV,		"IVU",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_IVU,
	C_AFSR_IVC,		"IVC ",		ECC_C_TRAP,
		CPU_IV,		"IVC",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_IVC,
	C_AFSR_IMC,		"IMC ",		ECC_C_TRAP,
		CPU_IV,		"IMC",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_IMC,

	0,			NULL,		0,
		0,		NULL,
		FM_EREPORT_PAYLOAD_UNKNOWN,
		FM_EREPORT_CPU_USIII_UNKNOWN,
};

/*
 * See Cheetah+ Delta PRM 10.9 and section P.6.1 of the Panther PRM
 *   Class 4:
 *      AFSR     -- UCC, UCU, TUE, TSCE, TUE_SH
 *      AFSR_EXT -- L3_UCC, L3_UCU, L3_TUE, L3_TUE_SH
 *   Class 3:
 *      AFSR     -- UE, DUE, EDU, EMU, WDU, CPU
 *      AFSR_EXT -- L3_EDU, L3_WDU, L3_CPU
 *   Class 2:
 *      AFSR     -- CE, EDC, EMC, WDC, CPC, THCE
 *      AFSR_EXT -- L3_EDC, L3_WDC, L3_CPC, L3_THCE
 *   Class 1:
 *      AFSR     -- TO, DTO, BERR, DBERR
 *      AFSR_EXT --
 */
uint64_t afar_overwrite[] = {
	/* class 4: */
	C_AFSR_UCC | C_AFSR_UCU | C_AFSR_TUE | C_AFSR_TSCE | C_AFSR_TUE_SH |
	C_AFSR_L3_UCC | C_AFSR_L3_UCU | C_AFSR_L3_TUE | C_AFSR_L3_TUE_SH,
	/* class 3: */
	C_AFSR_UE | C_AFSR_DUE | C_AFSR_EDU | C_AFSR_EMU | C_AFSR_WDU |
	C_AFSR_CPU | C_AFSR_L3_EDU | C_AFSR_L3_WDU | C_AFSR_L3_CPU,
	/* class 2: */
	C_AFSR_CE | C_AFSR_EDC | C_AFSR_EMC | C_AFSR_WDC | C_AFSR_CPC |
	C_AFSR_THCE | C_AFSR_L3_EDC | C_AFSR_L3_WDC | C_AFSR_L3_CPC |
	C_AFSR_L3_THCE,
	/* class 1: */
	C_AFSR_TO | C_AFSR_DTO | C_AFSR_BERR | C_AFSR_DBERR,

	0
};

/*
 * For Cheetah+, the E_SYND and M_SYND overwrite priorities are combined.
 * See Cheetah+ Delta PRM 10.9 and Cheetah+ PRM 11.6.2
 *   Class 2:  UE, DUE, IVU, EDU, EMU, WDU, UCU, CPU
 *   Class 1:  CE, IVC, EDC, EMC, WDC, UCC, CPC
 */
uint64_t esynd_overwrite[] = {
	/* class 2: */
	C_AFSR_UE | C_AFSR_DUE | C_AFSR_IVU | C_AFSR_EDU | C_AFSR_EMU |
	    C_AFSR_WDU | C_AFSR_UCU | C_AFSR_CPU,
	/* class 1: */
	C_AFSR_CE | C_AFSR_IVC | C_AFSR_EDC | C_AFSR_EMC | C_AFSR_WDC |
	    C_AFSR_UCC | C_AFSR_CPC,
	0
};

/*
 * In panther, the E_SYND overwrite policy changed a little bit
 * by adding one more level.
 * See Panther PRM P.6.2
 *   class 3:
 *      AFSR     -- UCU, UCC
 *      AFSR_EXT -- L3_UCU, L3_UCC
 *   Class 2:
 *      AFSR     -- UE, DUE, IVU, EDU, WDU, CPU
 *      AFSR_EXT -- L3_EDU, L3_WDU, L3_CPU
 *   Class 1:
 *      AFSR     -- CE, IVC, EDC, WDC, CPC
 *      AFSR_EXT -- L3_EDC, L3_WDC, L3_CPC
 */
uint64_t pn_esynd_overwrite[] = {
	/* class 3: */
	C_AFSR_UCU | C_AFSR_UCC |
	C_AFSR_L3_UCU | C_AFSR_L3_UCC,
	/* class 2: */
	C_AFSR_UE | C_AFSR_DUE | C_AFSR_IVU | C_AFSR_EDU | C_AFSR_WDU |
	    C_AFSR_CPU |
	C_AFSR_L3_EDU | C_AFSR_L3_WDU | C_AFSR_L3_CPU,
	/* class 1: */
	C_AFSR_CE | C_AFSR_IVC | C_AFSR_EDC | C_AFSR_WDC | C_AFSR_CPC |
	C_AFSR_L3_EDC | C_AFSR_L3_WDC | C_AFSR_L3_CPC,

	0
};

int
afsr_to_pn_esynd_status(uint64_t afsr, uint64_t afsr_bit)
{
	return (afsr_to_overw_status(afsr, afsr_bit, pn_esynd_overwrite));
}

/*
 * Prioritized list of Error bits for MSYND overwrite.
 * See Panther PRM P.6.2 (For Cheetah+, see esynd_overwrite classes)
 *   Class 2:  EMU, IMU
 *   Class 1:  EMC, IMC
 *
 * Panther adds IMU and IMC.
 */
uint64_t msynd_overwrite[] = {
	/* class 2: */
	C_AFSR_EMU | C_AFSR_IMU,
	/* class 1: */
	C_AFSR_EMC | C_AFSR_IMC,

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
	 * Running with Cheetah CPUs in a Cheetah+, Jaguar, Panther or
	 * mixed Cheetah+/Jaguar/Panther machine is not a supported
	 * configuration. Attempting to do so may result in unpredictable
	 * failures (e.g. running Cheetah+ CPUs with Cheetah E$ disp flush)
	 * so don't allow it.
	 *
	 * This is just defensive code since this configuration mismatch
	 * should have been caught prior to OS execution.
	 */
	if (!(IS_CHEETAH_PLUS(cpunodes[cp->cpu_id].implementation) ||
	    IS_JAGUAR(cpunodes[cp->cpu_id].implementation) ||
	    IS_PANTHER(cpunodes[cp->cpu_id].implementation))) {
		cmn_err(CE_PANIC, "CPU%d: UltraSPARC-III not supported"
		    " on UltraSPARC-III+/IV/IV+ code\n", cp->cpu_id);
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
	chprp->chpr_tlb_logout.tlo_addr = LOGOUT_INVALID;
	for (i = 0; i < CH_ERR_TL1_TLMAX; i++)
		chprp->chpr_tl1_err_data[i].ch_err_tl1_logout.clo_data.chd_afar
		    = LOGOUT_INVALID;

	/* Panther has a larger Icache compared to cheetahplus or Jaguar */
	if (IS_PANTHER(cpunodes[cp->cpu_id].implementation)) {
		chprp->chpr_icache_size = PN_ICACHE_SIZE;
		chprp->chpr_icache_linesize = PN_ICACHE_LSIZE;
	} else {
		chprp->chpr_icache_size = CH_ICACHE_SIZE;
		chprp->chpr_icache_linesize = CH_ICACHE_LSIZE;
	}

	cpu_init_ecache_scrub_dr(cp);

	/*
	 * Panther's L2$ and E$ are shared between cores, so the scrubber is
	 * only needed on one of the cores.  At this point, we assume all cores
	 * are online, and we only enable the scrubber on core 0.
	 */
	if (IS_PANTHER(cpunodes[cp->cpu_id].implementation)) {
		chprp->chpr_scrub_misc.chsm_core_state =
		    SCRUBBER_BOTH_CORES_ONLINE;
		if (cp->cpu_id != (processorid_t)cmp_cpu_to_chip(cp->cpu_id)) {
			chprp->chpr_scrub_misc.chsm_enable[
			    CACHE_SCRUBBER_INFO_E] = 0;
		}
	}

	chprp->chpr_ec_set_size = cpunodes[cp->cpu_id].ecache_size /
	    cpu_ecache_nway();

	adjust_hw_copy_limits(cpunodes[cp->cpu_id].ecache_size);
	ch_err_tl1_paddrs[cp->cpu_id] = va_to_pa(chprp);
	ASSERT(ch_err_tl1_paddrs[cp->cpu_id] != -1);
}

/*
 * Clear the error state registers for this CPU.
 * For Cheetah+/Jaguar, just clear the AFSR but
 * for Panther we also have to clear the AFSR_EXT.
 */
void
set_cpu_error_state(ch_cpu_errors_t *cpu_error_regs)
{
	set_asyncflt(cpu_error_regs->afsr & ~C_AFSR_FATAL_ERRS);
	if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
		set_afsr_ext(cpu_error_regs->afsr_ext & ~C_AFSR_EXT_FATAL_ERRS);
	}
}

void
pn_cpu_log_diag_l2_info(ch_async_flt_t *ch_flt) {
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	ch_ec_data_t *l2_data = &ch_flt->flt_diag_data.chd_l2_data[0];
	uint64_t faddr = aflt->flt_addr;
	uint8_t log_way_mask = 0;
	int i;

	/*
	 * Only Panther CPUs have the additional L2$ data that needs
	 * to be logged here
	 */
	if (!IS_PANTHER(cpunodes[aflt->flt_inst].implementation))
		return;

	/*
	 * We'll use a simple bit mask to keep track of which way(s)
	 * of the stored cache line we want to log. The idea is to
	 * log the entry if it is a valid line and it matches our
	 * fault AFAR. If no match is found, we will simply log all
	 * the ways.
	 */
	for (i = 0; i < PN_L2_NWAYS; i++)
		if (pn_matching_valid_l2_line(faddr, &l2_data[i]))
			log_way_mask |= (1 << i);

	/* If no matching valid lines were found, we log all ways */
	if (log_way_mask == 0)
		log_way_mask = (1 << PN_L2_NWAYS) - 1;

	/* Log the cache lines */
	for (i = 0; i < PN_L2_NWAYS; i++)
		if (log_way_mask & (1 << i))
			l2_data[i].ec_logflag = EC_LOGFLAG_MAGIC;
}

/*
 * For this routine to return true, the L2 tag in question must be valid
 * and the tag PA must match the fault address (faddr) assuming the correct
 * index is being used.
 */
static int
pn_matching_valid_l2_line(uint64_t faddr, ch_ec_data_t *clo_l2_data) {
	if ((!PN_L2_LINE_INVALID(clo_l2_data->ec_tag)) &&
	((faddr & P2ALIGN(C_AFAR_PA, PN_L2_SET_SIZE)) ==
	    PN_L2TAG_TO_PA(clo_l2_data->ec_tag)))
		return (1);
	return (0);
}

/*
 * This array is used to convert the 3 digit PgSz encoding (as used in
 * various MMU registers such as MMU_TAG_ACCESS_EXT) into the corresponding
 * page size.
 */
static uint64_t tlb_pgsz_to_size[] = {
	/* 000 = 8KB: */
	0x2000,
	/* 001 = 64KB: */
	0x10000,
	/* 010 = 512KB: */
	0x80000,
	/* 011 = 4MB: */
	0x400000,
	/* 100 = 32MB: */
	0x2000000,
	/* 101 = 256MB: */
	0x10000000,
	/* undefined for encodings 110 and 111: */
	0, 0
};

/*
 * The itlb_parity_trap and dtlb_parity_trap handlers transfer control here
 * after collecting logout information related to the TLB parity error and
 * flushing the offending TTE entries from the ITLB or DTLB.
 *
 * DTLB traps which occur at TL>0 are not recoverable because we will most
 * likely be corrupting some other trap handler's alternate globals. As
 * such, we simply panic here when that happens. ITLB parity errors are
 * not expected to happen at TL>0.
 */
void
cpu_tlb_parity_error(struct regs *rp, ulong_t trap_va, ulong_t tlb_info) {
	ch_async_flt_t ch_flt;
	struct async_flt *aflt;
	pn_tlb_logout_t *tlop = NULL;
	int immu_parity = (tlb_info & PN_TLO_INFO_IMMU) != 0;
	int tl1_trap = (tlb_info & PN_TLO_INFO_TL1) != 0;
	char *error_class;

	bzero(&ch_flt, sizeof (ch_async_flt_t));

	/*
	 * Get the CPU log out info. If we can't find our CPU private
	 * pointer, or if the logout information does not correspond to
	 * this error, then we will have to make due without detailed
	 * logout information.
	 */
	if (CPU_PRIVATE(CPU)) {
		tlop = CPU_PRIVATE_PTR(CPU, chpr_tlb_logout);
		if ((tlop->tlo_addr != trap_va) ||
		    (tlop->tlo_info != tlb_info))
			tlop = NULL;
	}

	if (tlop) {
		ch_flt.tlb_diag_data = *tlop;

		/* Zero out + invalidate TLB logout. */
		bzero(tlop, sizeof (pn_tlb_logout_t));
		tlop->tlo_addr = LOGOUT_INVALID;
	} else {
		/*
		 * Copy what logout information we have and mark
		 * it incomplete.
		 */
		ch_flt.flt_data_incomplete = 1;
		ch_flt.tlb_diag_data.tlo_info = tlb_info;
		ch_flt.tlb_diag_data.tlo_addr = trap_va;
	}

	/*
	 * Log the error.
	 */
	aflt = (struct async_flt *)&ch_flt;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_bus_id = getprocessorid();
	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_pc = (caddr_t)rp->r_pc;
	aflt->flt_addr = trap_va;
	aflt->flt_prot = AFLT_PROT_NONE;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_priv = (rp->r_tstate & TSTATE_PRIV) ?  1 : 0;
	aflt->flt_tl = tl1_trap ? 1 : 0;
	aflt->flt_panic = tl1_trap ? 1 : 0;

	if (immu_parity) {
		aflt->flt_status = ECC_ITLB_TRAP;
		ch_flt.flt_type = CPU_ITLB_PARITY;
		error_class = FM_EREPORT_CPU_USIII_ITLBPE;
		aflt->flt_payload = FM_EREPORT_PAYLOAD_ITLB_PE;
	} else {
		aflt->flt_status = ECC_DTLB_TRAP;
		ch_flt.flt_type = CPU_DTLB_PARITY;
		error_class = FM_EREPORT_CPU_USIII_DTLBPE;
		aflt->flt_payload = FM_EREPORT_PAYLOAD_DTLB_PE;
	}

	/*
	 * The TLB entries have already been flushed by the TL1 trap
	 * handler so at this point the only thing left to do is log
	 * the error message.
	 */
	if (aflt->flt_panic) {
		cpu_errorq_dispatch(error_class, (void *)&ch_flt,
		    sizeof (ch_async_flt_t), ue_queue, aflt->flt_panic);
		/*
		 * Panic here if aflt->flt_panic has been set.  Enqueued
		 * errors will be logged as part of the panic flow.
		 */
		fm_panic("%sError(s)", immu_parity ? "ITLBPE " : "DTLBPE ");
	} else {
		cpu_errorq_dispatch(error_class, (void *)&ch_flt,
		    sizeof (ch_async_flt_t), ce_queue, aflt->flt_panic);
	}
}

/*
 * This routine is called when a TLB parity error event is 'ue_drain'ed
 * or 'ce_drain'ed from the errorq.
 */
void
cpu_async_log_tlb_parity_err(void *flt) {
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)flt;
	struct async_flt *aflt = (struct async_flt *)flt;
#ifdef lint
	aflt = aflt;
#endif

	/*
	 * We only capture TLB information if we encountered
	 * a TLB parity error and Panther is the only CPU which
	 * can detect a TLB parity error.
	 */
	ASSERT(IS_PANTHER(cpunodes[aflt->flt_inst].implementation));
	ASSERT((ch_flt->flt_type == CPU_ITLB_PARITY) ||
	    (ch_flt->flt_type == CPU_DTLB_PARITY));

	if (ch_flt->flt_data_incomplete == 0) {
		if (ch_flt->flt_type == CPU_ITLB_PARITY)
			ch_flt->tlb_diag_data.tlo_logflag = IT_LOGFLAG_MAGIC;
		else /* parity error is in DTLB */
			ch_flt->tlb_diag_data.tlo_logflag = DT_LOGFLAG_MAGIC;
	}
}

/*
 * Add L1 Prefetch cache data to the ereport payload.
 */
void
cpu_payload_add_pcache(struct async_flt *aflt, nvlist_t *nvl)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;
	ch_pc_data_t *pcp;
	ch_pc_data_t pcdata[CH_PCACHE_NWAY];
	uint_t nelem;
	int i, ways_logged = 0;

	/*
	 * We only capture P$ information if we encountered
	 * a P$ parity error and Panther is the only CPU which
	 * can detect a P$ parity error.
	 */
	ASSERT(IS_PANTHER(cpunodes[aflt->flt_inst].implementation));
	for (i = 0; i < CH_PCACHE_NWAY; i++) {
		pcp = &ch_flt->parity_data.dpe.cpl_pc[i];
		if (pcp->pc_logflag == PC_LOGFLAG_MAGIC) {
			bcopy(pcp, &pcdata[ways_logged],
			    sizeof (ch_pc_data_t));
			ways_logged++;
		}
	}

	/*
	 * Add the pcache data to the payload.
	 */
	fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L1P_WAYS,
	    DATA_TYPE_UINT8, (uint8_t)ways_logged, NULL);
	if (ways_logged != 0) {
		nelem = sizeof (ch_pc_data_t) / sizeof (uint64_t) * ways_logged;
		fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L1P_DATA,
		    DATA_TYPE_UINT64_ARRAY, nelem, (uint64_t *)pcdata, NULL);
	}
}

/*
 * Add TLB diagnostic data to the ereport payload.
 */
void
cpu_payload_add_tlb(struct async_flt *aflt, nvlist_t *nvl)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;
	uint8_t num_entries, tlb_data_words;

	/*
	 * We only capture TLB information if we encountered
	 * a TLB parity error and Panther is the only CPU which
	 * can detect a TLB parity error.
	 */
	ASSERT(IS_PANTHER(cpunodes[aflt->flt_inst].implementation));
	ASSERT((ch_flt->flt_type == CPU_ITLB_PARITY) ||
	    (ch_flt->flt_type == CPU_DTLB_PARITY));

	if (ch_flt->flt_type == CPU_ITLB_PARITY) {
		num_entries = (uint8_t)(PN_ITLB_NWAYS * PN_NUM_512_ITLBS);
		tlb_data_words = sizeof (ch_tte_entry_t) / sizeof (uint64_t) *
		    num_entries;

		/*
		 * Add the TLB diagnostic data to the payload
		 * if it was collected.
		 */
		if (ch_flt->tlb_diag_data.tlo_logflag == IT_LOGFLAG_MAGIC) {
			fm_payload_set(nvl,
			    FM_EREPORT_PAYLOAD_NAME_ITLB_ENTRIES,
			    DATA_TYPE_UINT8, num_entries, NULL);
			fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_ITLB_DATA,
			    DATA_TYPE_UINT64_ARRAY, tlb_data_words,
			    (uint64_t *)ch_flt->tlb_diag_data.tlo_itlb_tte,
			    NULL);
		}
	} else {
		num_entries = (uint8_t)(PN_DTLB_NWAYS * PN_NUM_512_DTLBS);
		tlb_data_words = sizeof (ch_tte_entry_t) / sizeof (uint64_t) *
		    num_entries;

		fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_VA,
		    DATA_TYPE_UINT64, ch_flt->tlb_diag_data.tlo_addr, NULL);

		/*
		 * Add the TLB diagnostic data to the payload
		 * if it was collected.
		 */
		if (ch_flt->tlb_diag_data.tlo_logflag == DT_LOGFLAG_MAGIC) {
			fm_payload_set(nvl,
			    FM_EREPORT_PAYLOAD_NAME_DTLB_ENTRIES,
			    DATA_TYPE_UINT8, num_entries, NULL);
			fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_DTLB_DATA,
			    DATA_TYPE_UINT64_ARRAY, tlb_data_words,
			    (uint64_t *)ch_flt->tlb_diag_data.tlo_dtlb_tte,
			    NULL);
		}
	}
}

/*
 * Panther Cache Scrubbing:
 *
 * In Jaguar, the E$ was split between cores, so the scrubber must run on both
 * cores.  For Panther, however, the L2$ and L3$ are shared across cores.
 * Therefore, the E$ scrubber only needs to run on one of the two cores.
 *
 * There are four possible states for the E$ scrubber:
 *
 * 0. If both cores are offline, add core 0 to cpu_offline_set so that
 *    the offline scrubber will run on it.
 * 1. If core 0 is online and core 1 off, we run the scrubber on core 0.
 * 2. If core 1 is online and core 0 off, we move the scrubber to run
 *    on core 1.
 * 3. If both cores are online, only run the scrubber on core 0.
 *
 * These states are enumerated by the SCRUBBER_[BOTH|CORE|NEITHER]_* defines
 * above.  One of those values is stored in
 * chpr_scrub_misc->chsm_core_state on each core.
 *
 * Also note that, for Panther, ecache_flush_line() will flush out the L2$
 * before the E$, so the L2$ will be scrubbed by the E$ scrubber.  No
 * additional code is necessary to scrub the L2$.
 *
 * For all cpu types, whenever a cpu or core is offlined, add it to
 * cpu_offline_set so the necessary scrubbers can still run.  This is still
 * necessary on Panther so the D$ scrubber can still run.
 */
/*ARGSUSED*/
int
cpu_scrub_cpu_setup(cpu_setup_t what, int cpuid, void *arg)
{
	processorid_t core_0_id;
	cpu_t *core_cpus[2];
	ch_scrub_misc_t *core_scrub[2];
	int old_state, i;
	int new_state = SCRUBBER_NEITHER_CORE_ONLINE;

	switch (what) {
	case CPU_ON:
	case CPU_INIT:
		CPUSET_DEL(cpu_offline_set, cpuid);
		break;
	case CPU_OFF:
		CPUSET_ADD(cpu_offline_set, cpuid);
		break;
	default:
		return (0);
	}

	if (!IS_PANTHER(cpunodes[cpuid].implementation)) {
		return (0);
	}

	/*
	 * Update the chsm_enable[CACHE_SCRUBBER_INFO_E] value
	 * if necessary
	 */
	core_0_id = cmp_cpu_to_chip(cpuid);
	core_cpus[0] = cpu_get(core_0_id);
	core_cpus[1] = cpu_get_sibling_core(core_cpus[0]);

	for (i = 0; i < 2; i++) {
		if (core_cpus[i] == NULL) {
			/*
			 * This may happen during DR - one core is offlined
			 * and completely unconfigured before the second
			 * core is offlined.  Give up and return quietly,
			 * since the second core should quickly be removed
			 * anyways.
			 */
			return (0);
		}
		core_scrub[i] = CPU_PRIVATE_PTR(core_cpus[i], chpr_scrub_misc);
	}

	if (cpuid == (processorid_t)cmp_cpu_to_chip(cpuid)) {
		/* cpuid is core 0 */
		if (cpu_is_active(core_cpus[1])) {
			new_state |= SCRUBBER_CORE_1_ONLINE;
		}
		if (what != CPU_OFF) {
			new_state |= SCRUBBER_CORE_0_ONLINE;
		}
	} else {
		/* cpuid is core 1 */
		if (cpu_is_active(core_cpus[0])) {
			new_state |= SCRUBBER_CORE_0_ONLINE;
		}
		if (what != CPU_OFF) {
			new_state |= SCRUBBER_CORE_1_ONLINE;
		}
	}

	old_state = core_scrub[0]->chsm_core_state;

	if (old_state == new_state) {
		return (0);
	}

	if (old_state == SCRUBBER_CORE_1_ONLINE) {
		/*
		 * We need to move the scrubber state from core 1
		 * back to core 0.  This data is not protected by
		 * locks, but the worst that can happen is some
		 * lines are scrubbed multiple times.  chsm_oustanding is
		 * set to 0 to make sure an interrupt is scheduled the
		 * first time through do_scrub().
		 */
		core_scrub[0]->chsm_flush_index[CACHE_SCRUBBER_INFO_E] =
		    core_scrub[1]->chsm_flush_index[CACHE_SCRUBBER_INFO_E];
		core_scrub[0]->chsm_outstanding[CACHE_SCRUBBER_INFO_E] = 0;
	}

	switch (new_state) {
	case SCRUBBER_NEITHER_CORE_ONLINE:
	case SCRUBBER_BOTH_CORES_ONLINE:
	case SCRUBBER_CORE_0_ONLINE:
		core_scrub[1]->chsm_enable[CACHE_SCRUBBER_INFO_E] = 0;
		core_scrub[0]->chsm_enable[CACHE_SCRUBBER_INFO_E] = 1;
		break;

	case SCRUBBER_CORE_1_ONLINE:
	default:
		/*
		 * We need to move the scrubber state from core 0
		 * to core 1.
		 */
		core_scrub[1]->chsm_flush_index[CACHE_SCRUBBER_INFO_E] =
		    core_scrub[0]->chsm_flush_index[CACHE_SCRUBBER_INFO_E];
		core_scrub[1]->chsm_outstanding[CACHE_SCRUBBER_INFO_E] = 0;

		core_scrub[0]->chsm_enable[CACHE_SCRUBBER_INFO_E] = 0;
		core_scrub[1]->chsm_enable[CACHE_SCRUBBER_INFO_E] = 1;
		break;
	}

	core_scrub[0]->chsm_core_state = new_state;
	core_scrub[1]->chsm_core_state = new_state;
	return (0);
}

/*
 * Returns a pointer to the cpu structure of the argument's sibling core.
 * If no sibling core can be found, return NULL.
 */
static cpu_t *
cpu_get_sibling_core(cpu_t *cpup)
{
	cpu_t		*nextp;
	pg_t		*pg;
	pg_cpu_itr_t	i;

	if ((cpup == NULL) || (!cmp_cpu_is_cmp(cpup->cpu_id)))
		return (NULL);
	pg = (pg_t *)pghw_find_pg(cpup, PGHW_CHIP);
	if (pg == NULL)
		return (NULL);

	/*
	 * Iterate over the CPUs in the chip PG looking
	 * for a CPU that isn't cpup
	 */
	PG_CPU_ITR_INIT(pg, i);
	while ((nextp = pg_cpu_next(&i)) != NULL) {
		if (nextp != cpup)
			break;
	}

	if (nextp == NULL)
		return (NULL);

	return (nextp);
}
