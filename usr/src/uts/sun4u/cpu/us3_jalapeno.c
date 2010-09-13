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
#include <sys/errclassify.h>

#ifdef	CHEETAHPLUS_ERRATUM_25
#include <sys/cyclic.h>
#endif	/* CHEETAHPLUS_ERRATUM_25 */

/* cpu estar private data */
typedef struct {
	uint8_t state : 7;
	uint8_t valid : 1;
} mcu_fsm_def_t;
mcu_fsm_def_t mcu_fsm_init_state[NCPU];

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
/*
 * jp_errata_85_enable can be set to 0 in /etc/system to disable
 * JP Errata 85 workaround.
 *
 * jp_errata_85_allow_slow_scrub is usually set to !jp_errata_85_enable,
 * but can be overridden in /etc/system.  If set, it allows the scrubber
 * to run in 1/2 or 1/32 mode.  If a cpu is vulnerable to errata 85,
 * this value should be zero.
 *
 * jp_errata_85_active is an internal variable and must not be
 * set/changed via /etc/system or in any other way.
 */
extern int	jp_errata_85_enable;	/* for /etc/system use */
extern int	jp_errata_85_allow_slow_scrub;	/* for /etc/system use */

int	jp_errata_85_active = -1;	/* warn: modified in code ONLY */
uint64_t	jp_estar_tl0_data[8];
uint64_t	jp_estar_tl1_data[8];
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

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
	extern int vac_size, vac_shift;
	extern uint_t vac_mask;

	static struct {
		char	*name;
		int	*var;
		int	defval;
	} prop[] = {
		"dcache-size", &dcache_size, CH_DCACHE_SIZE,
		"dcache-line-size", &dcache_linesize, CH_DCACHE_LSIZE,
		"icache-size", &icache_size, CH_ICACHE_SIZE,
		"icache-line-size", &icache_linesize, CH_ICACHE_LSIZE,
		"ecache-size", &ecache_size, JP_ECACHE_MAX_SIZE,
		"ecache-line-size", &ecache_alignsize, JP_ECACHE_MAX_LSIZE,
		"ecache-associativity", &ecache_associativity, JP_ECACHE_NWAY
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
}

void
send_mondo_set(cpuset_t set)
{
	int lo, busy, nack, shipped = 0;
	uint16_t i, cpuids[IDSR_BN_SETS];
	uint64_t idsr, nackmask = 0, busymask, curnack, curbusy;
	uint64_t starttick, endtick, tick, lasttick;
#ifdef	CHEETAHPLUS_ERRATUM_25
	int recovered = 0;
	int cpuid;
#endif

	ASSERT(!CPUSET_ISNULL(set));
	starttick = lasttick = gettick();

	/*
	 * Lower 2 bits of the agent ID determine which BUSY/NACK pair
	 * will be used for dispatching interrupt. For now, assume
	 * there are no more than IDSR_BN_SETS CPUs, hence no aliasing
	 * issues with respect to BUSY/NACK pair usage.
	 */
	for (i = 0; i < NCPU; i++)
		if (CPU_IN_SET(set, i)) {
			shipit(i, shipped /* ignored */);
			nackmask |= IDSR_NACK_BIT(CPUID_TO_BN_PAIR(i));
			cpuids[CPUID_TO_BN_PAIR(i)] = i;
			shipped++;
			CPUSET_DEL(set, i);
			if (CPUSET_ISNULL(set))
				break;
		}
	CPU_STATS_ADDQ(CPU, sys, xcalls, shipped);

	busymask = IDSR_NACK_TO_BUSY(nackmask);
	busy = nack = 0;
	endtick = starttick + xc_tick_limit;
	for (;;) {
		idsr = getidsr();
		if (idsr == 0)
			break;
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
int
cpu_impl_async_log_err(void *flt, errorq_elem_t *eqep)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)flt;
	struct async_flt *aflt = (struct async_flt *)flt;
	uint64_t errors;

	switch (ch_flt->flt_type) {

	case CPU_IC_PARITY:
		cpu_async_log_ic_parity_err(flt);
		return (CH_ASYNC_LOG_DONE);

	case CPU_DC_PARITY:
		cpu_async_log_dc_parity_err(flt);
		return (CH_ASYNC_LOG_DONE);

	case CPU_RCE:
		if (page_retire_check(aflt->flt_addr, &errors) == EINVAL) {
			CE_XDIAG_SETSKIPCODE(aflt->flt_disp,
			    CE_XDIAG_SKIP_NOPP);
		} else if (errors != PR_OK) {
			CE_XDIAG_SETSKIPCODE(aflt->flt_disp,
			    CE_XDIAG_SKIP_PAGEDET);
		} else if (ce_scrub_xdiag_recirc(aflt, ce_queue, eqep,
		    offsetof(ch_async_flt_t, cmn_asyncflt))) {
			return (CH_ASYNC_LOG_RECIRC);
		}
		/*FALLTHRU*/
	/*
	 * cases where we just want to report the error and continue.
	 */
	case CPU_BPAR:
	case CPU_UMS:
	case CPU_FRC:
	case CPU_FRU:
		cpu_log_err(aflt);
		return (CH_ASYNC_LOG_DONE);

	/*
	 * Cases where we want to fall through to handle panicking.
	 */
	case CPU_RUE:
		cpu_log_err(aflt);
		return (CH_ASYNC_LOG_CONTINUE);

	default:
		return (CH_ASYNC_LOG_UNKNOWN);
	}
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
	return (JP_ECACHE_NWAY);
}

/*
 * Note that these are entered into the table in the order:
 * Fatal Errors first, orphaned UCU/UCC, AFAR Overwrite policy,
 * FRC/FRU, and finally IVPE.
 *
 * Afar overwrite policy is:
 * Jalapeno:
 *   UCU,UCC > RUE,UE,EDU,WDU,CPU,WBP,BP > RCE,CE,EDC,WDC,CPC >
 *   TO,BERR > UMS,OM
 * Serrano:
 *   UCU,UCC > RUE,UE,EDU,WDU,CPU,WBP,BP > RCE,CE,EDC,WDC,CPC,ETI,ETC >
 *   TO,BERR > UMS,OM
 */
ecc_type_to_info_t ecc_type_to_info[] = {

	/* Fatal Errors */
	C_AFSR_JETO,	"JETO ",	ECC_ALL_TRAPS,	CPU_FATAL,
		"JETO Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_JETO,
	C_AFSR_SCE,	"SCE ",		ECC_ALL_TRAPS,	CPU_FATAL,
		"SCE Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_SCE,
	C_AFSR_JEIC,	"JEIC ",	ECC_ALL_TRAPS,	CPU_FATAL,
		"JEIC Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_JEIC,
	C_AFSR_JEIT,	"JEIT ",	ECC_ALL_TRAPS,	CPU_FATAL,
		"JEIT Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_JEIT,
	C_AFSR_JEIS,	"JEIS ",	ECC_ALL_TRAPS,	CPU_FATAL,
		"JEIS Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_JEIS,
#if defined(JALAPENO)
	C_AFSR_ETP,	"ETP ",		ECC_ALL_TRAPS,	CPU_FATAL,
		"ETP Fatal",
		FM_EREPORT_PAYLOAD_L2_TAG_PE,
		FM_EREPORT_CPU_USIII_ETP,
#elif defined(SERRANO)
	C_AFSR_ETS,	"ETS ",		ECC_ASYNC_TRAPS, CPU_FATAL,
		"ETS Fatal",
		FM_EREPORT_PAYLOAD_L2_TAG_ECC,
		FM_EREPORT_CPU_USIII_ETS,
	C_AFSR_ETU,	"ETU ",		ECC_ASYNC_TRAPS, CPU_FATAL,
		"ETU Fatal",
		FM_EREPORT_PAYLOAD_L2_TAG_ECC,
		FM_EREPORT_CPU_USIII_ETU,
#endif	/* SERRANO */
	C_AFSR_IERR,	"IERR ", 	ECC_ALL_TRAPS,	CPU_FATAL,
		"IERR Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM2,
		FM_EREPORT_CPU_USIII_IERR,
	C_AFSR_ISAP,	"ISAP ",	ECC_ALL_TRAPS,	CPU_FATAL,
		"ISAP Fatal",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_ISAP,

	/* Orphaned UCU/UCC Errors */
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


	/* RUE, UE, EDU:ST, EDU:BLD, WDU, CPU, BP, WBP */
	C_AFSR_RUE,	"RUE ",		ECC_ASYNC_TRAPS, CPU_RUE,
		"Uncorrectable remote memory/cache (RUE)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_RUE,
	C_AFSR_UE,	"UE ",		ECC_ASYNC_TRAPS, CPU_UE,
		"Uncorrectable memory (UE)",
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
	C_AFSR_WBP,	"WBP ",		ECC_C_TRAP,	CPU_BPAR,
		"JBUS parity error on writeback or block store (WBP)",
		FM_EREPORT_PAYLOAD_SYSTEM3,
		FM_EREPORT_CPU_USIII_WBP,
	C_AFSR_BP,	"BP ",		ECC_ASYNC_TRAPS, CPU_BPAR,
		"JBUS parity error on returned read data (BP)",
		FM_EREPORT_PAYLOAD_SYSTEM3,
		FM_EREPORT_CPU_USIII_BP,

	/* RCE, CE, EDC, WDC, CPC */
	C_AFSR_RCE,	"RCE ",		ECC_C_TRAP,	CPU_RCE,
		"Corrected remote memory/cache (RCE)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_RCE,
	C_AFSR_CE,	"CE ",		ECC_C_TRAP,	CPU_CE,
		"Corrected memory (CE)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_CE,
	C_AFSR_EDC,	"EDC ",		ECC_C_TRAP,	CPU_CE_ECACHE,
		"EDC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_EDC,
	C_AFSR_WDC,	"WDC ",		ECC_C_TRAP,	CPU_CE_ECACHE,
		"WDC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_WDC,
	C_AFSR_CPC,	"CPC ",		ECC_C_TRAP,	CPU_CE_ECACHE,
		"CPC",
		FM_EREPORT_PAYLOAD_L2_DATA,
		FM_EREPORT_CPU_USIII_CPC,
#if defined(SERRANO)
	/* ETI, ETC */
	C_AFSR_ETI,	"ETI",	ECC_F_TRAP | ECC_C_TRAP, CPU_CE_ECACHE,
		"ETI",
		FM_EREPORT_PAYLOAD_L2_TAG_ECC,
		FM_EREPORT_CPU_USIII_ETI,
	C_AFSR_ETC,	"ETC",	ECC_F_TRAP | ECC_C_TRAP, CPU_CE_ECACHE,
		"ETC",
		FM_EREPORT_PAYLOAD_L2_TAG_ECC,
		FM_EREPORT_CPU_USIII_ETC,
#endif	/* SERRANO */

	/* TO, BERR */
	C_AFSR_TO,	"TO ",		ECC_ASYNC_TRAPS, CPU_TO,
		"Timeout (TO)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_TO,
	C_AFSR_BERR,	"BERR ",	ECC_ASYNC_TRAPS, CPU_BERR,
		"Bus Error (BERR)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_BERR,

	/* UMS, OM */
	C_AFSR_UMS,	"UMS ",		ECC_C_TRAP,	 CPU_UMS,
		"Unsupported store (UMS)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_UMS,
	C_AFSR_OM,	"OM ",		ECC_ASYNC_TRAPS, CPU_BERR,
		"Out of range memory (OM)",
		FM_EREPORT_PAYLOAD_IO,
		FM_EREPORT_CPU_USIII_OM,

	/* FRC, FRU */
	C_AFSR_FRC,	"FRC ",		ECC_C_TRAP,	CPU_FRC,
		"Corrected memory (FRC)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_FRC,
	C_AFSR_FRU,	"FRU ",		ECC_C_TRAP,	 CPU_FRU,
		"Uncorrectable memory (FRU)",
		FM_EREPORT_PAYLOAD_MEMORY,
		FM_EREPORT_CPU_USIII_FRU,

	/* IVPE */
	C_AFSR_IVPE,	"IVPE ",	ECC_C_TRAP,	CPU_IV,
		"IVPE",
		FM_EREPORT_PAYLOAD_SYSTEM1,
		FM_EREPORT_CPU_USIII_IVPE,

	0,		NULL,		0,		0,
		NULL,
		FM_EREPORT_PAYLOAD_UNKNOWN,
		FM_EREPORT_CPU_USIII_UNKNOWN,
};

/*
 * J_REQ overwrite policy (see UltraSPARC-IIIi PRM)
 *
 *   Class 4:  RUE, BP, WBP
 *   Class 3:  RCE
 *   Class 2:  TO, BERR
 *   Class 1:  UMS
 */
uint64_t jreq_overwrite[] = {
	C_AFSR_RUE | C_AFSR_BP | C_AFSR_WBP,
	C_AFSR_RCE,
	C_AFSR_TO | C_AFSR_BERR,
	C_AFSR_UMS,
	0
};

/*
 * AGENT ID overwrite policy (see UltraSPARC-IIIi PRM)
 *
 *   Class 2:  CPU, FRU
 *   Class 1:  CPC, FRC
 */
uint64_t jbus_aid_overwrite[] = {
	C_AFSR_CPU | C_AFSR_FRU,
	C_AFSR_CPC | C_AFSR_FRC,
	0
};

int
afsr_to_jaid_status(uint64_t afsr, uint64_t afsr_bit)
{
	return (afsr_to_overw_status(afsr, afsr_bit, jbus_aid_overwrite));
}

/*
 * See UltraSPARC-IIIi+ PRM
 *   Class 5:  ETS, ETU, EFES
 *   Class 4:  UCC, UCU
 *   Class 3:  UE, RUE, BP, WBP, EDU, WDU, CPU
 *   Class 2:  CE, RCE, EDC, WDC, CPC, ETI, ETC
 *   Class 1:  TO, BERR
 *   Class 0:  UMS, OM
 *
 * See UltraSPARC-IIIi PRM
 *   Class 5:  ETP
 *   Class 4:  UCC, UCU
 *   Class 3:  UE, RUE, BP, WBP, EDU, WDU
 *   Class 2:  CE, RCE, EDC, WDC
 *   Class 1:  TO, BERR
 *   Class 0:  UMS, OM
 */
uint64_t afar_overwrite[] = {
#if defined(JALAPENO)
	C_AFSR_ETP,
#elif defined(SERRANO)
	C_AFSR_ETS | C_AFSR_ETU | C_AFSR_EFES,
#endif /* SERRANO */
	C_AFSR_UCC | C_AFSR_UCU,
	C_AFSR_UE | C_AFSR_RUE | C_AFSR_BP | C_AFSR_WBP | C_AFSR_EDU |
	    C_AFSR_WDU | C_AFSR_CPU,
#if defined(SERRANO)
	C_AFSR_ETI | C_AFSR_ETC |
#endif /* SERRANO */
	C_AFSR_CE | C_AFSR_RCE | C_AFSR_EDC | C_AFSR_WDC | C_AFSR_CPC,
	C_AFSR_TO | C_AFSR_BERR,
	C_AFSR_UMS | C_AFSR_OM,
	0
};

#if defined(SERRANO)
/*
 * Serrano has a second AFAR that captures the physical address on
 * FRC/FRU errors (which Jalapeno does not).  This register also
 * captures the address for UE and CE errors.
 *
 * See UltraSPARC-IIIi+ PRM
 *  Class 3: UE
 *  Class 2: FRU
 *  Class 1: CE
 *  Class 0: FRC
 */
uint64_t afar2_overwrite[] = {
	C_AFSR_UE,
	C_AFSR_FRU,
	C_AFSR_CE,
	C_AFSR_FRC,
	0
};
#endif  /* SERRANO */

/*
 * See UltraSPARC-IIIi PRM
 *   Class 2:  UE, FRU, EDU, WDU, UCU, CPU
 *   Class 1:  CE, FRC, EDC, WDC, UCC, CPC
 */
uint64_t esynd_overwrite[] = {
#if defined(SERRANO)
	C_AFSR_ETS | C_AFSR_ETU |
#endif	/* SERRANO */
	C_AFSR_UE | C_AFSR_FRU | C_AFSR_EDU | C_AFSR_WDU | C_AFSR_UCU |
	    C_AFSR_CPU,
	C_AFSR_CE | C_AFSR_FRC | C_AFSR_EDC | C_AFSR_WDC | C_AFSR_UCC |
	    C_AFSR_CPC,
	0
};

/*
 * Prioritized list of Error bits for BSYND (referred to as
 * MSYND to share code with CHEETAH & CHEETAH_PLUS) overwrite.
 * See UltraSPARC-IIIi PRM
 *   Class 3:  ISAP
 *   Class 2:  BP
 *   Class 1:  WBP, IVPE
 */
uint64_t msynd_overwrite[] = {
	C_AFSR_ISAP,
	C_AFSR_BP,
	C_AFSR_WBP | C_AFSR_IVPE,
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
	uint64_t		oldreg;
	uint64_t		mreg;
	uint64_t		val64;
	int			id = (CPU)->cpu_id;
	processor_info_t	*pi = &(CPU->cpu_type_info);

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	/*
	 * ASI Ecache flush in 1/2 or 1/32 speed mode can result
	 * in CPU fatal reset (JETO or IERR/TO on MP). A workaround
	 * is to force the CPU to full speed mode prior to using
	 * ASI Ecache flush opeartion to flush E$. Since we can't
	 * always use cross calls at the time of flushing E$, we
	 * cannot change other CPU speed. Hence, this workaround
	 * is applicable to uniprocessor configuration only and
	 * can't be used in multiprocessor configuration.
	 *
	 * Note that this workaround is activated only when the CPU
	 * has been fully initialized and its speed is lowered by the
	 * ppm for the first time. It can be disabled via /etc/system
	 * by setting jp_errata_85_enable to 0 and rebooting the
	 * system.
	 */
	if ((jp_errata_85_active == -1) &&
	    jp_errata_85_enable &&
	    (divisor != JBUS_CONFIG_ECLK_1_DIV)) {
		if (ncpus == 1)
			jp_errata_85_active = 1;
		else
			jp_errata_85_active = 0;
	}
	if ((!jp_errata_85_allow_slow_scrub) && (CPU_PRIVATE(CPU) != NULL)) {
		int i;
		ch_scrub_misc_t	*chpr_scrubp =
		    CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);

		/* We're only allowed to run the scrubbers at full speed */

		for (i = 0; i < CACHE_SCRUBBER_COUNT; i++) {
			chpr_scrubp->chsm_enable[i] =
			    (divisor == JBUS_CONFIG_ECLK_1_DIV);
		}
	}
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	/*
	 * We're only interested in mcu_ctl_reg1 bit 26 and 25, of which
	 * the value will be stored in the lower half of a byte.  The
	 * top bit of this byte is designated as a valid bit - 0 means
	 * invalid, 1 means valid.
	 */
	if (!mcu_fsm_init_state[id].valid) {
		val64 = get_mcu_ctl_reg1() & JP_MCU_FSM_MASK;
		mcu_fsm_init_state[id].state = val64 >> JP_MCU_FSM_SHIFT;
		mcu_fsm_init_state[id].valid = 1;
	}

	for (bceclk = bus_config_eclk; bceclk->divisor; bceclk++) {
		if (bceclk->divisor != divisor)
			continue;
		reg = get_jbus_config();
		oldreg = reg;
		reg &= ~JBUS_CONFIG_ECLK_MASK;
		reg |= bceclk->mask;
		set_jbus_config(reg);
		(void) get_jbus_config();

		/*
		 * MCU workaround, refer to Jalapeno spec, EnergyStar section
		 * for detail.
		 */

		/* Upon entering engery star mode, turn off extra MCU FSMs */
		if (((oldreg & JBUS_CONFIG_ECLK_MASK) == JBUS_CONFIG_ECLK_1) &&
		    ((divisor == JBUS_CONFIG_ECLK_2_DIV) ||
		    (divisor == JBUS_CONFIG_ECLK_32_DIV))) {
			mreg = get_mcu_ctl_reg1();
			if ((mreg & JP_MCU_FSM_MASK) != 0) {
				mreg &= ~JP_MCU_FSM_MASK;
				set_mcu_ctl_reg1(mreg);
				(void) get_mcu_ctl_reg1();
			}
		/* Upon exiting energy star mode, restore extra MCU FSMs */
		} else if (divisor == JBUS_CONFIG_ECLK_1_DIV) {
			mreg = get_mcu_ctl_reg1();
			val64 = mcu_fsm_init_state[id].state;
			mreg |= val64 << JP_MCU_FSM_SHIFT;
			set_mcu_ctl_reg1(mreg);
			(void) get_mcu_ctl_reg1();
		}
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

#if defined(SERRANO)
	if (!IS_SERRANO(cpunodes[cp->cpu_id].implementation)) {
		cmn_err(CE_PANIC, "CPU%d: implementation 0x%x not supported"
		    " on UltraSPARC-IIIi+ code\n", cp->cpu_id,
		    cpunodes[cp->cpu_id].implementation);
	}
#else /* SERRANO */
	if (!IS_JALAPENO(cpunodes[cp->cpu_id].implementation)) {
		cmn_err(CE_PANIC, "CPU%d: implementation 0x%x not supported"
		    " on UltraSPARC-IIIi code\n", cp->cpu_id,
		    cpunodes[cp->cpu_id].implementation);
	}
#endif /* SERRANO */

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
 * For Jalapeno, just clear the AFSR
 */
void
set_cpu_error_state(ch_cpu_errors_t *cpu_error_regs)
{
	set_asyncflt(cpu_error_regs->afsr & ~C_AFSR_FATAL_ERRS);
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
