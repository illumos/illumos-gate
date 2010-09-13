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

/*
 * Support for Olympus-C (SPARC64-VI) and Jupiter (SPARC64-VII).
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
#include <vm/vm_dep.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kpm.h>
#include <vm/seg_kmem.h>
#include <sys/cpuvar.h>
#include <sys/opl_olympus_regs.h>
#include <sys/opl_module.h>
#include <sys/async.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/dditypes.h>
#include <sys/cpu_module.h>
#include <sys/sysmacros.h>
#include <sys/intreg.h>
#include <sys/clock.h>
#include <sys/platform_module.h>
#include <sys/ontrap.h>
#include <sys/panic.h>
#include <sys/memlist.h>
#include <sys/ndifm.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/cpu/SPARC64-VI.h>
#include <sys/dtrace.h>
#include <sys/watchpoint.h>
#include <sys/promif.h>

/*
 * Internal functions.
 */
static int cpu_sync_log_err(void *flt);
static void cpu_payload_add_aflt(struct async_flt *, nvlist_t *, nvlist_t *);
static void opl_cpu_sync_error(struct regs *, ulong_t, ulong_t, uint_t, uint_t);
static int  cpu_flt_in_memory(opl_async_flt_t *, uint64_t);
static int prom_SPARC64VII_support_enabled(void);
static void opl_ta3();
static int plat_prom_preserve_kctx_is_supported(void);

/*
 * Error counters resetting interval.
 */
static int opl_async_check_interval = 60;		/* 1 min */

uint_t cpu_impl_dual_pgsz = 1;

/*
 * PA[22:0] represent Displacement in Jupiter
 * configuration space.
 */
uint_t	root_phys_addr_lo_mask = 0x7fffffu;

/*
 * set in /etc/system to control logging of user BERR/TO's
 */
int cpu_berr_to_verbose = 0;

/*
 * Set to 1 if booted with all Jupiter cpus (all-Jupiter features enabled).
 */
int cpu_alljupiter = 0;

/*
 * The sfmmu_cext field to be used by processes in a shared context domain.
 */
static uchar_t shctx_cext = TAGACCEXT_MKSZPAIR(DEFAULT_ISM_PAGESZC, TTE8K);

static int min_ecache_size;
static uint_t priv_hcl_1;
static uint_t priv_hcl_2;
static uint_t priv_hcl_4;
static uint_t priv_hcl_8;

/*
 * Olympus error log
 */
static opl_errlog_t	*opl_err_log;
static int		opl_cpu0_log_setup;

/*
 * OPL ta 3 save area.
 */
char	*opl_ta3_save;

/*
 * UE is classified into four classes (MEM, CHANNEL, CPU, PATH).
 * No any other ecc_type_info insertion is allowed in between the following
 * four UE classess.
 */
ecc_type_to_info_t ecc_type_to_info[] = {
	SFSR_UE,	"UE ",	(OPL_ECC_SYNC_TRAP), OPL_CPU_SYNC_UE,
	"Uncorrectable ECC",  FM_EREPORT_PAYLOAD_SYNC,
	FM_EREPORT_CPU_UE_MEM,
	SFSR_UE,	"UE ",	(OPL_ECC_SYNC_TRAP), OPL_CPU_SYNC_UE,
	"Uncorrectable ECC",  FM_EREPORT_PAYLOAD_SYNC,
	FM_EREPORT_CPU_UE_CHANNEL,
	SFSR_UE,	"UE ",	(OPL_ECC_SYNC_TRAP), OPL_CPU_SYNC_UE,
	"Uncorrectable ECC",  FM_EREPORT_PAYLOAD_SYNC,
	FM_EREPORT_CPU_UE_CPU,
	SFSR_UE,	"UE ",	(OPL_ECC_SYNC_TRAP), OPL_CPU_SYNC_UE,
	"Uncorrectable ECC",  FM_EREPORT_PAYLOAD_SYNC,
	FM_EREPORT_CPU_UE_PATH,
	SFSR_BERR, "BERR ", (OPL_ECC_SYNC_TRAP), OPL_CPU_SYNC_OTHERS,
	"Bus Error",  FM_EREPORT_PAYLOAD_SYNC,
	FM_EREPORT_CPU_BERR,
	SFSR_TO, "TO ", (OPL_ECC_SYNC_TRAP), OPL_CPU_SYNC_OTHERS,
	"Bus Timeout",  FM_EREPORT_PAYLOAD_SYNC,
	FM_EREPORT_CPU_BTO,
	SFSR_TLB_MUL, "TLB_MUL ", (OPL_ECC_SYNC_TRAP), OPL_CPU_SYNC_OTHERS,
	"TLB MultiHit",  FM_EREPORT_PAYLOAD_SYNC,
	FM_EREPORT_CPU_MTLB,
	SFSR_TLB_PRT, "TLB_PRT ", (OPL_ECC_SYNC_TRAP), OPL_CPU_SYNC_OTHERS,
	"TLB Parity",  FM_EREPORT_PAYLOAD_SYNC,
	FM_EREPORT_CPU_TLBP,

	UGESR_IAUG_CRE, "IAUG_CRE", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IAUG CRE",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_CRE,
	UGESR_IAUG_TSBCTXT, "IAUG_TSBCTXT",
	OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IAUG TSBCTXT",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_TSBCTX,
	UGESR_IUG_TSBP, "IUG_TSBP", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG TSBP",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_TSBP,
	UGESR_IUG_PSTATE, "IUG_PSTATE", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG PSTATE",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_PSTATE,
	UGESR_IUG_TSTATE, "IUG_TSTATE", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG TSTATE",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_TSTATE,
	UGESR_IUG_F, "IUG_F", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG FREG",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_IUG_F,
	UGESR_IUG_R, "IUG_R", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG RREG",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_IUG_R,
	UGESR_AUG_SDC, "AUG_SDC", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"AUG SDC",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_SDC,
	UGESR_IUG_WDT, "IUG_WDT", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG WDT",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_WDT,
	UGESR_IUG_DTLB, "IUG_DTLB", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG DTLB",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_DTLB,
	UGESR_IUG_ITLB, "IUG_ITLB", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG ITLB",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_ITLB,
	UGESR_IUG_COREERR, "IUG_COREERR",
	OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"IUG COREERR",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_CORE,
	UGESR_MULTI_DAE, "MULTI_DAE", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"MULTI DAE",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_DAE,
	UGESR_MULTI_IAE, "MULTI_IAE", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"MULTI IAE",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_IAE,
	UGESR_MULTI_UGE, "MULTI_UGE", OPL_ECC_URGENT_TRAP, OPL_CPU_URGENT,
	"MULTI UGE",  FM_EREPORT_PAYLOAD_URGENT,
	FM_EREPORT_CPU_UGE,
	0,		NULL,		0,		0,
	NULL,  0,	   0,
};

int (*p2get_mem_info)(int synd_code, uint64_t paddr,
		uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
		int *segsp, int *banksp, int *mcidp);


/*
 * Setup trap handlers for 0xA, 0x32, 0x40 trap types
 * and "ta 3" and "ta 4".
 */
void
cpu_init_trap(void)
{
	OPL_SET_TRAP(tt0_iae, opl_serr_instr);
	OPL_SET_TRAP(tt1_iae, opl_serr_instr);
	OPL_SET_TRAP(tt0_dae, opl_serr_instr);
	OPL_SET_TRAP(tt1_dae, opl_serr_instr);
	OPL_SET_TRAP(tt0_asdat, opl_ugerr_instr);
	OPL_SET_TRAP(tt1_asdat, opl_ugerr_instr);
	OPL_SET_TRAP(tt0_flushw, opl_ta3_instr);
	OPL_PATCH_28(opl_cleanw_patch, opl_ta4_instr);
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
		"l1-dcache-size", &dcache_size, OPL_DCACHE_SIZE,
		"l1-dcache-line-size", &dcache_linesize, OPL_DCACHE_LSIZE,
		"l1-icache-size", &icache_size, OPL_ICACHE_SIZE,
		"l1-icache-line-size", &icache_linesize, OPL_ICACHE_LSIZE,
		"l2-cache-size", &ecache_size, OPL_ECACHE_SIZE,
		"l2-cache-line-size", &ecache_alignsize, OPL_ECACHE_LSIZE,
		"l2-cache-associativity", &ecache_associativity, OPL_ECACHE_NWAY
	};

	for (i = 0; i < sizeof (prop) / sizeof (prop[0]); i++)
		*prop[i].var = getintprop(dnode, prop[i].name, prop[i].defval);

	ecache_setsize = ecache_size / ecache_associativity;

	vac_size = OPL_VAC_SIZE;
	vac_mask = MMU_PAGEMASK & (vac_size - 1);
	i = 0; a = vac_size;
	while (a >>= 1)
		++i;
	vac_shift = i;
	shm_alignment = vac_size;
	vac = 1;
}

/*
 * Enable features for Jupiter-only domains.
 */
void
cpu_fix_alljupiter(void)
{
	if (!prom_SPARC64VII_support_enabled()) {
		/*
		 * Do not enable all-Jupiter features and do not turn on
		 * the cpu_alljupiter flag.
		 */
		return;
	}

	cpu_alljupiter = 1;

	/*
	 * Enable ima hwcap for Jupiter-only domains.  DR will prevent
	 * addition of Olympus-C to all-Jupiter domains to preserve ima
	 * hwcap semantics.
	 */
	cpu_hwcap_flags |= AV_SPARC_IMA;

	/*
	 * Enable shared context support.
	 */
	shctx_on = 1;
}

#ifdef	OLYMPUS_C_REV_B_ERRATA_XCALL
/*
 * Quick and dirty way to redefine locally in
 * OPL the value of IDSR_BN_SETS to 31 instead
 * of the standard 32 value. This is to workaround
 * REV_B of Olympus_c processor's problem in handling
 * more than 31 xcall broadcast.
 */
#undef	IDSR_BN_SETS
#define	IDSR_BN_SETS    31
#endif	/* OLYMPUS_C_REV_B_ERRATA_XCALL */

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
#ifdef	OLYMPUS_C_REV_A_ERRATA_XCALL
	int bn_sets = IDSR_BN_SETS;
	uint64_t ver;

	ASSERT(NCPU > bn_sets);
#endif

	ASSERT(!CPUSET_ISNULL(set));
	starttick = lasttick = gettick();

#ifdef	OLYMPUS_C_REV_A_ERRATA_XCALL
	ver = ultra_getver();
	if (((ULTRA_VER_IMPL(ver)) == OLYMPUS_C_IMPL) &&
	    ((OLYMPUS_REV_MASK(ver)) == OLYMPUS_C_A))
		bn_sets = 1;
#endif

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
#ifdef	OLYMPUS_C_REV_A_ERRATA_XCALL
			if (shipped < bn_sets) {
#else
			if (shipped < IDSR_BN_SETS) {
#endif
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
			cmn_err(CE_CONT, "send mondo timeout [%d NACK %d "
			    "BUSY]\nIDSR 0x%" PRIx64 "  cpuids:",
			    nack, busy, idsr);
#ifdef	OLYMPUS_C_REV_A_ERRATA_XCALL
			for (i = 0; i < bn_sets; i++) {
#else
			for (i = 0; i < IDSR_BN_SETS; i++) {
#endif
				if (idsr & (IDSR_NACK_BIT(i) |
				    IDSR_BUSY_BIT(i))) {
					cmn_err(CE_CONT, " 0x%x", cpuids[i]);
				}
			}
			cmn_err(CE_CONT, "\n");
			cmn_err(CE_PANIC, "send_mondo_set: timeout");
		}
		curnack = idsr & nackmask;
		curbusy = idsr & busymask;

#ifdef OLYMPUS_C_REV_B_ERRATA_XCALL
		/*
		 * Only proceed to send more xcalls if all the
		 * cpus in the previous IDSR_BN_SETS were completed.
		 */
		if (curbusy) {
			busy++;
			continue;
		}
#endif /* OLYMPUS_C_REV_B_ERRATA_XCALL */

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
				continue;
			}
		}
#endif
#ifndef	OLYMPUS_C_REV_B_ERRATA_XCALL
		if (curbusy) {
			busy++;
			continue;
		}
#endif	/* OLYMPUS_C_REV_B_ERRATA_XCALL */
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
 * Cpu private initialization.
 */
void
cpu_init_private(struct cpu *cp)
{
	if (!((IS_OLYMPUS_C(cpunodes[cp->cpu_id].implementation)) ||
	    (IS_JUPITER(cpunodes[cp->cpu_id].implementation)))) {
		cmn_err(CE_PANIC, "CPU%d Impl %d: Only SPARC64-VI(I) is "
		    "supported", cp->cpu_id,
		    cpunodes[cp->cpu_id].implementation);
	}

	adjust_hw_copy_limits(cpunodes[cp->cpu_id].ecache_size);
}

void
cpu_setup(void)
{
	extern int at_flags;
	extern int cpc_has_overflow_intr;
	uint64_t cpu0_log;
	extern	 uint64_t opl_cpu0_err_log;

	/*
	 * Initialize Error log Scratch register for error handling.
	 */

	cpu0_log = va_to_pa(&opl_cpu0_err_log);
	opl_error_setup(cpu0_log);
	opl_cpu0_log_setup = 1;

	/*
	 * Enable MMU translating multiple page sizes for
	 * sITLB and sDTLB.
	 */
	cpu_early_feature_init();

	/*
	 * Setup chip-specific trap handlers.
	 */
	cpu_init_trap();

	cache |= (CACHE_VAC | CACHE_PTAG | CACHE_IOCOHERENT);

	at_flags = EF_SPARC_32PLUS | EF_SPARC_SUN_US1 | EF_SPARC_SUN_US3;

	/*
	 * Due to the number of entries in the fully-associative tlb
	 * this may have to be tuned lower than in spitfire.
	 */
	pp_slots = MIN(8, MAXPP_SLOTS);

	/*
	 * Block stores do not invalidate all pages of the d$, pagecopy
	 * et. al. need virtual translations with virtual coloring taken
	 * into consideration.  prefetch/ldd will pollute the d$ on the
	 * load side.
	 */
	pp_consistent_coloring = PPAGE_STORE_VCOLORING | PPAGE_LOADS_POLLUTE;

	if (use_page_coloring) {
		do_pg_coloring = 1;
	}

	isa_list =
	    "sparcv9+vis2 sparcv9+vis sparcv9 "
	    "sparcv8plus+vis2 sparcv8plus+vis sparcv8plus "
	    "sparcv8 sparcv8-fsmuld sparcv7 sparc";

	cpu_hwcap_flags = AV_SPARC_VIS | AV_SPARC_VIS2 |
	    AV_SPARC_POPC | AV_SPARC_FMAF;

	/*
	 * On SPARC64-VI, there's no hole in the virtual address space
	 */
	hole_start = hole_end = 0;

	/*
	 * The kpm mapping window.
	 * kpm_size:
	 *	The size of a single kpm range.
	 *	The overall size will be: kpm_size * vac_colors.
	 * kpm_vbase:
	 *	The virtual start address of the kpm range within the kernel
	 *	virtual address space. kpm_vbase has to be kpm_size aligned.
	 */
	kpm_size = (size_t)(128ull * 1024 * 1024 * 1024 * 1024); /* 128TB */
	kpm_size_shift = 47;
	kpm_vbase = (caddr_t)0x8000000000000000ull; /* 8EB */
	kpm_smallpages = 1;

	/*
	 * The traptrace code uses either %tick or %stick for
	 * timestamping.  We have %stick so we can use it.
	 */
	traptrace_use_stick = 1;

	/*
	 * SPARC64-VI has a performance counter overflow interrupt
	 */
	cpc_has_overflow_intr = 1;

	/*
	 * Declare that this architecture/cpu combination does not support
	 * fpRAS.
	 */
	fpras_implemented = 0;
}

/*
 * Called by setcpudelay
 */
void
cpu_init_tick_freq(void)
{
	/*
	 * For SPARC64-VI we want to use the system clock rate as
	 * the basis for low level timing, due to support of mixed
	 * speed CPUs and power managment.
	 */
	if (system_clock_freq == 0)
		cmn_err(CE_PANIC, "setcpudelay: invalid system_clock_freq");

	sys_tick_freq = system_clock_freq;
}

#ifdef SEND_MONDO_STATS
uint32_t x_one_stimes[64];
uint32_t x_one_ltimes[16];
uint32_t x_set_stimes[64];
uint32_t x_set_ltimes[16];
uint32_t x_set_cpus[NCPU];
uint32_t x_nack_stimes[64];
#endif

/*
 * Note: A version of this function is used by the debugger via the KDI,
 * and must be kept in sync with this version.  Any changes made to this
 * function to support new chips or to accomodate errata must also be included
 * in the KDI-specific version.  See us3_kdi.c.
 */
void
send_one_mondo(int cpuid)
{
	int busy, nack;
	uint64_t idsr, starttick, endtick, tick, lasttick;
	uint64_t busymask;

	CPU_STATS_ADDQ(CPU, sys, xcalls, 1);
	starttick = lasttick = gettick();
	shipit(cpuid, 0);
	endtick = starttick + xc_tick_limit;
	busy = nack = 0;
	busymask = IDSR_BUSY;
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
			cmn_err(CE_PANIC, "send mondo timeout (target 0x%x) "
			    "[%d NACK %d BUSY]", cpuid, nack, busy);
		}

		if (idsr & busymask) {
			busy++;
			continue;
		}
		drv_usecwait(1);
		shipit(cpuid, 0);
		nack++;
		busy = 0;
	}
#ifdef SEND_MONDO_STATS
	{
		int n = gettick() - starttick;
		if (n < 8192)
			x_one_stimes[n >> 7]++;
		else
			x_one_ltimes[(n >> 13) & 0xf]++;
	}
#endif
}

/*
 * init_mmu_page_sizes is set to one after the bootup time initialization
 * via mmu_init_mmu_page_sizes, to indicate that mmu_page_sizes has a
 * valid value.
 *
 * mmu_disable_ism_large_pages and mmu_disable_large_pages are the mmu-specific
 * versions of disable_ism_large_pages and disable_large_pages, and feed back
 * into those two hat variables at hat initialization time.
 *
 */
int init_mmu_page_sizes = 0;

static uint_t mmu_disable_large_pages = 0;
static uint_t mmu_disable_ism_large_pages = ((1 << TTE64K) |
	(1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
static uint_t mmu_disable_auto_data_large_pages = ((1 << TTE64K) |
	(1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
static uint_t mmu_disable_auto_text_large_pages = ((1 << TTE64K) |
	(1 << TTE512K));

/*
 * Re-initialize mmu_page_sizes and friends, for SPARC64-VI mmu support.
 * Called during very early bootup from check_cpus_set().
 * Can be called to verify that mmu_page_sizes are set up correctly.
 *
 * Set Olympus defaults. We do not use the function parameter.
 */
/*ARGSUSED*/
void
mmu_init_scd(sf_scd_t *scdp)
{
	scdp->scd_sfmmup->sfmmu_cext = shctx_cext;
}

/*ARGSUSED*/
int
mmu_init_mmu_page_sizes(int32_t not_used)
{
	if (!init_mmu_page_sizes) {
		mmu_page_sizes = MMU_PAGE_SIZES;
		mmu_hashcnt = MAX_HASHCNT;
		mmu_ism_pagesize = DEFAULT_ISM_PAGESIZE;
		mmu_exported_pagesize_mask = (1 << TTE8K) |
		    (1 << TTE64K) | (1 << TTE512K) | (1 << TTE4M) |
		    (1 << TTE32M) | (1 << TTE256M);
		init_mmu_page_sizes = 1;
		return (0);
	}
	return (1);
}

/* SPARC64-VI worst case DTLB parameters */
#ifndef	LOCKED_DTLB_ENTRIES
#define	LOCKED_DTLB_ENTRIES	5	/* 2 user TSBs, 2 nucleus, + OBP */
#endif
#define	TOTAL_DTLB_ENTRIES	32
#define	AVAIL_32M_ENTRIES	0
#define	AVAIL_256M_ENTRIES	0
#define	AVAIL_DTLB_ENTRIES	(TOTAL_DTLB_ENTRIES - LOCKED_DTLB_ENTRIES)
static uint64_t ttecnt_threshold[MMU_PAGE_SIZES] = {
	AVAIL_DTLB_ENTRIES, AVAIL_DTLB_ENTRIES,
	AVAIL_DTLB_ENTRIES, AVAIL_DTLB_ENTRIES,
	AVAIL_DTLB_ENTRIES, AVAIL_DTLB_ENTRIES};

/*
 * The function returns the mmu-specific values for the
 * hat's disable_large_pages, disable_ism_large_pages, and
 * disable_auto_data_large_pages and
 * disable_text_data_large_pages variables.
 */
uint_t
mmu_large_pages_disabled(uint_t flag)
{
	uint_t pages_disable = 0;
	extern int use_text_pgsz64K;
	extern int use_text_pgsz512K;

	if (flag == HAT_LOAD) {
		pages_disable =  mmu_disable_large_pages;
	} else if (flag == HAT_LOAD_SHARE) {
		pages_disable = mmu_disable_ism_large_pages;
	} else if (flag == HAT_AUTO_DATA) {
		pages_disable = mmu_disable_auto_data_large_pages;
	} else if (flag == HAT_AUTO_TEXT) {
		pages_disable = mmu_disable_auto_text_large_pages;
		if (use_text_pgsz512K) {
			pages_disable &= ~(1 << TTE512K);
		}
		if (use_text_pgsz64K) {
			pages_disable &= ~(1 << TTE64K);
		}
	}
	return (pages_disable);
}

/*
 * mmu_init_large_pages is called with the desired ism_pagesize parameter.
 * It may be called from set_platform_defaults, if some value other than 4M
 * is desired.  mmu_ism_pagesize is the tunable.  If it has a bad value,
 * then only warn, since it would be bad form to panic due to a user typo.
 *
 * The function re-initializes the mmu_disable_ism_large_pages variable.
 */
void
mmu_init_large_pages(size_t ism_pagesize)
{

	switch (ism_pagesize) {
	case MMU_PAGESIZE4M:
		mmu_disable_ism_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
		mmu_disable_auto_data_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
		shctx_cext = TAGACCEXT_MKSZPAIR(TTE4M, TTE8K);
		break;
	case MMU_PAGESIZE32M:
		mmu_disable_ism_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE256M));
		mmu_disable_auto_data_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE4M) | (1 << TTE256M));
		adjust_data_maxlpsize(ism_pagesize);
		shctx_cext = TAGACCEXT_MKSZPAIR(TTE32M, TTE8K);
		break;
	case MMU_PAGESIZE256M:
		mmu_disable_ism_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE32M));
		mmu_disable_auto_data_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE4M) | (1 << TTE32M));
		adjust_data_maxlpsize(ism_pagesize);
		shctx_cext = TAGACCEXT_MKSZPAIR(TTE256M, TTE8K);
		break;
	default:
		cmn_err(CE_WARN, "Unrecognized mmu_ism_pagesize value 0x%lx",
		    ism_pagesize);
		break;
	}
}

/*
 * Function to reprogram the TLBs when page sizes used
 * by a process change significantly.
 */
static void
mmu_setup_page_sizes(struct hat *hat, uint64_t *ttecnt, uint8_t *tmp_pgsz)
{
	uint8_t pgsz0, pgsz1;

	/*
	 * Don't program 2nd dtlb for kernel and ism hat
	 */
	ASSERT(hat->sfmmu_ismhat == NULL);
	ASSERT(hat != ksfmmup);

	/*
	 * hat->sfmmu_pgsz[] is an array whose elements
	 * contain a sorted order of page sizes.  Element
	 * 0 is the most commonly used page size, followed
	 * by element 1, and so on.
	 *
	 * ttecnt[] is an array of per-page-size page counts
	 * mapped into the process.
	 *
	 * If the HAT's choice for page sizes is unsuitable,
	 * we can override it here.  The new values written
	 * to the array will be handed back to us later to
	 * do the actual programming of the TLB hardware.
	 *
	 */
	pgsz0 = (uint8_t)MIN(tmp_pgsz[0], tmp_pgsz[1]);
	pgsz1 = (uint8_t)MAX(tmp_pgsz[0], tmp_pgsz[1]);

	/*
	 * This implements PAGESIZE programming of the sTLB
	 * if large TTE counts don't exceed the thresholds.
	 */
	if (ttecnt[pgsz0] < ttecnt_threshold[pgsz0])
		pgsz0 = page_szc(MMU_PAGESIZE);
	if (ttecnt[pgsz1] < ttecnt_threshold[pgsz1])
		pgsz1 = page_szc(MMU_PAGESIZE);
	tmp_pgsz[0] = pgsz0;
	tmp_pgsz[1] = pgsz1;
	/* otherwise, accept what the HAT chose for us */
}

/*
 * The HAT calls this function when an MMU context is allocated so that we
 * can reprogram the large TLBs appropriately for the new process using
 * the context.
 *
 * The caller must hold the HAT lock.
 */
void
mmu_set_ctx_page_sizes(struct hat *hat)
{
	uint8_t pgsz0, pgsz1;
	uint8_t new_cext;

	ASSERT(sfmmu_hat_lock_held(hat));
	/*
	 * Don't program 2nd dtlb for kernel and ism hat
	 */
	if (hat->sfmmu_ismhat || hat == ksfmmup)
		return;

	/*
	 * If supported, reprogram the TLBs to a larger pagesize.
	 */
	if (hat->sfmmu_scdp != NULL) {
		new_cext = hat->sfmmu_scdp->scd_sfmmup->sfmmu_cext;
		ASSERT(new_cext == shctx_cext);
	} else {
		pgsz0 = hat->sfmmu_pgsz[0];
		pgsz1 = hat->sfmmu_pgsz[1];
		ASSERT(pgsz0 < mmu_page_sizes);
		ASSERT(pgsz1 < mmu_page_sizes);
		new_cext = TAGACCEXT_MKSZPAIR(pgsz1, pgsz0);
	}
	if (hat->sfmmu_cext != new_cext) {
#ifdef DEBUG
		int i;
		/*
		 * assert cnum should be invalid, this is because pagesize
		 * can only be changed after a proc's ctxs are invalidated.
		 */
		for (i = 0; i < max_mmu_ctxdoms; i++) {
			ASSERT(hat->sfmmu_ctxs[i].cnum == INVALID_CONTEXT);
		}
#endif /* DEBUG */
		hat->sfmmu_cext = new_cext;
	}
	/*
	 * sfmmu_setctx_sec() will take care of the
	 * rest of the dirty work for us.
	 */
}

/*
 * This function assumes that there are either four or six supported page
 * sizes and at most two programmable TLBs, so we need to decide which
 * page sizes are most important and then adjust the TLB page sizes
 * accordingly (if supported).
 *
 * If these assumptions change, this function will need to be
 * updated to support whatever the new limits are.
 */
void
mmu_check_page_sizes(sfmmu_t *sfmmup, uint64_t *ttecnt)
{
	uint64_t sortcnt[MMU_PAGE_SIZES];
	uint8_t tmp_pgsz[MMU_PAGE_SIZES];
	uint8_t i, j, max;
	uint16_t oldval, newval;

	/*
	 * We only consider reprogramming the TLBs if one or more of
	 * the two most used page sizes changes and we're using
	 * large pages in this process.
	 */
	if (SFMMU_LGPGS_INUSE(sfmmup)) {
		/* Sort page sizes. */
		for (i = 0; i < mmu_page_sizes; i++) {
			sortcnt[i] = ttecnt[i];
		}
		for (j = 0; j < mmu_page_sizes; j++) {
			for (i = mmu_page_sizes - 1, max = 0; i > 0; i--) {
				if (sortcnt[i] > sortcnt[max])
					max = i;
			}
			tmp_pgsz[j] = max;
			sortcnt[max] = 0;
		}

		oldval = sfmmup->sfmmu_pgsz[0] << 8 | sfmmup->sfmmu_pgsz[1];

		mmu_setup_page_sizes(sfmmup, ttecnt, tmp_pgsz);

		/* Check 2 largest values after the sort. */
		newval = tmp_pgsz[0] << 8 | tmp_pgsz[1];
		if (newval != oldval) {
			sfmmu_reprog_pgsz_arr(sfmmup, tmp_pgsz);
		}
	}
}

/*
 * Return processor specific async error structure
 * size used.
 */
int
cpu_aflt_size(void)
{
	return (sizeof (opl_async_flt_t));
}

/*
 * The cpu_sync_log_err() function is called via the [uc]e_drain() function to
 * post-process CPU events that are dequeued.  As such, it can be invoked
 * from softint context, from AST processing in the trap() flow, or from the
 * panic flow.  We decode the CPU-specific data, and take appropriate actions.
 * Historically this entry point was used to log the actual cmn_err(9F) text;
 * now with FMA it is used to prepare 'flt' to be converted into an ereport.
 * With FMA this function now also returns a flag which indicates to the
 * caller whether the ereport should be posted (1) or suppressed (0).
 */
/*ARGSUSED*/
static int
cpu_sync_log_err(void *flt)
{
	opl_async_flt_t *opl_flt = (opl_async_flt_t *)flt;
	struct async_flt *aflt = (struct async_flt *)flt;

	/*
	 * No extra processing of urgent error events.
	 * Always generate ereports for these events.
	 */
	if (aflt->flt_status == OPL_ECC_URGENT_TRAP)
		return (1);

	/*
	 * Additional processing for synchronous errors.
	 */
	switch (opl_flt->flt_type) {
	case OPL_CPU_INV_SFSR:
		return (1);

	case OPL_CPU_SYNC_UE:
		/*
		 * The validity: SFSR_MK_UE bit has been checked
		 * in opl_cpu_sync_error()
		 * No more check is required.
		 *
		 * opl_flt->flt_eid_mod and flt_eid_sid have been set by H/W,
		 * and they have been retrieved in cpu_queue_events()
		 */

		if (opl_flt->flt_eid_mod == OPL_ERRID_MEM) {
			ASSERT(aflt->flt_in_memory);
			/*
			 * We want to skip logging only if ALL the following
			 * conditions are true:
			 *
			 *	1. We are not panicing already.
			 *	2. The error is a memory error.
			 *	3. There is only one error.
			 *	4. The error is on a retired page.
			 *	5. The error occurred under on_trap
			 *	protection AFLT_PROT_EC
			 */
			if (!panicstr && aflt->flt_prot == AFLT_PROT_EC &&
			    page_retire_check(aflt->flt_addr, NULL) == 0) {
				/*
				 * Do not log an error from
				 * the retired page
				 */
				softcall(ecc_page_zero, (void *)aflt->flt_addr);
				return (0);
			}
			if (!panicstr)
				cpu_page_retire(opl_flt);
		}
		return (1);

	case OPL_CPU_SYNC_OTHERS:
		/*
		 * For the following error cases, the processor HW does
		 * not set the flt_eid_mod/flt_eid_sid. Instead, SW will attempt
		 * to assign appropriate values here to reflect what we
		 * think is the most likely cause of the problem w.r.t to
		 * the particular error event.  For Buserr and timeout
		 * error event, we will assign OPL_ERRID_CHANNEL as the
		 * most likely reason.  For TLB parity or multiple hit
		 * error events, we will assign the reason as
		 * OPL_ERRID_CPU (cpu related problem) and set the
		 * flt_eid_sid to point to the cpuid.
		 */

		if (opl_flt->flt_bit & (SFSR_BERR|SFSR_TO)) {
			/*
			 * flt_eid_sid will not be used for this case.
			 */
			opl_flt->flt_eid_mod = OPL_ERRID_CHANNEL;
		}
		if (opl_flt->flt_bit & (SFSR_TLB_MUL|SFSR_TLB_PRT)) {
			opl_flt->flt_eid_mod = OPL_ERRID_CPU;
			opl_flt->flt_eid_sid = aflt->flt_inst;
		}

		/*
		 * In case of no effective error bit
		 */
		if ((opl_flt->flt_bit & SFSR_ERRS) == 0) {
			opl_flt->flt_eid_mod = OPL_ERRID_CPU;
			opl_flt->flt_eid_sid = aflt->flt_inst;
		}
		break;

		default:
			return (1);
	}
	return (1);
}

/*
 * Retire the bad page that may contain the flushed error.
 */
void
cpu_page_retire(opl_async_flt_t *opl_flt)
{
	struct async_flt *aflt = (struct async_flt *)opl_flt;
	(void) page_retire(aflt->flt_addr, PR_UE);
}

/*
 * Invoked by error_init() early in startup and therefore before
 * startup_errorq() is called to drain any error Q -
 *
 * startup()
 *   startup_end()
 *     error_init()
 *       cpu_error_init()
 * errorq_init()
 *   errorq_drain()
 * start_other_cpus()
 *
 * The purpose of this routine is to create error-related taskqs.  Taskqs
 * are used for this purpose because cpu_lock can't be grabbed from interrupt
 * context.
 *
 */
/*ARGSUSED*/
void
cpu_error_init(int items)
{
	opl_err_log = (opl_errlog_t *)
	    kmem_alloc(ERRLOG_ALLOC_SZ, KM_SLEEP);
	if ((uint64_t)opl_err_log & MMU_PAGEOFFSET)
		cmn_err(CE_PANIC, "The base address of the error log "
		    "is not page aligned");
}

/*
 * We route all errors through a single switch statement.
 */
void
cpu_ue_log_err(struct async_flt *aflt)
{
	switch (aflt->flt_class) {
	case CPU_FAULT:
		if (cpu_sync_log_err(aflt))
			cpu_ereport_post(aflt);
		break;

	case BUS_FAULT:
		bus_async_log_err(aflt);
		break;

	default:
		cmn_err(CE_WARN, "discarding async error %p with invalid "
		    "fault class (0x%x)", (void *)aflt, aflt->flt_class);
		return;
	}
}

/*
 * Routine for panic hook callback from panic_idle().
 *
 * Nothing to do here.
 */
void
cpu_async_panic_callb(void)
{
}

/*
 * Routine to return a string identifying the physical name
 * associated with a memory/cache error.
 */
/*ARGSUSED*/
int
cpu_get_mem_unum(int synd_status, ushort_t flt_synd, uint64_t flt_stat,
    uint64_t flt_addr, int flt_bus_id, int flt_in_memory,
    ushort_t flt_status, char *buf, int buflen, int *lenp)
{
	int synd_code;
	int ret;

	/*
	 * An AFSR of -1 defaults to a memory syndrome.
	 */
	synd_code = (int)flt_synd;

	if (&plat_get_mem_unum) {
		if ((ret = plat_get_mem_unum(synd_code, flt_addr, flt_bus_id,
		    flt_in_memory, flt_status, buf, buflen, lenp)) != 0) {
			buf[0] = '\0';
			*lenp = 0;
		}
		return (ret);
	}
	buf[0] = '\0';
	*lenp = 0;
	return (ENOTSUP);
}

/*
 * Wrapper for cpu_get_mem_unum() routine that takes an
 * async_flt struct rather than explicit arguments.
 */
int
cpu_get_mem_unum_aflt(int synd_status, struct async_flt *aflt,
    char *buf, int buflen, int *lenp)
{
	/*
	 * We always pass -1 so that cpu_get_mem_unum will interpret this as a
	 * memory error.
	 */
	return (cpu_get_mem_unum(synd_status, aflt->flt_synd,
	    (uint64_t)-1,
	    aflt->flt_addr, aflt->flt_bus_id, aflt->flt_in_memory,
	    aflt->flt_status, buf, buflen, lenp));
}

/*
 * This routine is a more generic interface to cpu_get_mem_unum()
 * that may be used by other modules (e.g. mm).
 */
/*ARGSUSED*/
int
cpu_get_mem_name(uint64_t synd, uint64_t *afsr, uint64_t afar,
    char *buf, int buflen, int *lenp)
{
	int synd_status, flt_in_memory, ret;
	ushort_t flt_status = 0;
	char unum[UNUM_NAMLEN];

	/*
	 * Check for an invalid address.
	 */
	if (afar == (uint64_t)-1)
		return (ENXIO);

	if (synd == (uint64_t)-1)
		synd_status = AFLT_STAT_INVALID;
	else
		synd_status = AFLT_STAT_VALID;

	flt_in_memory = (*afsr & SFSR_MEMORY) &&
	    pf_is_memory(afar >> MMU_PAGESHIFT);

	ret = cpu_get_mem_unum(synd_status, (ushort_t)synd, *afsr, afar,
	    CPU->cpu_id, flt_in_memory, flt_status, unum, UNUM_NAMLEN, lenp);
	if (ret != 0)
		return (ret);

	if (*lenp >= buflen)
		return (ENAMETOOLONG);

	(void) strncpy(buf, unum, buflen);

	return (0);
}

/*
 * Routine to return memory information associated
 * with a physical address and syndrome.
 */
/*ARGSUSED*/
int
cpu_get_mem_info(uint64_t synd, uint64_t afar,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp)
{
	int synd_code = (int)synd;

	if (afar == (uint64_t)-1)
		return (ENXIO);

	if (p2get_mem_info != NULL)
		return ((p2get_mem_info)(synd_code, afar, mem_sizep, seg_sizep,
		    bank_sizep, segsp, banksp, mcidp));
	else
		return (ENOTSUP);
}

/*
 * Routine to return a string identifying the physical
 * name associated with a cpuid.
 */
int
cpu_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	int ret;
	char unum[UNUM_NAMLEN];

	if (&plat_get_cpu_unum) {
		if ((ret = plat_get_cpu_unum(cpuid, unum, UNUM_NAMLEN,
		    lenp)) != 0)
			return (ret);
	} else {
		return (ENOTSUP);
	}

	if (*lenp >= buflen)
		return (ENAMETOOLONG);

	(void) strncpy(buf, unum, *lenp);

	return (0);
}

/*
 * This routine exports the name buffer size.
 */
size_t
cpu_get_name_bufsize()
{
	return (UNUM_NAMLEN);
}

/*
 * Flush the entire ecache by ASI_L2_CNTL.U2_FLUSH
 */
void
cpu_flush_ecache(void)
{
	flush_ecache(ecache_flushaddr, cpunodes[CPU->cpu_id].ecache_size,
	    cpunodes[CPU->cpu_id].ecache_linesize);
}

static uint8_t
flt_to_trap_type(struct async_flt *aflt)
{
	if (aflt->flt_status & OPL_ECC_ISYNC_TRAP)
		return (TRAP_TYPE_ECC_I);
	if (aflt->flt_status & OPL_ECC_DSYNC_TRAP)
		return (TRAP_TYPE_ECC_D);
	if (aflt->flt_status & OPL_ECC_URGENT_TRAP)
		return (TRAP_TYPE_URGENT);
	return (TRAP_TYPE_UNKNOWN);
}

/*
 * Encode the data saved in the opl_async_flt_t struct into
 * the FM ereport payload.
 */
/* ARGSUSED */
static void
cpu_payload_add_aflt(struct async_flt *aflt, nvlist_t *payload,
		nvlist_t *resource)
{
	opl_async_flt_t *opl_flt = (opl_async_flt_t *)aflt;
	char unum[UNUM_NAMLEN];
	char sbuf[21]; /* sizeof (UINT64_MAX) + '\0' */
	int len;


	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_SFSR) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SFSR,
		    DATA_TYPE_UINT64, aflt->flt_stat, NULL);
	}
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_SFAR) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SFAR,
		    DATA_TYPE_UINT64, aflt->flt_addr, NULL);
	}
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_UGESR) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_UGESR,
		    DATA_TYPE_UINT64, aflt->flt_stat, NULL);
	}
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_PC) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PC,
		    DATA_TYPE_UINT64, (uint64_t)aflt->flt_pc, NULL);
	}
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_TL) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_TL,
		    DATA_TYPE_UINT8, (uint8_t)aflt->flt_tl, NULL);
	}
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_TT) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_TT,
		    DATA_TYPE_UINT8, flt_to_trap_type(aflt), NULL);
	}
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_PRIV) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PRIV,
		    DATA_TYPE_BOOLEAN_VALUE,
		    (aflt->flt_priv ? B_TRUE : B_FALSE), NULL);
	}
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_FLT_STATUS) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FLT_STATUS,
		    DATA_TYPE_UINT64, (uint64_t)aflt->flt_status, NULL);
	}

	switch (opl_flt->flt_eid_mod) {
	case OPL_ERRID_CPU:
		(void) snprintf(sbuf, sizeof (sbuf), "%llX",
		    (u_longlong_t)cpunodes[opl_flt->flt_eid_sid].device_id);
		(void) fm_fmri_cpu_set(resource, FM_CPU_SCHEME_VERSION,
		    NULL, opl_flt->flt_eid_sid,
		    (uint8_t *)&cpunodes[opl_flt->flt_eid_sid].version, sbuf);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RESOURCE,
		    DATA_TYPE_NVLIST, resource, NULL);
		break;

	case OPL_ERRID_CHANNEL:
		/*
		 * No resource is created but the cpumem DE will find
		 * the defective path by retreiving EID from SFSR which is
		 * included in the payload.
		 */
		break;

	case OPL_ERRID_MEM:
		(void) cpu_get_mem_unum_aflt(0, aflt, unum, UNUM_NAMLEN, &len);
		(void) fm_fmri_mem_set(resource, FM_MEM_SCHEME_VERSION, NULL,
		    unum, NULL, (uint64_t)-1);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RESOURCE,
		    DATA_TYPE_NVLIST, resource, NULL);
		break;

	case OPL_ERRID_PATH:
		/*
		 * No resource is created but the cpumem DE will find
		 * the defective path by retreiving EID from SFSR which is
		 * included in the payload.
		 */
		break;
	}
}

/*
 * Returns whether fault address is valid for this error bit and
 * whether the address is "in memory" (i.e. pf_is_memory returns 1).
 */
/*ARGSUSED*/
static int
cpu_flt_in_memory(opl_async_flt_t *opl_flt, uint64_t t_afsr_bit)
{
	struct async_flt *aflt = (struct async_flt *)opl_flt;

	if (aflt->flt_status & (OPL_ECC_SYNC_TRAP)) {
		return ((t_afsr_bit & SFSR_MEMORY) &&
		    pf_is_memory(aflt->flt_addr >> MMU_PAGESHIFT));
	}
	return (0);
}

/*
 * In OPL SCF does the stick synchronization.
 */
void
sticksync_slave(void)
{
}

/*
 * In OPL SCF does the stick synchronization.
 */
void
sticksync_master(void)
{
}

/*
 * Cpu private unitialization.  OPL cpus do not use the private area.
 */
void
cpu_uninit_private(struct cpu *cp)
{
	cmp_delete_cpu(cp->cpu_id);
}

/*
 * Always flush an entire cache.
 */
void
cpu_error_ecache_flush(void)
{
	cpu_flush_ecache();
}

void
cpu_ereport_post(struct async_flt *aflt)
{
	char *cpu_type, buf[FM_MAX_CLASS];
	nv_alloc_t *nva = NULL;
	nvlist_t *ereport, *detector, *resource;
	errorq_elem_t *eqep;
	char sbuf[21]; /* sizeof (UINT64_MAX) + '\0' */

	if (aflt->flt_panic || panicstr) {
		eqep = errorq_reserve(ereport_errorq);
		if (eqep == NULL)
			return;
		ereport = errorq_elem_nvl(ereport_errorq, eqep);
		nva = errorq_elem_nva(ereport_errorq, eqep);
	} else {
		ereport = fm_nvlist_create(nva);
	}

	/*
	 * Create the scheme "cpu" FMRI.
	 */
	detector = fm_nvlist_create(nva);
	resource = fm_nvlist_create(nva);
	switch (cpunodes[aflt->flt_inst].implementation) {
	case OLYMPUS_C_IMPL:
		cpu_type = FM_EREPORT_CPU_SPARC64_VI;
		break;
	case JUPITER_IMPL:
		cpu_type = FM_EREPORT_CPU_SPARC64_VII;
		break;
	default:
		cpu_type = FM_EREPORT_CPU_UNSUPPORTED;
		break;
	}
	(void) snprintf(sbuf, sizeof (sbuf), "%llX",
	    (u_longlong_t)cpunodes[aflt->flt_inst].device_id);
	(void) fm_fmri_cpu_set(detector, FM_CPU_SCHEME_VERSION, NULL,
	    aflt->flt_inst, (uint8_t *)&cpunodes[aflt->flt_inst].version,
	    sbuf);

	/*
	 * Encode all the common data into the ereport.
	 */
	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s.%s",
	    FM_ERROR_CPU, cpu_type, aflt->flt_erpt_class);

	fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
	    fm_ena_generate(aflt->flt_id, FM_ENA_FMT1), detector, NULL);

	/*
	 * Encode the error specific data that was saved in
	 * the async_flt structure into the ereport.
	 */
	cpu_payload_add_aflt(aflt, ereport, resource);

	if (aflt->flt_panic || panicstr) {
		errorq_commit(ereport_errorq, eqep, ERRORQ_SYNC);
	} else {
		(void) fm_ereport_post(ereport, EVCH_TRYHARD);
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
		fm_nvlist_destroy(detector, FM_NVA_FREE);
		fm_nvlist_destroy(resource, FM_NVA_FREE);
	}
}

void
cpu_run_bus_error_handlers(struct async_flt *aflt, int expected)
{
	int status;
	ddi_fm_error_t de;

	bzero(&de, sizeof (ddi_fm_error_t));

	de.fme_version = DDI_FME_VERSION;
	de.fme_ena = fm_ena_generate(aflt->flt_id, FM_ENA_FMT1);
	de.fme_flag = expected;
	de.fme_bus_specific = (void *)aflt->flt_addr;
	status = ndi_fm_handler_dispatch(ddi_root_node(), NULL, &de);
	if ((aflt->flt_prot == AFLT_PROT_NONE) && (status == DDI_FM_FATAL))
		aflt->flt_panic = 1;
}

void
cpu_errorq_dispatch(char *error_class, void *payload, size_t payload_sz,
    errorq_t *eqp, uint_t flag)
{
	struct async_flt *aflt = (struct async_flt *)payload;

	aflt->flt_erpt_class = error_class;
	errorq_dispatch(eqp, payload, payload_sz, flag);
}

void
adjust_hw_copy_limits(int ecache_size)
{
	/*
	 * Set hw copy limits.
	 *
	 * /etc/system will be parsed later and can override one or more
	 * of these settings.
	 *
	 * At this time, ecache size seems only mildly relevant.
	 * We seem to run into issues with the d-cache and stalls
	 * we see on misses.
	 *
	 * Cycle measurement indicates that 2 byte aligned copies fare
	 * little better than doing things with VIS at around 512 bytes.
	 * 4 byte aligned shows promise until around 1024 bytes. 8 Byte
	 * aligned is faster whenever the source and destination data
	 * in cache and the total size is less than 2 Kbytes.  The 2K
	 * limit seems to be driven by the 2K write cache.
	 * When more than 2K of copies are done in non-VIS mode, stores
	 * backup in the write cache.  In VIS mode, the write cache is
	 * bypassed, allowing faster cache-line writes aligned on cache
	 * boundaries.
	 *
	 * In addition, in non-VIS mode, there is no prefetching, so
	 * for larger copies, the advantage of prefetching to avoid even
	 * occasional cache misses is enough to justify using the VIS code.
	 *
	 * During testing, it was discovered that netbench ran 3% slower
	 * when hw_copy_limit_8 was 2K or larger.  Apparently for server
	 * applications, data is only used once (copied to the output
	 * buffer, then copied by the network device off the system).  Using
	 * the VIS copy saves more L2 cache state.  Network copies are
	 * around 1.3K to 1.5K in size for historical reasons.
	 *
	 * Therefore, a limit of 1K bytes will be used for the 8 byte
	 * aligned copy even for large caches and 8 MB ecache.  The
	 * infrastructure to allow different limits for different sized
	 * caches is kept to allow further tuning in later releases.
	 */

	if (min_ecache_size == 0 && use_hw_bcopy) {
		/*
		 * First time through - should be before /etc/system
		 * is read.
		 * Could skip the checks for zero but this lets us
		 * preserve any debugger rewrites.
		 */
		if (hw_copy_limit_1 == 0) {
			hw_copy_limit_1 = VIS_COPY_THRESHOLD;
			priv_hcl_1 = hw_copy_limit_1;
		}
		if (hw_copy_limit_2 == 0) {
			hw_copy_limit_2 = 2 * VIS_COPY_THRESHOLD;
			priv_hcl_2 = hw_copy_limit_2;
		}
		if (hw_copy_limit_4 == 0) {
			hw_copy_limit_4 = 4 * VIS_COPY_THRESHOLD;
			priv_hcl_4 = hw_copy_limit_4;
		}
		if (hw_copy_limit_8 == 0) {
			hw_copy_limit_8 = 4 * VIS_COPY_THRESHOLD;
			priv_hcl_8 = hw_copy_limit_8;
		}
		min_ecache_size = ecache_size;
	} else {
		/*
		 * MP initialization. Called *after* /etc/system has
		 * been parsed. One CPU has already been initialized.
		 * Need to cater for /etc/system having scragged one
		 * of our values.
		 */
		if (ecache_size == min_ecache_size) {
			/*
			 * Same size ecache. We do nothing unless we
			 * have a pessimistic ecache setting. In that
			 * case we become more optimistic (if the cache is
			 * large enough).
			 */
			if (hw_copy_limit_8 == 4 * VIS_COPY_THRESHOLD) {
				/*
				 * Need to adjust hw_copy_limit* from our
				 * pessimistic uniprocessor value to a more
				 * optimistic UP value *iff* it hasn't been
				 * reset.
				 */
				if ((ecache_size > 1048576) &&
				    (priv_hcl_8 == hw_copy_limit_8)) {
					if (ecache_size <= 2097152)
						hw_copy_limit_8 = 4 *
						    VIS_COPY_THRESHOLD;
					else if (ecache_size <= 4194304)
						hw_copy_limit_8 = 4 *
						    VIS_COPY_THRESHOLD;
					else
						hw_copy_limit_8 = 4 *
						    VIS_COPY_THRESHOLD;
					priv_hcl_8 = hw_copy_limit_8;
				}
			}
		} else if (ecache_size < min_ecache_size) {
			/*
			 * A different ecache size. Can this even happen?
			 */
			if (priv_hcl_8 == hw_copy_limit_8) {
				/*
				 * The previous value that we set
				 * is unchanged (i.e., it hasn't been
				 * scragged by /etc/system). Rewrite it.
				 */
				if (ecache_size <= 1048576)
					hw_copy_limit_8 = 8 *
					    VIS_COPY_THRESHOLD;
				else if (ecache_size <= 2097152)
					hw_copy_limit_8 = 8 *
					    VIS_COPY_THRESHOLD;
				else if (ecache_size <= 4194304)
					hw_copy_limit_8 = 8 *
					    VIS_COPY_THRESHOLD;
				else
					hw_copy_limit_8 = 10 *
					    VIS_COPY_THRESHOLD;
				priv_hcl_8 = hw_copy_limit_8;
				min_ecache_size = ecache_size;
			}
		}
	}
}

#define	VIS_BLOCKSIZE		64

int
dtrace_blksuword32_err(uintptr_t addr, uint32_t *data)
{
	int ret, watched;

	watched = watch_disable_addr((void *)addr, VIS_BLOCKSIZE, S_WRITE);
	ret = dtrace_blksuword32(addr, data, 0);
	if (watched)
		watch_enable_addr((void *)addr, VIS_BLOCKSIZE, S_WRITE);

	return (ret);
}

void
opl_cpu_reg_init()
{
	uint64_t	this_cpu_log;

	if (cpu[getprocessorid()] == &cpu0 && opl_cpu0_log_setup == 1) {
		/*
		 * Support for "ta 3"
		 */
		opl_ta3();

		/*
		 * If we are being called at boot time on cpu0 the error
		 * log is already set up in cpu_setup. Clear the
		 * opl_cpu0_log_setup flag so that a subsequent DR of cpu0 will
		 * do the proper initialization.
		 */
		opl_cpu0_log_setup = 0;
		return;
	}

	/*
	 * Initialize Error log Scratch register for error handling.
	 */

	this_cpu_log = va_to_pa((void*)(((uint64_t)opl_err_log) +
	    ERRLOG_BUFSZ * (getprocessorid())));
	opl_error_setup(this_cpu_log);
}

/*
 * Queue one event in ue_queue based on ecc_type_to_info entry.
 */
static void
cpu_queue_one_event(opl_async_flt_t *opl_flt, char *reason,
    ecc_type_to_info_t *eccp)
{
	struct async_flt *aflt = (struct async_flt *)opl_flt;

	if (reason &&
	    strlen(reason) + strlen(eccp->ec_reason) < MAX_REASON_STRING) {
		(void) strcat(reason, eccp->ec_reason);
	}

	opl_flt->flt_bit = eccp->ec_afsr_bit;
	opl_flt->flt_type = eccp->ec_flt_type;
	aflt->flt_in_memory = cpu_flt_in_memory(opl_flt, opl_flt->flt_bit);
	aflt->flt_payload = eccp->ec_err_payload;

	ASSERT(aflt->flt_status & (OPL_ECC_SYNC_TRAP|OPL_ECC_URGENT_TRAP));
	cpu_errorq_dispatch(eccp->ec_err_class, (void *)opl_flt,
	    sizeof (opl_async_flt_t), ue_queue, aflt->flt_panic);
}

/*
 * Queue events on async event queue one event per error bit.
 * Return number of events queued.
 */
int
cpu_queue_events(opl_async_flt_t *opl_flt, char *reason, uint64_t t_afsr_errs)
{
	struct async_flt *aflt = (struct async_flt *)opl_flt;
	ecc_type_to_info_t *eccp;
	int nevents = 0;

	/*
	 * Queue expected errors, error bit and fault type must must match
	 * in the ecc_type_to_info table.
	 */
	for (eccp = ecc_type_to_info; t_afsr_errs != 0 && eccp->ec_desc != NULL;
	    eccp++) {
		if ((eccp->ec_afsr_bit & t_afsr_errs) != 0 &&
		    (eccp->ec_flags & aflt->flt_status) != 0) {
			/*
			 * UE error event can be further
			 * classified/breakdown into finer granularity
			 * based on the flt_eid_mod value set by HW.  We do
			 * special handling here so that we can report UE
			 * error in finer granularity as ue_mem,
			 * ue_channel, ue_cpu or ue_path.
			 */
			if (eccp->ec_flt_type == OPL_CPU_SYNC_UE) {
				opl_flt->flt_eid_mod = (aflt->flt_stat &
				    SFSR_EID_MOD) >> SFSR_EID_MOD_SHIFT;
				opl_flt->flt_eid_sid = (aflt->flt_stat &
				    SFSR_EID_SID) >> SFSR_EID_SID_SHIFT;
				/*
				 * Need to advance eccp pointer by flt_eid_mod
				 * so that we get an appropriate ecc pointer
				 *
				 * EID			# of advances
				 * ----------------------------------
				 * OPL_ERRID_MEM	0
				 * OPL_ERRID_CHANNEL	1
				 * OPL_ERRID_CPU	2
				 * OPL_ERRID_PATH	3
				 */
				eccp += opl_flt->flt_eid_mod;
			}
			cpu_queue_one_event(opl_flt, reason, eccp);
			t_afsr_errs &= ~eccp->ec_afsr_bit;
			nevents++;
		}
	}

	return (nevents);
}

/*
 * Sync. error wrapper functions.
 * We use these functions in order to transfer here from the
 * nucleus trap handler information about trap type (data or
 * instruction) and trap level (0 or above 0). This way we
 * get rid of using SFSR's reserved bits.
 */

#define	OPL_SYNC_TL0	0
#define	OPL_SYNC_TL1	1
#define	OPL_ISYNC_ERR	0
#define	OPL_DSYNC_ERR	1

void
opl_cpu_isync_tl0_error(struct regs *rp, ulong_t p_sfar, ulong_t p_sfsr)
{
	uint64_t t_sfar = p_sfar;
	uint64_t t_sfsr = p_sfsr;

	opl_cpu_sync_error(rp, t_sfar, t_sfsr,
	    OPL_SYNC_TL0, OPL_ISYNC_ERR);
}

void
opl_cpu_isync_tl1_error(struct regs *rp, ulong_t p_sfar, ulong_t p_sfsr)
{
	uint64_t t_sfar = p_sfar;
	uint64_t t_sfsr = p_sfsr;

	opl_cpu_sync_error(rp, t_sfar, t_sfsr,
	    OPL_SYNC_TL1, OPL_ISYNC_ERR);
}

void
opl_cpu_dsync_tl0_error(struct regs *rp, ulong_t p_sfar, ulong_t p_sfsr)
{
	uint64_t t_sfar = p_sfar;
	uint64_t t_sfsr = p_sfsr;

	opl_cpu_sync_error(rp, t_sfar, t_sfsr,
	    OPL_SYNC_TL0, OPL_DSYNC_ERR);
}

void
opl_cpu_dsync_tl1_error(struct regs *rp, ulong_t p_sfar, ulong_t p_sfsr)
{
	uint64_t t_sfar = p_sfar;
	uint64_t t_sfsr = p_sfsr;

	opl_cpu_sync_error(rp, t_sfar, t_sfsr,
	    OPL_SYNC_TL1, OPL_DSYNC_ERR);
}

/*
 * The fj sync err handler transfers control here for UE, BERR, TO, TLB_MUL
 * and TLB_PRT.
 * This function is designed based on cpu_deferred_error().
 */

static void
opl_cpu_sync_error(struct regs *rp, ulong_t t_sfar, ulong_t t_sfsr,
    uint_t tl, uint_t derr)
{
	opl_async_flt_t opl_flt;
	struct async_flt *aflt;
	int trampolined = 0;
	char pr_reason[MAX_REASON_STRING];
	uint64_t log_sfsr;
	int expected = DDI_FM_ERR_UNEXPECTED;
	ddi_acc_hdl_t *hp;

	/*
	 * We need to look at p_flag to determine if the thread detected an
	 * error while dumping core.  We can't grab p_lock here, but it's ok
	 * because we just need a consistent snapshot and we know that everyone
	 * else will store a consistent set of bits while holding p_lock.  We
	 * don't have to worry about a race because SDOCORE is set once prior
	 * to doing i/o from the process's address space and is never cleared.
	 */
	uint_t pflag = ttoproc(curthread)->p_flag;

	pr_reason[0] = '\0';

	/*
	 * handle the specific error
	 */
	bzero(&opl_flt, sizeof (opl_async_flt_t));
	aflt = (struct async_flt *)&opl_flt;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_bus_id = getprocessorid();
	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_stat = t_sfsr;
	aflt->flt_addr = t_sfar;
	aflt->flt_pc = (caddr_t)rp->r_pc;
	aflt->flt_prot = (uchar_t)AFLT_PROT_NONE;
	aflt->flt_class = (uchar_t)CPU_FAULT;
	aflt->flt_priv = (uchar_t)(tl == 1 ? 1 : ((rp->r_tstate &
	    TSTATE_PRIV) ? 1 : 0));
	aflt->flt_tl = (uchar_t)tl;
	aflt->flt_panic = (uchar_t)(tl != 0 || aft_testfatal != 0 ||
	    (t_sfsr & (SFSR_TLB_MUL|SFSR_TLB_PRT)) != 0);
	aflt->flt_core = (pflag & SDOCORE) ? 1 : 0;
	aflt->flt_status = (derr) ? OPL_ECC_DSYNC_TRAP : OPL_ECC_ISYNC_TRAP;

	/*
	 * If SFSR.FV is not set, both SFSR and SFAR/SFPAR values are uncertain.
	 * So, clear all error bits to avoid mis-handling and force the system
	 * panicked.
	 * We skip all the procedures below down to the panic message call.
	 */
	if (!(t_sfsr & SFSR_FV)) {
		opl_flt.flt_type = OPL_CPU_INV_SFSR;
		aflt->flt_panic = 1;
		aflt->flt_payload = FM_EREPORT_PAYLOAD_SYNC;
		cpu_errorq_dispatch(FM_EREPORT_CPU_INV_SFSR, (void *)&opl_flt,
		    sizeof (opl_async_flt_t), ue_queue, aflt->flt_panic);
		fm_panic("%sErrors(s)", "invalid SFSR");
	}

	/*
	 * If either UE and MK bit is off, this is not valid UE error.
	 * If it is not valid UE error, clear UE & MK_UE bits to prevent
	 * mis-handling below.
	 * aflt->flt_stat keeps the original bits as a reference.
	 */
	if ((t_sfsr & (SFSR_MK_UE|SFSR_UE)) !=
	    (SFSR_MK_UE|SFSR_UE)) {
		t_sfsr &= ~(SFSR_MK_UE|SFSR_UE);
	}

	/*
	 * If the trap occurred in privileged mode at TL=0, we need to check to
	 * see if we were executing in the kernel under on_trap() or t_lofault
	 * protection.  If so, modify the saved registers so that we return
	 * from the trap to the appropriate trampoline routine.
	 */
	if (!aflt->flt_panic && aflt->flt_priv && tl == 0) {
		if (curthread->t_ontrap != NULL) {
			on_trap_data_t *otp = curthread->t_ontrap;

			if (otp->ot_prot & OT_DATA_EC) {
				aflt->flt_prot = (uchar_t)AFLT_PROT_EC;
				otp->ot_trap |= (ushort_t)OT_DATA_EC;
				rp->r_pc = otp->ot_trampoline;
				rp->r_npc = rp->r_pc + 4;
				trampolined = 1;
			}

			if ((t_sfsr & (SFSR_TO | SFSR_BERR)) &&
			    (otp->ot_prot & OT_DATA_ACCESS)) {
				aflt->flt_prot = (uchar_t)AFLT_PROT_ACCESS;
				otp->ot_trap |= (ushort_t)OT_DATA_ACCESS;
				rp->r_pc = otp->ot_trampoline;
				rp->r_npc = rp->r_pc + 4;
				trampolined = 1;
				/*
				 * for peeks and caut_gets errors are expected
				 */
				hp = (ddi_acc_hdl_t *)otp->ot_handle;
				if (!hp)
					expected = DDI_FM_ERR_PEEK;
				else if (hp->ah_acc.devacc_attr_access ==
				    DDI_CAUTIOUS_ACC)
					expected = DDI_FM_ERR_EXPECTED;
			}

		} else if (curthread->t_lofault) {
			aflt->flt_prot = AFLT_PROT_COPY;
			rp->r_g1 = EFAULT;
			rp->r_pc = curthread->t_lofault;
			rp->r_npc = rp->r_pc + 4;
			trampolined = 1;
		}
	}

	/*
	 * If we're in user mode or we're doing a protected copy, we either
	 * want the ASTON code below to send a signal to the user process
	 * or we want to panic if aft_panic is set.
	 *
	 * If we're in privileged mode and we're not doing a copy, then we
	 * need to check if we've trampolined.  If we haven't trampolined,
	 * we should panic.
	 */
	if (!aflt->flt_priv || aflt->flt_prot == AFLT_PROT_COPY) {
		if (t_sfsr & (SFSR_ERRS & ~(SFSR_BERR | SFSR_TO)))
			aflt->flt_panic |= aft_panic;
	} else if (!trampolined) {
		aflt->flt_panic = 1;
	}

	/*
	 * If we've trampolined due to a privileged TO or BERR, or if an
	 * unprivileged TO or BERR occurred, we don't want to enqueue an
	 * event for that TO or BERR.  Queue all other events (if any) besides
	 * the TO/BERR.
	 */
	log_sfsr = t_sfsr;
	if (trampolined) {
		log_sfsr &= ~(SFSR_TO | SFSR_BERR);
	} else if (!aflt->flt_priv) {
		/*
		 * User mode, suppress messages if
		 * cpu_berr_to_verbose is not set.
		 */
		if (!cpu_berr_to_verbose)
			log_sfsr &= ~(SFSR_TO | SFSR_BERR);
	}

	if (((log_sfsr & SFSR_ERRS) && (cpu_queue_events(&opl_flt, pr_reason,
	    t_sfsr) == 0)) || ((t_sfsr & SFSR_ERRS) == 0)) {
		opl_flt.flt_type = OPL_CPU_INV_SFSR;
		aflt->flt_payload = FM_EREPORT_PAYLOAD_SYNC;
		cpu_errorq_dispatch(FM_EREPORT_CPU_INV_SFSR, (void *)&opl_flt,
		    sizeof (opl_async_flt_t), ue_queue, aflt->flt_panic);
	}

	if (t_sfsr & (SFSR_UE|SFSR_TO|SFSR_BERR)) {
		cpu_run_bus_error_handlers(aflt, expected);
	}

	/*
	 * Panic here if aflt->flt_panic has been set.  Enqueued errors will
	 * be logged as part of the panic flow.
	 */
	if (aflt->flt_panic) {
		if (pr_reason[0] == 0)
			strcpy(pr_reason, "invalid SFSR ");

		fm_panic("%sErrors(s)", pr_reason);
	}

	/*
	 * If we queued an error and we are going to return from the trap and
	 * the error was in user mode or inside of a copy routine, set AST flag
	 * so the queue will be drained before returning to user mode.  The
	 * AST processing will also act on our failure policy.
	 */
	if (!aflt->flt_priv || aflt->flt_prot == AFLT_PROT_COPY) {
		int pcb_flag = 0;

		if (t_sfsr & (SFSR_ERRS & ~(SFSR_BERR | SFSR_TO)))
			pcb_flag |= ASYNC_HWERR;

		if (t_sfsr & SFSR_BERR)
			pcb_flag |= ASYNC_BERR;

		if (t_sfsr & SFSR_TO)
			pcb_flag |= ASYNC_BTO;

		ttolwp(curthread)->lwp_pcb.pcb_flags |= pcb_flag;
		aston(curthread);
	}
}

/*ARGSUSED*/
void
opl_cpu_urgent_error(struct regs *rp, ulong_t p_ugesr, ulong_t tl)
{
	opl_async_flt_t opl_flt;
	struct async_flt *aflt;
	char pr_reason[MAX_REASON_STRING];

	/* normalize tl */
	tl = (tl >= 2 ? 1 : 0);
	pr_reason[0] = '\0';

	bzero(&opl_flt, sizeof (opl_async_flt_t));
	aflt = (struct async_flt *)&opl_flt;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_bus_id = getprocessorid();
	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_stat = p_ugesr;
	aflt->flt_pc = (caddr_t)rp->r_pc;
	aflt->flt_class = (uchar_t)CPU_FAULT;
	aflt->flt_tl = tl;
	aflt->flt_priv = (uchar_t)(tl == 1 ? 1 : ((rp->r_tstate & TSTATE_PRIV) ?
	    1 : 0));
	aflt->flt_status = OPL_ECC_URGENT_TRAP;
	aflt->flt_panic = 1;
	/*
	 * HW does not set mod/sid in case of urgent error.
	 * So we have to set it here.
	 */
	opl_flt.flt_eid_mod = OPL_ERRID_CPU;
	opl_flt.flt_eid_sid = aflt->flt_inst;

	if (cpu_queue_events(&opl_flt, pr_reason, p_ugesr) == 0) {
		opl_flt.flt_type = OPL_CPU_INV_UGESR;
		aflt->flt_payload = FM_EREPORT_PAYLOAD_URGENT;
		cpu_errorq_dispatch(FM_EREPORT_CPU_INV_URG, (void *)&opl_flt,
		    sizeof (opl_async_flt_t), ue_queue, aflt->flt_panic);
	}

	fm_panic("Urgent Error");
}

/*
 * Initialization error counters resetting.
 */
/* ARGSUSED */
static void
opl_ras_online(void *arg, cpu_t *cp, cyc_handler_t *hdlr, cyc_time_t *when)
{
	hdlr->cyh_func = (cyc_func_t)ras_cntr_reset;
	hdlr->cyh_level = CY_LOW_LEVEL;
	hdlr->cyh_arg = (void *)(uintptr_t)cp->cpu_id;

	when->cyt_when = cp->cpu_id * (((hrtime_t)NANOSEC * 10)/ NCPU);
	when->cyt_interval = (hrtime_t)NANOSEC * opl_async_check_interval;
}

void
cpu_mp_init(void)
{
	cyc_omni_handler_t hdlr;

	hdlr.cyo_online = opl_ras_online;
	hdlr.cyo_offline = NULL;
	hdlr.cyo_arg = NULL;
	mutex_enter(&cpu_lock);
	(void) cyclic_add_omni(&hdlr);
	mutex_exit(&cpu_lock);
}

int heaplp_use_stlb = 0;

void
mmu_init_kernel_pgsz(struct hat *hat)
{
	uint_t tte = page_szc(segkmem_lpsize);
	uchar_t new_cext_primary, new_cext_nucleus;

	if (heaplp_use_stlb == 0) {
		/* do not reprogram stlb */
		tte = TTE8K;
	} else if (!plat_prom_preserve_kctx_is_supported()) {
		/* OBP does not support non-zero primary context */
		tte = TTE8K;
		heaplp_use_stlb = 0;
	}

	new_cext_nucleus = TAGACCEXT_MKSZPAIR(tte, TTE8K);
	new_cext_primary = TAGACCEXT_MKSZPAIR(TTE8K, tte);

	hat->sfmmu_cext = new_cext_primary;
	kcontextreg = ((uint64_t)new_cext_nucleus << CTXREG_NEXT_SHIFT) |
	    ((uint64_t)new_cext_primary << CTXREG_EXT_SHIFT);
}

size_t
mmu_get_kernel_lpsize(size_t lpsize)
{
	uint_t tte;

	if (lpsize == 0) {
		/* no setting for segkmem_lpsize in /etc/system: use default */
		return (MMU_PAGESIZE4M);
	}

	for (tte = TTE8K; tte <= TTE4M; tte++) {
		if (lpsize == TTEBYTES(tte))
			return (lpsize);
	}

	return (TTEBYTES(TTE8K));
}

/*
 * Support for ta 3.
 * We allocate here a buffer for each cpu
 * for saving the current register window.
 */
typedef struct win_regs {
	uint64_t l[8];
	uint64_t i[8];
} win_regs_t;
static void
opl_ta3(void)
{
	/*
	 * opl_ta3 should only be called once at boot time.
	 */
	if (opl_ta3_save == NULL)
		opl_ta3_save = (char *)kmem_alloc(NCPU * sizeof (win_regs_t),
		    KM_SLEEP);
}

/*
 * The following are functions that are unused in
 * OPL cpu module. They are defined here to resolve
 * dependencies in the "unix" module.
 * Unused functions that should never be called in
 * OPL are coded with ASSERT(0).
 */

void
cpu_disable_errors(void)
{}

void
cpu_enable_errors(void)
{ ASSERT(0); }

/*ARGSUSED*/
void
cpu_ce_scrub_mem_err(struct async_flt *ecc, boolean_t t)
{ ASSERT(0); }

/*ARGSUSED*/
void
cpu_faulted_enter(struct cpu *cp)
{}

/*ARGSUSED*/
void
cpu_faulted_exit(struct cpu *cp)
{}

/*ARGSUSED*/
void
cpu_check_allcpus(struct async_flt *aflt)
{}

/*ARGSUSED*/
void
cpu_ce_log_err(struct async_flt *aflt, errorq_elem_t *t)
{ ASSERT(0); }

/*ARGSUSED*/
void
cpu_check_ce(int flag, uint64_t pa, caddr_t va, uint_t psz)
{ ASSERT(0); }

/*ARGSUSED*/
void
cpu_ce_count_unum(struct async_flt *ecc, int len, char *unum)
{ ASSERT(0); }

/*ARGSUSED*/
void
cpu_busy_ecache_scrub(struct cpu *cp)
{}

/*ARGSUSED*/
void
cpu_idle_ecache_scrub(struct cpu *cp)
{}

/* ARGSUSED */
void
cpu_change_speed(uint64_t divisor, uint64_t arg2)
{ ASSERT(0); }

void
cpu_init_cache_scrub(void)
{}

/* ARGSUSED */
int
cpu_get_mem_sid(char *unum, char *buf, int buflen, int *lenp)
{
	if (&plat_get_mem_sid) {
		return (plat_get_mem_sid(unum, buf, buflen, lenp));
	} else {
		return (ENOTSUP);
	}
}

/* ARGSUSED */
int
cpu_get_mem_addr(char *unum, char *sid, uint64_t offset, uint64_t *addrp)
{
	if (&plat_get_mem_addr) {
		return (plat_get_mem_addr(unum, sid, offset, addrp));
	} else {
		return (ENOTSUP);
	}
}

/* ARGSUSED */
int
cpu_get_mem_offset(uint64_t flt_addr, uint64_t *offp)
{
	if (&plat_get_mem_offset) {
		return (plat_get_mem_offset(flt_addr, offp));
	} else {
		return (ENOTSUP);
	}
}

/*ARGSUSED*/
void
itlb_rd_entry(uint_t entry, tte_t *tte, uint64_t *va_tag)
{ ASSERT(0); }

/*ARGSUSED*/
void
dtlb_rd_entry(uint_t entry, tte_t *tte, uint64_t *va_tag)
{ ASSERT(0); }

/*ARGSUSED*/
void
read_ecc_data(struct async_flt *aflt, short verbose, short ce_err)
{ ASSERT(0); }

/*ARGSUSED*/
int
ce_scrub_xdiag_recirc(struct async_flt *aflt, errorq_t *eqp,
    errorq_elem_t *eqep, size_t afltoffset)
{
	ASSERT(0);
	return (0);
}

/*ARGSUSED*/
char *
flt_to_error_type(struct async_flt *aflt)
{
	ASSERT(0);
	return (NULL);
}

#define	PROM_SPARC64VII_MODE_PROPNAME	"SPARC64-VII-mode"

/*
 * Check for existence of OPL OBP property that indicates
 * SPARC64-VII support. By default, only enable Jupiter
 * features if the property is present.   It will be
 * present in all-Jupiter domains by OBP if the domain has
 * been selected by the user on the system controller to
 * run in Jupiter mode.  Basically, this OBP property must
 * be present to turn on the cpu_alljupiter flag.
 */
static int
prom_SPARC64VII_support_enabled(void)
{
	int val;

	return ((prom_getprop(prom_rootnode(), PROM_SPARC64VII_MODE_PROPNAME,
	    (caddr_t)&val) == 0) ? 1 : 0);
}

#define	PROM_KCTX_PRESERVED_PROPNAME	"context0-page-size-preserved"

/*
 * Check for existence of OPL OBP property that indicates support for
 * preserving Solaris kernel page sizes when entering OBP.  We need to
 * check the prom tree since the ddi tree is not yet built when the
 * platform startup sequence is called.
 */
static int
plat_prom_preserve_kctx_is_supported(void)
{
	pnode_t		pnode;
	int		val;

	/*
	 * Check for existence of context0-page-size-preserved property
	 * in virtual-memory prom node.
	 */
	pnode = (pnode_t)prom_getphandle(prom_mmu_ihandle());
	return ((prom_getprop(pnode, PROM_KCTX_PRESERVED_PROPNAME,
	    (caddr_t)&val) == 0) ? 1 : 0);
}
