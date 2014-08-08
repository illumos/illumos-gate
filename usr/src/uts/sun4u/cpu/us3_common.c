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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
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
#include <vm/vm_dep.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kpm.h>
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
#include <sys/taskq.h>
#include <sys/note.h>
#include <sys/ndifm.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <sys/fpras_impl.h>
#include <sys/dtrace.h>
#include <sys/watchpoint.h>
#include <sys/plat_ecc_unum.h>
#include <sys/cyclic.h>
#include <sys/errorq.h>
#include <sys/errclassify.h>
#include <sys/pghw.h>
#include <sys/clock_impl.h>

#ifdef	CHEETAHPLUS_ERRATUM_25
#include <sys/xc_impl.h>
#endif	/* CHEETAHPLUS_ERRATUM_25 */

ch_cpu_logout_t	clop_before_flush;
ch_cpu_logout_t	clop_after_flush;
uint_t	flush_retries_done = 0;
/*
 * Note that 'Cheetah PRM' refers to:
 *   SPARC V9 JPS1 Implementation Supplement: Sun UltraSPARC-III
 */

/*
 * Per CPU pointers to physical address of TL>0 logout data areas.
 * These pointers have to be in the kernel nucleus to avoid MMU
 * misses.
 */
uint64_t ch_err_tl1_paddrs[NCPU];

/*
 * One statically allocated structure to use during startup/DR
 * to prevent unnecessary panics.
 */
ch_err_tl1_data_t ch_err_tl1_data;

/*
 * Per CPU pending error at TL>0, used by level15 softint handler
 */
uchar_t ch_err_tl1_pending[NCPU];

/*
 * For deferred CE re-enable after trap.
 */
taskq_t		*ch_check_ce_tq;

/*
 * Internal functions.
 */
static int cpu_async_log_err(void *flt, errorq_elem_t *eqep);
static void cpu_log_diag_info(ch_async_flt_t *ch_flt);
static void cpu_queue_one_event(ch_async_flt_t *ch_flt, char *reason,
    ecc_type_to_info_t *eccp, ch_diag_data_t *cdp);
static int cpu_flt_in_memory_one_event(ch_async_flt_t *ch_flt,
    uint64_t t_afsr_bit);
static int clear_ecc(struct async_flt *ecc);
#if defined(CPU_IMP_ECACHE_ASSOC)
static int cpu_ecache_line_valid(ch_async_flt_t *ch_flt);
#endif
int cpu_ecache_set_size(struct cpu *cp);
static int cpu_ectag_line_invalid(int cachesize, uint64_t tag);
int cpu_ectag_pa_to_subblk(int cachesize, uint64_t subaddr);
uint64_t cpu_ectag_to_pa(int setsize, uint64_t tag);
int cpu_ectag_pa_to_subblk_state(int cachesize,
				uint64_t subaddr, uint64_t tag);
static void cpu_flush_ecache_line(ch_async_flt_t *ch_flt);
static int afsr_to_afar_status(uint64_t afsr, uint64_t afsr_bit);
static int afsr_to_esynd_status(uint64_t afsr, uint64_t afsr_bit);
static int afsr_to_msynd_status(uint64_t afsr, uint64_t afsr_bit);
static int afsr_to_synd_status(uint_t cpuid, uint64_t afsr, uint64_t afsr_bit);
static int synd_to_synd_code(int synd_status, ushort_t synd, uint64_t afsr_bit);
static int cpu_get_mem_unum_synd(int synd_code, struct async_flt *, char *buf);
static void cpu_uninit_ecache_scrub_dr(struct cpu *cp);
static void cpu_scrubphys(struct async_flt *aflt);
static void cpu_payload_add_aflt(struct async_flt *, nvlist_t *, nvlist_t *,
    int *, int *);
static void cpu_payload_add_ecache(struct async_flt *, nvlist_t *);
static void cpu_ereport_init(struct async_flt *aflt);
static int cpu_check_secondary_errors(ch_async_flt_t *, uint64_t, uint64_t);
static uint8_t cpu_flt_bit_to_plat_error(struct async_flt *aflt);
static void cpu_log_fast_ecc_error(caddr_t tpc, int priv, int tl, uint64_t ceen,
    uint64_t nceen, ch_cpu_logout_t *clop);
static int cpu_ce_delayed_ec_logout(uint64_t);
static int cpu_matching_ecache_line(uint64_t, void *, int, int *);
static int cpu_error_is_ecache_data(int, uint64_t);
static void cpu_fmri_cpu_set(nvlist_t *, int);
static int cpu_error_to_resource_type(struct async_flt *aflt);

#ifdef	CHEETAHPLUS_ERRATUM_25
static int mondo_recover_proc(uint16_t, int);
static void cheetah_nudge_init(void);
static void cheetah_nudge_onln(void *arg, cpu_t *cpu, cyc_handler_t *hdlr,
    cyc_time_t *when);
static void cheetah_nudge_buddy(void);
#endif	/* CHEETAHPLUS_ERRATUM_25 */

#if defined(CPU_IMP_L1_CACHE_PARITY)
static void cpu_dcache_parity_info(ch_async_flt_t *ch_flt);
static void cpu_dcache_parity_check(ch_async_flt_t *ch_flt, int index);
static void cpu_record_dc_data_parity(ch_async_flt_t *ch_flt,
    ch_dc_data_t *dest_dcp, ch_dc_data_t *src_dcp, int way, int word);
static void cpu_icache_parity_info(ch_async_flt_t *ch_flt);
static void cpu_icache_parity_check(ch_async_flt_t *ch_flt, int index);
static void cpu_pcache_parity_info(ch_async_flt_t *ch_flt);
static void cpu_pcache_parity_check(ch_async_flt_t *ch_flt, int index);
static void cpu_payload_add_dcache(struct async_flt *, nvlist_t *);
static void cpu_payload_add_icache(struct async_flt *, nvlist_t *);
#endif	/* CPU_IMP_L1_CACHE_PARITY */

int (*p2get_mem_info)(int synd_code, uint64_t paddr,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp);

/*
 * This table is used to determine which bit(s) is(are) bad when an ECC
 * error occurs.  The array is indexed by an 9-bit syndrome.  The entries
 * of this array have the following semantics:
 *
 *      00-127  The number of the bad bit, when only one bit is bad.
 *      128     ECC bit C0 is bad.
 *      129     ECC bit C1 is bad.
 *      130     ECC bit C2 is bad.
 *      131     ECC bit C3 is bad.
 *      132     ECC bit C4 is bad.
 *      133     ECC bit C5 is bad.
 *      134     ECC bit C6 is bad.
 *      135     ECC bit C7 is bad.
 *      136     ECC bit C8 is bad.
 *	137-143 reserved for Mtag Data and ECC.
 *      144(M2) Two bits are bad within a nibble.
 *      145(M3) Three bits are bad within a nibble.
 *      146(M3) Four bits are bad within a nibble.
 *      147(M)  Multiple bits (5 or more) are bad.
 *      148     NO bits are bad.
 * Based on "Cheetah Programmer's Reference Manual" rev 1.1, Tables 11-4,11-5.
 */

#define	C0	128
#define	C1	129
#define	C2	130
#define	C3	131
#define	C4	132
#define	C5	133
#define	C6	134
#define	C7	135
#define	C8	136
#define	MT0	137	/* Mtag Data bit 0 */
#define	MT1	138
#define	MT2	139
#define	MTC0	140	/* Mtag Check bit 0 */
#define	MTC1	141
#define	MTC2	142
#define	MTC3	143
#define	M2	144
#define	M3	145
#define	M4	146
#define	M	147
#define	NA	148
#if defined(JALAPENO) || defined(SERRANO)
#define	S003	149	/* Syndrome 0x003 => likely from CPU/EDU:ST/FRU/BP */
#define	S003MEM	150	/* Syndrome 0x003 => likely from WDU/WBP */
#define	SLAST	S003MEM	/* last special syndrome */
#else /* JALAPENO || SERRANO */
#define	S003	149	/* Syndrome 0x003 => likely from EDU:ST */
#define	S071	150	/* Syndrome 0x071 => likely from WDU/CPU */
#define	S11C	151	/* Syndrome 0x11c => likely from BERR/DBERR */
#define	SLAST	S11C	/* last special syndrome */
#endif /* JALAPENO || SERRANO */
#if defined(JALAPENO) || defined(SERRANO)
#define	BPAR0	152	/* syndrom 152 through 167 for bus parity */
#define	BPAR15	167
#endif	/* JALAPENO || SERRANO */

static uint8_t ecc_syndrome_tab[] =
{
NA,  C0,  C1, S003, C2,  M2,  M3,  47,  C3,  M2,  M2,  53,  M2,  41,  29,   M,
C4,   M,   M,  50,  M2,  38,  25,  M2,  M2,  33,  24,  M2,  11,   M,  M2,  16,
C5,   M,   M,  46,  M2,  37,  19,  M2,   M,  31,  32,   M,   7,  M2,  M2,  10,
M2,  40,  13,  M2,  59,   M,  M2,  66,   M,  M2,  M2,   0,  M2,  67,  71,   M,
C6,   M,   M,  43,   M,  36,  18,   M,  M2,  49,  15,   M,  63,  M2,  M2,   6,
M2,  44,  28,  M2,   M,  M2,  M2,  52,  68,  M2,  M2,  62,  M2,  M3,  M3,  M4,
M2,  26, 106,  M2,  64,   M,  M2,   2, 120,   M,  M2,  M3,   M,  M3,  M3,  M4,
#if defined(JALAPENO) || defined(SERRANO)
116, M2,  M2,  M3,  M2,  M3,   M,  M4,  M2,  58,  54,  M2,   M,  M4,  M4,  M3,
#else	/* JALAPENO || SERRANO */
116, S071, M2,  M3,  M2,  M3,   M,  M4,  M2,  58,  54,  M2,   M,  M4,  M4,  M3,
#endif	/* JALAPENO || SERRANO */
C7,  M2,   M,  42,   M,  35,  17,  M2,   M,  45,  14,  M2,  21,  M2,  M2,   5,
M,   27,   M,   M,  99,   M,   M,   3, 114,  M2,  M2,  20,  M2,  M3,  M3,   M,
M2,  23, 113,  M2, 112,  M2,   M,  51,  95,   M,  M2,  M3,  M2,  M3,  M3,  M2,
103,  M,  M2,  M3,  M2,  M3,  M3,  M4,  M2,  48,   M,   M,  73,  M2,   M,  M3,
M2,  22, 110,  M2, 109,  M2,   M,   9, 108,  M2,   M,  M3,  M2,  M3,  M3,   M,
102, M2,   M,   M,  M2,  M3,  M3,   M,  M2,  M3,  M3,  M2,   M,  M4,   M,  M3,
98,   M,  M2,  M3,  M2,   M,  M3,  M4,  M2,  M3,  M3,  M4,  M3,   M,   M,   M,
M2,  M3,  M3,   M,  M3,   M,   M,   M,  56,  M4,   M,  M3,  M4,   M,   M,   M,
C8,   M,  M2,  39,   M,  34, 105,  M2,   M,  30, 104,   M, 101,   M,   M,   4,
#if defined(JALAPENO) || defined(SERRANO)
M,    M, 100,   M,  83,   M,  M2,  12,  87,   M,   M,  57,  M2,   M,  M3,   M,
#else	/* JALAPENO || SERRANO */
M,    M, 100,   M,  83,   M,  M2,  12,  87,   M,   M,  57, S11C,  M,  M3,   M,
#endif	/* JALAPENO || SERRANO */
M2,  97,  82,  M2,  78,  M2,  M2,   1,  96,   M,   M,   M,   M,   M,  M3,  M2,
94,   M,  M2,  M3,  M2,   M,  M3,   M,  M2,   M,  79,   M,  69,   M,  M4,   M,
M2,  93,  92,   M,  91,   M,  M2,   8,  90,  M2,  M2,   M,   M,   M,   M,  M4,
89,   M,   M,  M3,  M2,  M3,  M3,   M,   M,   M,  M3,  M2,  M3,  M2,   M,  M3,
86,   M,  M2,  M3,  M2,   M,  M3,   M,  M2,   M,  M3,   M,  M3,   M,   M,  M3,
M,    M,  M3,  M2,  M3,  M2,  M4,   M,  60,   M,  M2,  M3,  M4,   M,   M,  M2,
M2,  88,  85,  M2,  84,   M,  M2,  55,  81,  M2,  M2,  M3,  M2,  M3,  M3,  M4,
77,   M,   M,   M,  M2,  M3,   M,   M,  M2,  M3,  M3,  M4,  M3,  M2,   M,   M,
74,   M,  M2,  M3,   M,   M,  M3,   M,   M,   M,  M3,   M,  M3,   M,  M4,  M3,
M2,  70, 107,  M4,  65,  M2,  M2,   M, 127,   M,   M,   M,  M2,  M3,  M3,   M,
80,  M2,  M2,  72,   M, 119, 118,   M,  M2, 126,  76,   M, 125,   M,  M4,  M3,
M2, 115, 124,   M,  75,   M,   M,  M3,  61,   M,  M4,   M,  M4,   M,   M,   M,
M,  123, 122,  M4, 121,  M4,   M,  M3, 117,  M2,  M2,  M3,  M4,  M3,   M,   M,
111,  M,   M,   M,  M4,  M3,  M3,   M,   M,   M,  M3,   M,  M3,  M2,   M,   M
};

#define	ESYND_TBL_SIZE	(sizeof (ecc_syndrome_tab) / sizeof (uint8_t))

#if !(defined(JALAPENO) || defined(SERRANO))
/*
 * This table is used to determine which bit(s) is(are) bad when a Mtag
 * error occurs.  The array is indexed by an 4-bit ECC syndrome. The entries
 * of this array have the following semantics:
 *
 *      -1	Invalid mtag syndrome.
 *      137     Mtag Data 0 is bad.
 *      138     Mtag Data 1 is bad.
 *      139     Mtag Data 2 is bad.
 *      140     Mtag ECC 0 is bad.
 *      141     Mtag ECC 1 is bad.
 *      142     Mtag ECC 2 is bad.
 *      143     Mtag ECC 3 is bad.
 * Based on "Cheetah Programmer's Reference Manual" rev 1.1, Tables 11-6.
 */
short mtag_syndrome_tab[] =
{
NA, MTC0, MTC1, M2, MTC2, M2, M2, MT0, MTC3, M2, M2,  MT1, M2, MT2, M2, M2
};

#define	MSYND_TBL_SIZE	(sizeof (mtag_syndrome_tab) / sizeof (short))

#else /* !(JALAPENO || SERRANO) */

#define	BSYND_TBL_SIZE	16

#endif /* !(JALAPENO || SERRANO) */

/*
 * Virtual Address bit flag in the data cache. This is actually bit 2 in the
 * dcache data tag.
 */
#define	VA13	INT64_C(0x0000000000000002)

/*
 * Types returned from cpu_error_to_resource_type()
 */
#define	ERRTYPE_UNKNOWN		0
#define	ERRTYPE_CPU		1
#define	ERRTYPE_MEMORY		2
#define	ERRTYPE_ECACHE_DATA	3

/*
 * CE initial classification and subsequent action lookup table
 */
static ce_dispact_t ce_disp_table[CE_INITDISPTBL_SIZE];
static int ce_disp_inited;

/*
 * Set to disable leaky and partner check for memory correctables
 */
int ce_xdiag_off;

/*
 * The following are not incremented atomically so are indicative only
 */
static int ce_xdiag_drops;
static int ce_xdiag_lkydrops;
static int ce_xdiag_ptnrdrops;
static int ce_xdiag_bad;

/*
 * CE leaky check callback structure
 */
typedef struct {
	struct async_flt *lkycb_aflt;
	errorq_t *lkycb_eqp;
	errorq_elem_t *lkycb_eqep;
} ce_lkychk_cb_t;

/*
 * defines for various ecache_flush_flag's
 */
#define	ECACHE_FLUSH_LINE	1
#define	ECACHE_FLUSH_ALL	2

/*
 * STICK sync
 */
#define	STICK_ITERATION 10
#define	MAX_TSKEW	1
#define	EV_A_START	0
#define	EV_A_END	1
#define	EV_B_START	2
#define	EV_B_END	3
#define	EVENTS		4

static int64_t stick_iter = STICK_ITERATION;
static int64_t stick_tsk = MAX_TSKEW;

typedef enum {
	EVENT_NULL = 0,
	SLAVE_START,
	SLAVE_CONT,
	MASTER_START
} event_cmd_t;

static volatile event_cmd_t stick_sync_cmd = EVENT_NULL;
static int64_t timestamp[EVENTS];
static volatile int slave_done;

#ifdef DEBUG
#define	DSYNC_ATTEMPTS 64
typedef struct {
	int64_t	skew_val[DSYNC_ATTEMPTS];
} ss_t;

ss_t stick_sync_stats[NCPU];
#endif /* DEBUG */

uint_t cpu_impl_dual_pgsz = 0;
#if defined(CPU_IMP_DUAL_PAGESIZE)
uint_t disable_dual_pgsz = 0;
#endif	/* CPU_IMP_DUAL_PAGESIZE */

/*
 * Save the cache bootup state for use when internal
 * caches are to be re-enabled after an error occurs.
 */
uint64_t cache_boot_state;

/*
 * PA[22:0] represent Displacement in Safari configuration space.
 */
uint_t	root_phys_addr_lo_mask = 0x7fffffu;

bus_config_eclk_t bus_config_eclk[] = {
#if defined(JALAPENO) || defined(SERRANO)
	{JBUS_CONFIG_ECLK_1_DIV, JBUS_CONFIG_ECLK_1},
	{JBUS_CONFIG_ECLK_2_DIV, JBUS_CONFIG_ECLK_2},
	{JBUS_CONFIG_ECLK_32_DIV, JBUS_CONFIG_ECLK_32},
#else /* JALAPENO || SERRANO */
	{SAFARI_CONFIG_ECLK_1_DIV, SAFARI_CONFIG_ECLK_1},
	{SAFARI_CONFIG_ECLK_2_DIV, SAFARI_CONFIG_ECLK_2},
	{SAFARI_CONFIG_ECLK_32_DIV, SAFARI_CONFIG_ECLK_32},
#endif /* JALAPENO || SERRANO */
	{0, 0}
};

/*
 * Interval for deferred CEEN reenable
 */
int cpu_ceen_delay_secs = CPU_CEEN_DELAY_SECS;

/*
 * set in /etc/system to control logging of user BERR/TO's
 */
int cpu_berr_to_verbose = 0;

/*
 * set to 0 in /etc/system to defer CEEN reenable for all CEs
 */
uint64_t cpu_ce_not_deferred = CPU_CE_NOT_DEFERRED;
uint64_t cpu_ce_not_deferred_ext = CPU_CE_NOT_DEFERRED_EXT;

/*
 * Set of all offline cpus
 */
cpuset_t cpu_offline_set;

static void cpu_delayed_check_ce_errors(void *);
static void cpu_check_ce_errors(void *);
void cpu_error_ecache_flush(ch_async_flt_t *);
static int cpu_error_ecache_flush_required(ch_async_flt_t *);
static void cpu_log_and_clear_ce(ch_async_flt_t *);
void cpu_ce_detected(ch_cpu_errors_t *, int);

/*
 * CE Leaky check timeout in microseconds.  This is chosen to be twice the
 * memory refresh interval of current DIMMs (64ms).  After initial fix that
 * gives at least one full refresh cycle in which the cell can leak
 * (whereafter further refreshes simply reinforce any incorrect bit value).
 */
clock_t cpu_ce_lkychk_timeout_usec = 128000;

/*
 * CE partner check partner caching period in seconds
 */
int cpu_ce_ptnr_cachetime_sec = 60;

/*
 * Sets trap table entry ttentry by overwriting eight instructions from ttlabel
 */
#define	CH_SET_TRAP(ttentry, ttlabel)			\
		bcopy((const void *)&ttlabel, &ttentry, 32);		\
		flush_instr_mem((caddr_t)&ttentry, 32);

static int min_ecache_size;
static uint_t priv_hcl_1;
static uint_t priv_hcl_2;
static uint_t priv_hcl_4;
static uint_t priv_hcl_8;

void
cpu_setup(void)
{
	extern int at_flags;
	extern int cpc_has_overflow_intr;

	/*
	 * Setup chip-specific trap handlers.
	 */
	cpu_init_trap();

	cache |= (CACHE_VAC | CACHE_PTAG | CACHE_IOCOHERENT);

	at_flags = EF_SPARC_32PLUS | EF_SPARC_SUN_US1 | EF_SPARC_SUN_US3;

	/*
	 * save the cache bootup state.
	 */
	cache_boot_state = get_dcu() & DCU_CACHE;

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

	/*
	 * On Panther-based machines, this should
	 * also include AV_SPARC_POPC too
	 */
	cpu_hwcap_flags = AV_SPARC_VIS | AV_SPARC_VIS2;

	/*
	 * On cheetah, there's no hole in the virtual address space
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
	kpm_size = (size_t)(8ull * 1024 * 1024 * 1024 * 1024); /* 8TB */
	kpm_size_shift = 43;
	kpm_vbase = (caddr_t)0x8000000000000000ull; /* 8EB */
	kpm_smallpages = 1;

	/*
	 * The traptrace code uses either %tick or %stick for
	 * timestamping.  We have %stick so we can use it.
	 */
	traptrace_use_stick = 1;

	/*
	 * Cheetah has a performance counter overflow interrupt
	 */
	cpc_has_overflow_intr = 1;

#if defined(CPU_IMP_DUAL_PAGESIZE)
	/*
	 * Use Cheetah+ and later dual page size support.
	 */
	if (!disable_dual_pgsz) {
		cpu_impl_dual_pgsz = 1;
	}
#endif	/* CPU_IMP_DUAL_PAGESIZE */

	/*
	 * Declare that this architecture/cpu combination does fpRAS.
	 */
	fpras_implemented = 1;

	/*
	 * Setup CE lookup table
	 */
	CE_INITDISPTBL_POPULATE(ce_disp_table);
	ce_disp_inited = 1;
}

/*
 * Called by setcpudelay
 */
void
cpu_init_tick_freq(void)
{
	/*
	 * For UltraSPARC III and beyond we want to use the
	 * system clock rate as the basis for low level timing,
	 * due to support of mixed speed CPUs and power managment.
	 */
	if (system_clock_freq == 0)
		cmn_err(CE_PANIC, "setcpudelay: invalid system_clock_freq");

	sys_tick_freq = system_clock_freq;
}

#ifdef CHEETAHPLUS_ERRATUM_25
/*
 * Tunables
 */
int cheetah_bpe_off = 0;
int cheetah_sendmondo_recover = 1;
int cheetah_sendmondo_fullscan = 0;
int cheetah_sendmondo_recover_delay = 5;

#define	CHEETAH_LIVELOCK_MIN_DELAY	1

/*
 * Recovery Statistics
 */
typedef struct cheetah_livelock_entry	{
	int cpuid;		/* fallen cpu */
	int buddy;		/* cpu that ran recovery */
	clock_t lbolt;		/* when recovery started */
	hrtime_t recovery_time;	/* time spent in recovery */
} cheetah_livelock_entry_t;

#define	CHEETAH_LIVELOCK_NENTRY	32

cheetah_livelock_entry_t cheetah_livelock_hist[CHEETAH_LIVELOCK_NENTRY];
int cheetah_livelock_entry_nxt;

#define	CHEETAH_LIVELOCK_ENTRY_NEXT(statp)	{			\
	statp = cheetah_livelock_hist + cheetah_livelock_entry_nxt;	\
	if (++cheetah_livelock_entry_nxt >= CHEETAH_LIVELOCK_NENTRY) {	\
		cheetah_livelock_entry_nxt = 0;				\
	}								\
}

#define	CHEETAH_LIVELOCK_ENTRY_SET(statp, item, val)	statp->item = val

struct {
	hrtime_t hrt;		/* maximum recovery time */
	int recovery;		/* recovered */
	int full_claimed;	/* maximum pages claimed in full recovery */
	int proc_entry;		/* attempted to claim TSB */
	int proc_tsb_scan;	/* tsb scanned */
	int proc_tsb_partscan;	/* tsb partially scanned */
	int proc_tsb_fullscan;	/* whole tsb scanned */
	int proc_claimed;	/* maximum pages claimed in tsb scan */
	int proc_user;		/* user thread */
	int proc_kernel;	/* kernel thread */
	int proc_onflt;		/* bad stack */
	int proc_cpu;		/* null cpu */
	int proc_thread;	/* null thread */
	int proc_proc;		/* null proc */
	int proc_as;		/* null as */
	int proc_hat;		/* null hat */
	int proc_hat_inval;	/* hat contents don't make sense */
	int proc_hat_busy;	/* hat is changing TSBs */
	int proc_tsb_reloc;	/* TSB skipped because being relocated */
	int proc_cnum_bad;	/* cnum out of range */
	int proc_cnum;		/* last cnum processed */
	tte_t proc_tte;		/* last tte processed */
} cheetah_livelock_stat;

#define	CHEETAH_LIVELOCK_STAT(item)	cheetah_livelock_stat.item++

#define	CHEETAH_LIVELOCK_STATSET(item, value)		\
	cheetah_livelock_stat.item = value

#define	CHEETAH_LIVELOCK_MAXSTAT(item, value)	{	\
	if (value > cheetah_livelock_stat.item)		\
		cheetah_livelock_stat.item = value;	\
}

/*
 * Attempt to recover a cpu by claiming every cache line as saved
 * in the TSB that the non-responsive cpu is using. Since we can't
 * grab any adaptive lock, this is at best an attempt to do so. Because
 * we don't grab any locks, we must operate under the protection of
 * on_fault().
 *
 * Return 1 if cpuid could be recovered, 0 if failed.
 */
int
mondo_recover_proc(uint16_t cpuid, int bn)
{
	label_t ljb;
	cpu_t *cp;
	kthread_t *t;
	proc_t *p;
	struct as *as;
	struct hat *hat;
	uint_t  cnum;
	struct tsb_info *tsbinfop;
	struct tsbe *tsbep;
	caddr_t tsbp;
	caddr_t end_tsbp;
	uint64_t paddr;
	uint64_t idsr;
	u_longlong_t pahi, palo;
	int pages_claimed = 0;
	tte_t tsbe_tte;
	int tried_kernel_tsb = 0;
	mmu_ctx_t *mmu_ctxp;

	CHEETAH_LIVELOCK_STAT(proc_entry);

	if (on_fault(&ljb)) {
		CHEETAH_LIVELOCK_STAT(proc_onflt);
		goto badstruct;
	}

	if ((cp = cpu[cpuid]) == NULL) {
		CHEETAH_LIVELOCK_STAT(proc_cpu);
		goto badstruct;
	}

	if ((t = cp->cpu_thread) == NULL) {
		CHEETAH_LIVELOCK_STAT(proc_thread);
		goto badstruct;
	}

	if ((p = ttoproc(t)) == NULL) {
		CHEETAH_LIVELOCK_STAT(proc_proc);
		goto badstruct;
	}

	if ((as = p->p_as) == NULL) {
		CHEETAH_LIVELOCK_STAT(proc_as);
		goto badstruct;
	}

	if ((hat = as->a_hat) == NULL) {
		CHEETAH_LIVELOCK_STAT(proc_hat);
		goto badstruct;
	}

	if (hat != ksfmmup) {
		CHEETAH_LIVELOCK_STAT(proc_user);
		if (hat->sfmmu_flags & (HAT_BUSY | HAT_SWAPPED | HAT_SWAPIN)) {
			CHEETAH_LIVELOCK_STAT(proc_hat_busy);
			goto badstruct;
		}
		tsbinfop = hat->sfmmu_tsb;
		if (tsbinfop == NULL) {
			CHEETAH_LIVELOCK_STAT(proc_hat_inval);
			goto badstruct;
		}
		tsbp = tsbinfop->tsb_va;
		end_tsbp = tsbp + TSB_BYTES(tsbinfop->tsb_szc);
	} else {
		CHEETAH_LIVELOCK_STAT(proc_kernel);
		tsbinfop = NULL;
		tsbp = ktsb_base;
		end_tsbp = tsbp + TSB_BYTES(ktsb_sz);
	}

	/* Verify as */
	if (hat->sfmmu_as != as) {
		CHEETAH_LIVELOCK_STAT(proc_hat_inval);
		goto badstruct;
	}

	mmu_ctxp = CPU_MMU_CTXP(cp);
	ASSERT(mmu_ctxp);
	cnum = hat->sfmmu_ctxs[mmu_ctxp->mmu_idx].cnum;
	CHEETAH_LIVELOCK_STATSET(proc_cnum, cnum);

	if ((cnum < 0) || (cnum == INVALID_CONTEXT) ||
	    (cnum >= mmu_ctxp->mmu_nctxs)) {
		CHEETAH_LIVELOCK_STAT(proc_cnum_bad);
		goto badstruct;
	}

	do {
		CHEETAH_LIVELOCK_STAT(proc_tsb_scan);

		/*
		 * Skip TSBs being relocated.  This is important because
		 * we want to avoid the following deadlock scenario:
		 *
		 * 1) when we came in we set ourselves to "in recover" state.
		 * 2) when we try to touch TSB being relocated the mapping
		 *    will be in the suspended state so we'll spin waiting
		 *    for it to be unlocked.
		 * 3) when the CPU that holds the TSB mapping locked tries to
		 *    unlock it it will send a xtrap which will fail to xcall
		 *    us or the CPU we're trying to recover, and will in turn
		 *    enter the mondo code.
		 * 4) since we are still spinning on the locked mapping
		 *    no further progress will be made and the system will
		 *    inevitably hard hang.
		 *
		 * A TSB not being relocated can't begin being relocated
		 * while we're accessing it because we check
		 * sendmondo_in_recover before relocating TSBs.
		 */
		if (hat != ksfmmup &&
		    (tsbinfop->tsb_flags & TSB_RELOC_FLAG) != 0) {
			CHEETAH_LIVELOCK_STAT(proc_tsb_reloc);
			goto next_tsbinfo;
		}

		for (tsbep = (struct tsbe *)tsbp;
		    tsbep < (struct tsbe *)end_tsbp; tsbep++) {
			tsbe_tte = tsbep->tte_data;

			if (tsbe_tte.tte_val == 0) {
				/*
				 * Invalid tte
				 */
				continue;
			}
			if (tsbe_tte.tte_se) {
				/*
				 * Don't want device registers
				 */
				continue;
			}
			if (tsbe_tte.tte_cp == 0) {
				/*
				 * Must be cached in E$
				 */
				continue;
			}
			if (tsbep->tte_tag.tag_invalid != 0) {
				/*
				 * Invalid tag, ingnore this entry.
				 */
				continue;
			}
			CHEETAH_LIVELOCK_STATSET(proc_tte, tsbe_tte);
			idsr = getidsr();
			if ((idsr & (IDSR_NACK_BIT(bn) |
			    IDSR_BUSY_BIT(bn))) == 0) {
				CHEETAH_LIVELOCK_STAT(proc_tsb_partscan);
				goto done;
			}
			pahi = tsbe_tte.tte_pahi;
			palo = tsbe_tte.tte_palo;
			paddr = (uint64_t)((pahi << 32) |
			    (palo << MMU_PAGESHIFT));
			claimlines(paddr, TTEBYTES(TTE_CSZ(&tsbe_tte)),
			    CH_ECACHE_SUBBLK_SIZE);
			if ((idsr & IDSR_BUSY_BIT(bn)) == 0) {
				shipit(cpuid, bn);
			}
			pages_claimed++;
		}
next_tsbinfo:
		if (tsbinfop != NULL)
			tsbinfop = tsbinfop->tsb_next;
		if (tsbinfop != NULL) {
			tsbp = tsbinfop->tsb_va;
			end_tsbp = tsbp + TSB_BYTES(tsbinfop->tsb_szc);
		} else if (tsbp == ktsb_base) {
			tried_kernel_tsb = 1;
		} else if (!tried_kernel_tsb) {
			tsbp = ktsb_base;
			end_tsbp = tsbp + TSB_BYTES(ktsb_sz);
			hat = ksfmmup;
			tsbinfop = NULL;
		}
	} while (tsbinfop != NULL ||
	    ((tsbp == ktsb_base) && !tried_kernel_tsb));

	CHEETAH_LIVELOCK_STAT(proc_tsb_fullscan);
	CHEETAH_LIVELOCK_MAXSTAT(proc_claimed, pages_claimed);
	no_fault();
	idsr = getidsr();
	if ((idsr & (IDSR_NACK_BIT(bn) |
	    IDSR_BUSY_BIT(bn))) == 0) {
		return (1);
	} else {
		return (0);
	}

done:
	no_fault();
	CHEETAH_LIVELOCK_MAXSTAT(proc_claimed, pages_claimed);
	return (1);

badstruct:
	no_fault();
	return (0);
}

/*
 * Attempt to claim ownership, temporarily, of every cache line that a
 * non-responsive cpu might be using.  This might kick that cpu out of
 * this state.
 *
 * The return value indicates to the caller if we have exhausted all recovery
 * techniques. If 1 is returned, it is useless to call this function again
 * even for a different target CPU.
 */
int
mondo_recover(uint16_t cpuid, int bn)
{
	struct memseg *seg;
	uint64_t begin_pa, end_pa, cur_pa;
	hrtime_t begin_hrt, end_hrt;
	int retval = 0;
	int pages_claimed = 0;
	cheetah_livelock_entry_t *histp;
	uint64_t idsr;

	if (atomic_cas_32(&sendmondo_in_recover, 0, 1) != 0) {
		/*
		 * Wait while recovery takes place
		 */
		while (sendmondo_in_recover) {
			drv_usecwait(1);
		}
		/*
		 * Assume we didn't claim the whole memory. If
		 * the target of this caller is not recovered,
		 * it will come back.
		 */
		return (retval);
	}

	CHEETAH_LIVELOCK_ENTRY_NEXT(histp);
	CHEETAH_LIVELOCK_ENTRY_SET(histp, lbolt, LBOLT_WAITFREE);
	CHEETAH_LIVELOCK_ENTRY_SET(histp, cpuid, cpuid);
	CHEETAH_LIVELOCK_ENTRY_SET(histp, buddy, CPU->cpu_id);

	begin_hrt = gethrtime_waitfree();
	/*
	 * First try to claim the lines in the TSB the target
	 * may have been using.
	 */
	if (mondo_recover_proc(cpuid, bn) == 1) {
		/*
		 * Didn't claim the whole memory
		 */
		goto done;
	}

	/*
	 * We tried using the TSB. The target is still
	 * not recovered. Check if complete memory scan is
	 * enabled.
	 */
	if (cheetah_sendmondo_fullscan == 0) {
		/*
		 * Full memory scan is disabled.
		 */
		retval = 1;
		goto done;
	}

	/*
	 * Try claiming the whole memory.
	 */
	for (seg = memsegs; seg; seg = seg->next) {
		begin_pa = (uint64_t)(seg->pages_base) << MMU_PAGESHIFT;
		end_pa = (uint64_t)(seg->pages_end) << MMU_PAGESHIFT;
		for (cur_pa = begin_pa; cur_pa < end_pa;
		    cur_pa += MMU_PAGESIZE) {
			idsr = getidsr();
			if ((idsr & (IDSR_NACK_BIT(bn) |
			    IDSR_BUSY_BIT(bn))) == 0) {
				/*
				 * Didn't claim all memory
				 */
				goto done;
			}
			claimlines(cur_pa, MMU_PAGESIZE,
			    CH_ECACHE_SUBBLK_SIZE);
			if ((idsr & IDSR_BUSY_BIT(bn)) == 0) {
				shipit(cpuid, bn);
			}
			pages_claimed++;
		}
	}

	/*
	 * We did all we could.
	 */
	retval = 1;

done:
	/*
	 * Update statistics
	 */
	end_hrt = gethrtime_waitfree();
	CHEETAH_LIVELOCK_STAT(recovery);
	CHEETAH_LIVELOCK_MAXSTAT(hrt, (end_hrt - begin_hrt));
	CHEETAH_LIVELOCK_MAXSTAT(full_claimed, pages_claimed);
	CHEETAH_LIVELOCK_ENTRY_SET(histp, recovery_time, \
	    (end_hrt -  begin_hrt));

	while (atomic_cas_32(&sendmondo_in_recover, 1, 0) != 1)
		;

	return (retval);
}

/*
 * This is called by the cyclic framework when this CPU becomes online
 */
/*ARGSUSED*/
static void
cheetah_nudge_onln(void *arg, cpu_t *cpu, cyc_handler_t *hdlr, cyc_time_t *when)
{

	hdlr->cyh_func = (cyc_func_t)cheetah_nudge_buddy;
	hdlr->cyh_level = CY_LOW_LEVEL;
	hdlr->cyh_arg = NULL;

	/*
	 * Stagger the start time
	 */
	when->cyt_when = cpu->cpu_id * (NANOSEC / NCPU);
	if (cheetah_sendmondo_recover_delay < CHEETAH_LIVELOCK_MIN_DELAY) {
		cheetah_sendmondo_recover_delay = CHEETAH_LIVELOCK_MIN_DELAY;
	}
	when->cyt_interval = cheetah_sendmondo_recover_delay * NANOSEC;
}

/*
 * Create a low level cyclic to send a xtrap to the next cpu online.
 * However, there's no need to have this running on a uniprocessor system.
 */
static void
cheetah_nudge_init(void)
{
	cyc_omni_handler_t hdlr;

	if (max_ncpus == 1) {
		return;
	}

	hdlr.cyo_online = cheetah_nudge_onln;
	hdlr.cyo_offline = NULL;
	hdlr.cyo_arg = NULL;

	mutex_enter(&cpu_lock);
	(void) cyclic_add_omni(&hdlr);
	mutex_exit(&cpu_lock);
}

/*
 * Cyclic handler to wake up buddy
 */
void
cheetah_nudge_buddy(void)
{
	/*
	 * Disable kernel preemption to protect the cpu list
	 */
	kpreempt_disable();
	if ((CPU->cpu_next_onln != CPU) && (sendmondo_in_recover == 0)) {
		xt_one(CPU->cpu_next_onln->cpu_id, (xcfunc_t *)xt_sync_tl1,
		    0, 0);
	}
	kpreempt_enable();
}

#endif	/* CHEETAHPLUS_ERRATUM_25 */

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
#ifdef	CHEETAHPLUS_ERRATUM_25
	int recovered = 0;
#endif

	CPU_STATS_ADDQ(CPU, sys, xcalls, 1);
	starttick = lasttick = gettick();
	shipit(cpuid, 0);
	endtick = starttick + xc_tick_limit;
	busy = nack = 0;
#if defined(JALAPENO) || defined(SERRANO)
	/*
	 * Lower 2 bits of the agent ID determine which BUSY/NACK pair
	 * will be used for dispatching interrupt. For now, assume
	 * there are no more than IDSR_BN_SETS CPUs, hence no aliasing
	 * issues with respect to BUSY/NACK pair usage.
	 */
	busymask  = IDSR_BUSY_BIT(cpuid);
#else /* JALAPENO || SERRANO */
	busymask = IDSR_BUSY;
#endif /* JALAPENO || SERRANO */
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
			if (cheetah_sendmondo_recover && recovered == 0) {
				if (mondo_recover(cpuid, 0)) {
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
				cmn_err(CE_PANIC, "send mondo timeout "
				    "(target 0x%x) [%d NACK %d BUSY]",
				    cpuid, nack, busy);
			}
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

void
syncfpu(void)
{
}

/*
 * Return processor specific async error structure
 * size used.
 */
int
cpu_aflt_size(void)
{
	return (sizeof (ch_async_flt_t));
}

/*
 * Tunable to disable the checking of other cpu logout areas during panic for
 * potential syndrome 71 generating errors.
 */
int enable_check_other_cpus_logout = 1;

/*
 * Check other cpus logout area for potential synd 71 generating
 * errors.
 */
static void
cpu_check_cpu_logout(int cpuid, caddr_t tpc, int tl, int ecc_type,
    ch_cpu_logout_t *clop)
{
	struct async_flt *aflt;
	ch_async_flt_t ch_flt;
	uint64_t t_afar, t_afsr, t_afsr_ext, t_afsr_errs;

	if (clop == NULL || clop->clo_data.chd_afar == LOGOUT_INVALID) {
		return;
	}

	bzero(&ch_flt, sizeof (ch_async_flt_t));

	t_afar = clop->clo_data.chd_afar;
	t_afsr = clop->clo_data.chd_afsr;
	t_afsr_ext = clop->clo_data.chd_afsr_ext;
#if defined(SERRANO)
	ch_flt.afar2 = clop->clo_data.chd_afar2;
#endif	/* SERRANO */

	/*
	 * In order to simplify code, we maintain this afsr_errs
	 * variable which holds the aggregate of AFSR and AFSR_EXT
	 * sticky bits.
	 */
	t_afsr_errs = (t_afsr_ext & C_AFSR_EXT_ALL_ERRS) |
	    (t_afsr & C_AFSR_ALL_ERRS);

	/* Setup the async fault structure */
	aflt = (struct async_flt *)&ch_flt;
	aflt->flt_id = gethrtime_waitfree();
	ch_flt.afsr_ext = t_afsr_ext;
	ch_flt.afsr_errs = t_afsr_errs;
	aflt->flt_stat = t_afsr;
	aflt->flt_addr = t_afar;
	aflt->flt_bus_id = cpuid;
	aflt->flt_inst = cpuid;
	aflt->flt_pc = tpc;
	aflt->flt_prot = AFLT_PROT_NONE;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_priv = ((t_afsr & C_AFSR_PRIV) != 0);
	aflt->flt_tl = tl;
	aflt->flt_status = ecc_type;
	aflt->flt_panic = C_AFSR_PANIC(t_afsr_errs);

	/*
	 * Queue events on the async event queue, one event per error bit.
	 * If no events are queued, queue an event to complain.
	 */
	if (cpu_queue_events(&ch_flt, NULL, t_afsr_errs, clop) == 0) {
		ch_flt.flt_type = CPU_INV_AFSR;
		cpu_errorq_dispatch(FM_EREPORT_CPU_USIII_INVALID_AFSR,
		    (void *)&ch_flt, sizeof (ch_async_flt_t), ue_queue,
		    aflt->flt_panic);
	}

	/*
	 * Zero out + invalidate CPU logout.
	 */
	bzero(clop, sizeof (ch_cpu_logout_t));
	clop->clo_data.chd_afar = LOGOUT_INVALID;
}

/*
 * Check the logout areas of all other cpus for unlogged errors.
 */
static void
cpu_check_other_cpus_logout(void)
{
	int i, j;
	processorid_t myid;
	struct cpu *cp;
	ch_err_tl1_data_t *cl1p;

	myid = CPU->cpu_id;
	for (i = 0; i < NCPU; i++) {
		cp = cpu[i];

		if ((cp == NULL) || !(cp->cpu_flags & CPU_EXISTS) ||
		    (cp->cpu_id == myid) || (CPU_PRIVATE(cp) == NULL)) {
			continue;
		}

		/*
		 * Check each of the tl>0 logout areas
		 */
		cl1p = CPU_PRIVATE_PTR(cp, chpr_tl1_err_data[0]);
		for (j = 0; j < CH_ERR_TL1_TLMAX; j++, cl1p++) {
			if (cl1p->ch_err_tl1_flags == 0)
				continue;

			cpu_check_cpu_logout(i, (caddr_t)cl1p->ch_err_tl1_tpc,
			    1, ECC_F_TRAP, &cl1p->ch_err_tl1_logout);
		}

		/*
		 * Check each of the remaining logout areas
		 */
		cpu_check_cpu_logout(i, NULL, 0, ECC_F_TRAP,
		    CPU_PRIVATE_PTR(cp, chpr_fecctl0_logout));
		cpu_check_cpu_logout(i, NULL, 0, ECC_C_TRAP,
		    CPU_PRIVATE_PTR(cp, chpr_cecc_logout));
		cpu_check_cpu_logout(i, NULL, 0, ECC_D_TRAP,
		    CPU_PRIVATE_PTR(cp, chpr_async_logout));
	}
}

/*
 * The fast_ecc_err handler transfers control here for UCU, UCC events.
 * Note that we flush Ecache twice, once in the fast_ecc_err handler to
 * flush the error that caused the UCU/UCC, then again here at the end to
 * flush the TL=1 trap handler code out of the Ecache, so we can minimize
 * the probability of getting a TL>1 Fast ECC trap when we're fielding
 * another Fast ECC trap.
 *
 * Cheetah+ also handles: TSCE: No additional processing required.
 * Panther adds L3_UCU and L3_UCC which are reported in AFSR_EXT.
 *
 * Note that the p_clo_flags input is only valid in cases where the
 * cpu_private struct is not yet initialized (since that is the only
 * time that information cannot be obtained from the logout struct.)
 */
/*ARGSUSED*/
void
cpu_fast_ecc_error(struct regs *rp, ulong_t p_clo_flags)
{
	ch_cpu_logout_t *clop;
	uint64_t ceen, nceen;

	/*
	 * Get the CPU log out info. If we can't find our CPU private
	 * pointer, then we will have to make due without any detailed
	 * logout information.
	 */
	if (CPU_PRIVATE(CPU) == NULL) {
		clop = NULL;
		ceen = p_clo_flags & EN_REG_CEEN;
		nceen = p_clo_flags & EN_REG_NCEEN;
	} else {
		clop = CPU_PRIVATE_PTR(CPU, chpr_fecctl0_logout);
		ceen = clop->clo_flags & EN_REG_CEEN;
		nceen = clop->clo_flags & EN_REG_NCEEN;
	}

	cpu_log_fast_ecc_error((caddr_t)rp->r_pc,
	    (rp->r_tstate & TSTATE_PRIV) ? 1 : 0, 0, ceen, nceen, clop);
}

/*
 * Log fast ecc error, called from either Fast ECC at TL=0 or Fast
 * ECC at TL>0.  Need to supply either a error register pointer or a
 * cpu logout structure pointer.
 */
static void
cpu_log_fast_ecc_error(caddr_t tpc, int priv, int tl, uint64_t ceen,
    uint64_t nceen, ch_cpu_logout_t *clop)
{
	struct async_flt *aflt;
	ch_async_flt_t ch_flt;
	uint64_t t_afar, t_afsr, t_afsr_ext, t_afsr_errs;
	char pr_reason[MAX_REASON_STRING];
	ch_cpu_errors_t cpu_error_regs;

	bzero(&ch_flt, sizeof (ch_async_flt_t));
	/*
	 * If no cpu logout data, then we will have to make due without
	 * any detailed logout information.
	 */
	if (clop == NULL) {
		ch_flt.flt_diag_data.chd_afar = LOGOUT_INVALID;
		get_cpu_error_state(&cpu_error_regs);
		set_cpu_error_state(&cpu_error_regs);
		t_afar = cpu_error_regs.afar;
		t_afsr = cpu_error_regs.afsr;
		t_afsr_ext = cpu_error_regs.afsr_ext;
#if defined(SERRANO)
		ch_flt.afar2 = cpu_error_regs.afar2;
#endif	/* SERRANO */
	} else {
		t_afar = clop->clo_data.chd_afar;
		t_afsr = clop->clo_data.chd_afsr;
		t_afsr_ext = clop->clo_data.chd_afsr_ext;
#if defined(SERRANO)
		ch_flt.afar2 = clop->clo_data.chd_afar2;
#endif	/* SERRANO */
	}

	/*
	 * In order to simplify code, we maintain this afsr_errs
	 * variable which holds the aggregate of AFSR and AFSR_EXT
	 * sticky bits.
	 */
	t_afsr_errs = (t_afsr_ext & C_AFSR_EXT_ALL_ERRS) |
	    (t_afsr & C_AFSR_ALL_ERRS);
	pr_reason[0] = '\0';

	/* Setup the async fault structure */
	aflt = (struct async_flt *)&ch_flt;
	aflt->flt_id = gethrtime_waitfree();
	ch_flt.afsr_ext = t_afsr_ext;
	ch_flt.afsr_errs = t_afsr_errs;
	aflt->flt_stat = t_afsr;
	aflt->flt_addr = t_afar;
	aflt->flt_bus_id = getprocessorid();
	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_pc = tpc;
	aflt->flt_prot = AFLT_PROT_NONE;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_priv = priv;
	aflt->flt_tl = tl;
	aflt->flt_status = ECC_F_TRAP;
	aflt->flt_panic = C_AFSR_PANIC(t_afsr_errs);

	/*
	 * XXXX - Phenomenal hack to get around Solaris not getting all the
	 * cmn_err messages out to the console.  The situation is a UCU (in
	 * priv mode) which causes a WDU which causes a UE (on the retry).
	 * The messages for the UCU and WDU are enqueued and then pulled off
	 * the async queue via softint and syslogd starts to process them
	 * but doesn't get them to the console.  The UE causes a panic, but
	 * since the UCU/WDU messages are already in transit, those aren't
	 * on the async queue.  The hack is to check if we have a matching
	 * WDU event for the UCU, and if it matches, we're more than likely
	 * going to panic with a UE, unless we're under protection.  So, we
	 * check to see if we got a matching WDU event and if we're under
	 * protection.
	 *
	 * For Cheetah/Cheetah+/Jaguar/Jalapeno, the sequence we care about
	 * looks like this:
	 *    UCU->WDU->UE
	 * For Panther, it could look like either of these:
	 *    UCU---->WDU->L3_WDU->UE
	 *    L3_UCU->WDU->L3_WDU->UE
	 */
	if ((t_afsr_errs & (C_AFSR_UCU | C_AFSR_L3_UCU)) &&
	    aflt->flt_panic == 0 && aflt->flt_priv != 0 &&
	    curthread->t_ontrap == NULL && curthread->t_lofault == NULL) {
		get_cpu_error_state(&cpu_error_regs);
		if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
			aflt->flt_panic |=
			    ((cpu_error_regs.afsr & C_AFSR_WDU) &&
			    (cpu_error_regs.afsr_ext & C_AFSR_L3_WDU) &&
			    (cpu_error_regs.afar == t_afar));
			aflt->flt_panic |= ((clop == NULL) &&
			    (t_afsr_errs & C_AFSR_WDU) &&
			    (t_afsr_errs & C_AFSR_L3_WDU));
		} else {
			aflt->flt_panic |=
			    ((cpu_error_regs.afsr & C_AFSR_WDU) &&
			    (cpu_error_regs.afar == t_afar));
			aflt->flt_panic |= ((clop == NULL) &&
			    (t_afsr_errs & C_AFSR_WDU));
		}
	}

	/*
	 * Queue events on the async event queue, one event per error bit.
	 * If no events are queued or no Fast ECC events are on in the AFSR,
	 * queue an event to complain.
	 */
	if (cpu_queue_events(&ch_flt, pr_reason, t_afsr_errs, clop) == 0 ||
	    ((t_afsr_errs & (C_AFSR_FECC_ERRS | C_AFSR_EXT_FECC_ERRS)) == 0)) {
		ch_flt.flt_type = CPU_INV_AFSR;
		cpu_errorq_dispatch(FM_EREPORT_CPU_USIII_INVALID_AFSR,
		    (void *)&ch_flt, sizeof (ch_async_flt_t), ue_queue,
		    aflt->flt_panic);
	}

	/*
	 * Zero out + invalidate CPU logout.
	 */
	if (clop) {
		bzero(clop, sizeof (ch_cpu_logout_t));
		clop->clo_data.chd_afar = LOGOUT_INVALID;
	}

	/*
	 * We carefully re-enable NCEEN and CEEN and then check if any deferred
	 * or disrupting errors have happened.  We do this because if a
	 * deferred or disrupting error had occurred with NCEEN/CEEN off, the
	 * trap will not be taken when NCEEN/CEEN is re-enabled.  Note that
	 * CEEN works differently on Cheetah than on Spitfire.  Also, we enable
	 * NCEEN/CEEN *before* checking the AFSR to avoid the small window of a
	 * deferred or disrupting error happening between checking the AFSR and
	 * enabling NCEEN/CEEN.
	 *
	 * Note: CEEN and NCEEN are only reenabled if they were on when trap
	 * taken.
	 */
	set_error_enable(get_error_enable() | (nceen | ceen));
	if (clear_errors(&ch_flt)) {
		aflt->flt_panic |= ((ch_flt.afsr_errs &
		    (C_AFSR_EXT_ASYNC_ERRS | C_AFSR_ASYNC_ERRS)) != 0);
		(void) cpu_queue_events(&ch_flt, pr_reason, ch_flt.afsr_errs,
		    NULL);
	}

	/*
	 * Panic here if aflt->flt_panic has been set.  Enqueued errors will
	 * be logged as part of the panic flow.
	 */
	if (aflt->flt_panic)
		fm_panic("%sError(s)", pr_reason);

	/*
	 * Flushing the Ecache here gets the part of the trap handler that
	 * is run at TL=1 out of the Ecache.
	 */
	cpu_flush_ecache();
}

/*
 * This is called via sys_trap from pil15_interrupt code if the
 * corresponding entry in ch_err_tl1_pending is set.  Checks the
 * various ch_err_tl1_data structures for valid entries based on the bit
 * settings in the ch_err_tl1_flags entry of the structure.
 */
/*ARGSUSED*/
void
cpu_tl1_error(struct regs *rp, int panic)
{
	ch_err_tl1_data_t *cl1p, cl1;
	int i, ncl1ps;
	uint64_t me_flags;
	uint64_t ceen, nceen;

	if (ch_err_tl1_paddrs[CPU->cpu_id] == 0) {
		cl1p = &ch_err_tl1_data;
		ncl1ps = 1;
	} else if (CPU_PRIVATE(CPU) != NULL) {
		cl1p = CPU_PRIVATE_PTR(CPU, chpr_tl1_err_data[0]);
		ncl1ps = CH_ERR_TL1_TLMAX;
	} else {
		ncl1ps = 0;
	}

	for (i = 0; i < ncl1ps; i++, cl1p++) {
		if (cl1p->ch_err_tl1_flags == 0)
			continue;

		/*
		 * Grab a copy of the logout data and invalidate
		 * the logout area.
		 */
		cl1 = *cl1p;
		bzero(cl1p, sizeof (ch_err_tl1_data_t));
		cl1p->ch_err_tl1_logout.clo_data.chd_afar = LOGOUT_INVALID;
		me_flags = CH_ERR_ME_FLAGS(cl1.ch_err_tl1_flags);

		/*
		 * Log "first error" in ch_err_tl1_data.
		 */
		if (cl1.ch_err_tl1_flags & CH_ERR_FECC) {
			ceen = get_error_enable() & EN_REG_CEEN;
			nceen = get_error_enable() & EN_REG_NCEEN;
			cpu_log_fast_ecc_error((caddr_t)cl1.ch_err_tl1_tpc, 1,
			    1, ceen, nceen, &cl1.ch_err_tl1_logout);
		}
#if defined(CPU_IMP_L1_CACHE_PARITY)
		if (cl1.ch_err_tl1_flags & (CH_ERR_IPE | CH_ERR_DPE)) {
			cpu_parity_error(rp, cl1.ch_err_tl1_flags,
			    (caddr_t)cl1.ch_err_tl1_tpc);
		}
#endif	/* CPU_IMP_L1_CACHE_PARITY */

		/*
		 * Log "multiple events" in ch_err_tl1_data.  Note that
		 * we don't read and clear the AFSR/AFAR in the TL>0 code
		 * if the structure is busy, we just do the cache flushing
		 * we have to do and then do the retry.  So the AFSR/AFAR
		 * at this point *should* have some relevant info.  If there
		 * are no valid errors in the AFSR, we'll assume they've
		 * already been picked up and logged.  For I$/D$ parity,
		 * we just log an event with an "Unknown" (NULL) TPC.
		 */
		if (me_flags & CH_ERR_FECC) {
			ch_cpu_errors_t cpu_error_regs;
			uint64_t t_afsr_errs;

			/*
			 * Get the error registers and see if there's
			 * a pending error.  If not, don't bother
			 * generating an "Invalid AFSR" error event.
			 */
			get_cpu_error_state(&cpu_error_regs);
			t_afsr_errs = (cpu_error_regs.afsr_ext &
			    C_AFSR_EXT_ALL_ERRS) |
			    (cpu_error_regs.afsr & C_AFSR_ALL_ERRS);
			if (t_afsr_errs != 0) {
				ceen = get_error_enable() & EN_REG_CEEN;
				nceen = get_error_enable() & EN_REG_NCEEN;
				cpu_log_fast_ecc_error((caddr_t)NULL, 1,
				    1, ceen, nceen, NULL);
			}
		}
#if defined(CPU_IMP_L1_CACHE_PARITY)
		if (me_flags & (CH_ERR_IPE | CH_ERR_DPE)) {
			cpu_parity_error(rp, me_flags, (caddr_t)NULL);
		}
#endif	/* CPU_IMP_L1_CACHE_PARITY */
	}
}

/*
 * Called from Fast ECC TL>0 handler in case of fatal error.
 * cpu_tl1_error should always find an associated ch_err_tl1_data structure,
 * but if we don't, we'll panic with something reasonable.
 */
/*ARGSUSED*/
void
cpu_tl1_err_panic(struct regs *rp, ulong_t flags)
{
	cpu_tl1_error(rp, 1);
	/*
	 * Should never return, but just in case.
	 */
	fm_panic("Unsurvivable ECC Error at TL>0");
}

/*
 * The ce_err/ce_err_tl1 handlers transfer control here for CE, EMC, EDU:ST,
 * EDC, WDU, WDC, CPU, CPC, IVU, IVC events.
 * Disrupting errors controlled by NCEEN: EDU:ST, WDU, CPU, IVU
 * Disrupting errors controlled by CEEN: CE, EMC, EDC, WDC, CPC, IVC
 *
 * Cheetah+ also handles (No additional processing required):
 *    DUE, DTO, DBERR	(NCEEN controlled)
 *    THCE		(CEEN and ET_ECC_en controlled)
 *    TUE		(ET_ECC_en controlled)
 *
 * Panther further adds:
 *    IMU, L3_EDU, L3_WDU, L3_CPU		(NCEEN controlled)
 *    IMC, L3_EDC, L3_WDC, L3_CPC, L3_THCE	(CEEN controlled)
 *    TUE_SH, TUE		(NCEEN and L2_tag_ECC_en controlled)
 *    L3_TUE, L3_TUE_SH		(NCEEN and ET_ECC_en controlled)
 *    THCE			(CEEN and L2_tag_ECC_en controlled)
 *    L3_THCE			(CEEN and ET_ECC_en controlled)
 *
 * Note that the p_clo_flags input is only valid in cases where the
 * cpu_private struct is not yet initialized (since that is the only
 * time that information cannot be obtained from the logout struct.)
 */
/*ARGSUSED*/
void
cpu_disrupting_error(struct regs *rp, ulong_t p_clo_flags)
{
	struct async_flt *aflt;
	ch_async_flt_t ch_flt;
	char pr_reason[MAX_REASON_STRING];
	ch_cpu_logout_t *clop;
	uint64_t t_afar, t_afsr, t_afsr_ext, t_afsr_errs;
	ch_cpu_errors_t cpu_error_regs;

	bzero(&ch_flt, sizeof (ch_async_flt_t));
	/*
	 * Get the CPU log out info. If we can't find our CPU private
	 * pointer, then we will have to make due without any detailed
	 * logout information.
	 */
	if (CPU_PRIVATE(CPU) == NULL) {
		clop = NULL;
		ch_flt.flt_diag_data.chd_afar = LOGOUT_INVALID;
		get_cpu_error_state(&cpu_error_regs);
		set_cpu_error_state(&cpu_error_regs);
		t_afar = cpu_error_regs.afar;
		t_afsr = cpu_error_regs.afsr;
		t_afsr_ext = cpu_error_regs.afsr_ext;
#if defined(SERRANO)
		ch_flt.afar2 = cpu_error_regs.afar2;
#endif	/* SERRANO */
	} else {
		clop = CPU_PRIVATE_PTR(CPU, chpr_cecc_logout);
		t_afar = clop->clo_data.chd_afar;
		t_afsr = clop->clo_data.chd_afsr;
		t_afsr_ext = clop->clo_data.chd_afsr_ext;
#if defined(SERRANO)
		ch_flt.afar2 = clop->clo_data.chd_afar2;
#endif	/* SERRANO */
	}

	/*
	 * In order to simplify code, we maintain this afsr_errs
	 * variable which holds the aggregate of AFSR and AFSR_EXT
	 * sticky bits.
	 */
	t_afsr_errs = (t_afsr_ext & C_AFSR_EXT_ALL_ERRS) |
	    (t_afsr & C_AFSR_ALL_ERRS);

	pr_reason[0] = '\0';
	/* Setup the async fault structure */
	aflt = (struct async_flt *)&ch_flt;
	ch_flt.afsr_ext = t_afsr_ext;
	ch_flt.afsr_errs = t_afsr_errs;
	aflt->flt_stat = t_afsr;
	aflt->flt_addr = t_afar;
	aflt->flt_pc = (caddr_t)rp->r_pc;
	aflt->flt_priv = (rp->r_tstate & TSTATE_PRIV) ?  1 : 0;
	aflt->flt_tl = 0;
	aflt->flt_panic = C_AFSR_PANIC(t_afsr_errs);

	/*
	 * If this trap is a result of one of the errors not masked
	 * by cpu_ce_not_deferred, we don't reenable CEEN. Instead
	 * indicate that a timeout is to be set later.
	 */
	if (!(t_afsr_errs & (cpu_ce_not_deferred | cpu_ce_not_deferred_ext)) &&
	    !aflt->flt_panic)
		ch_flt.flt_trapped_ce = CE_CEEN_DEFER | CE_CEEN_TRAPPED;
	else
		ch_flt.flt_trapped_ce = CE_CEEN_NODEFER | CE_CEEN_TRAPPED;

	/*
	 * log the CE and clean up
	 */
	cpu_log_and_clear_ce(&ch_flt);

	/*
	 * We re-enable CEEN (if required) and check if any disrupting errors
	 * have happened.  We do this because if a disrupting error had occurred
	 * with CEEN off, the trap will not be taken when CEEN is re-enabled.
	 * Note that CEEN works differently on Cheetah than on Spitfire.  Also,
	 * we enable CEEN *before* checking the AFSR to avoid the small window
	 * of a error happening between checking the AFSR and enabling CEEN.
	 */
	if (ch_flt.flt_trapped_ce & CE_CEEN_NODEFER)
		set_error_enable(get_error_enable() | EN_REG_CEEN);
	if (clear_errors(&ch_flt)) {
		(void) cpu_queue_events(&ch_flt, pr_reason, ch_flt.afsr_errs,
		    NULL);
	}

	/*
	 * Panic here if aflt->flt_panic has been set.  Enqueued errors will
	 * be logged as part of the panic flow.
	 */
	if (aflt->flt_panic)
		fm_panic("%sError(s)", pr_reason);
}

/*
 * The async_err handler transfers control here for UE, EMU, EDU:BLD,
 * L3_EDU:BLD, TO, and BERR events.
 * Deferred errors controlled by NCEEN: UE, EMU, EDU:BLD, L3_EDU:BLD, TO, BERR
 *
 * Cheetah+: No additional errors handled.
 *
 * Note that the p_clo_flags input is only valid in cases where the
 * cpu_private struct is not yet initialized (since that is the only
 * time that information cannot be obtained from the logout struct.)
 */
/*ARGSUSED*/
void
cpu_deferred_error(struct regs *rp, ulong_t p_clo_flags)
{
	ushort_t ttype, tl;
	ch_async_flt_t ch_flt;
	struct async_flt *aflt;
	int trampolined = 0;
	char pr_reason[MAX_REASON_STRING];
	ch_cpu_logout_t *clop;
	uint64_t ceen, clo_flags;
	uint64_t log_afsr;
	uint64_t t_afar, t_afsr, t_afsr_ext, t_afsr_errs;
	ch_cpu_errors_t cpu_error_regs;
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

	bzero(&ch_flt, sizeof (ch_async_flt_t));
	/*
	 * Get the CPU log out info. If we can't find our CPU private
	 * pointer then we will have to make due without any detailed
	 * logout information.
	 */
	if (CPU_PRIVATE(CPU) == NULL) {
		clop = NULL;
		ch_flt.flt_diag_data.chd_afar = LOGOUT_INVALID;
		get_cpu_error_state(&cpu_error_regs);
		set_cpu_error_state(&cpu_error_regs);
		t_afar = cpu_error_regs.afar;
		t_afsr = cpu_error_regs.afsr;
		t_afsr_ext = cpu_error_regs.afsr_ext;
#if defined(SERRANO)
		ch_flt.afar2 = cpu_error_regs.afar2;
#endif	/* SERRANO */
		clo_flags = p_clo_flags;
	} else {
		clop = CPU_PRIVATE_PTR(CPU, chpr_async_logout);
		t_afar = clop->clo_data.chd_afar;
		t_afsr = clop->clo_data.chd_afsr;
		t_afsr_ext = clop->clo_data.chd_afsr_ext;
#if defined(SERRANO)
		ch_flt.afar2 = clop->clo_data.chd_afar2;
#endif	/* SERRANO */
		clo_flags = clop->clo_flags;
	}

	/*
	 * In order to simplify code, we maintain this afsr_errs
	 * variable which holds the aggregate of AFSR and AFSR_EXT
	 * sticky bits.
	 */
	t_afsr_errs = (t_afsr_ext & C_AFSR_EXT_ALL_ERRS) |
	    (t_afsr & C_AFSR_ALL_ERRS);
	pr_reason[0] = '\0';

	/*
	 * Grab information encoded into our clo_flags field.
	 */
	ceen = clo_flags & EN_REG_CEEN;
	tl = (clo_flags & CLO_FLAGS_TL_MASK) >> CLO_FLAGS_TL_SHIFT;
	ttype = (clo_flags & CLO_FLAGS_TT_MASK) >> CLO_FLAGS_TT_SHIFT;

	/*
	 * handle the specific error
	 */
	aflt = (struct async_flt *)&ch_flt;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_bus_id = getprocessorid();
	aflt->flt_inst = CPU->cpu_id;
	ch_flt.afsr_ext = t_afsr_ext;
	ch_flt.afsr_errs = t_afsr_errs;
	aflt->flt_stat = t_afsr;
	aflt->flt_addr = t_afar;
	aflt->flt_pc = (caddr_t)rp->r_pc;
	aflt->flt_prot = AFLT_PROT_NONE;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_priv = (rp->r_tstate & TSTATE_PRIV) ?  1 : 0;
	aflt->flt_tl = (uchar_t)tl;
	aflt->flt_panic = ((tl != 0) || (aft_testfatal != 0) ||
	    C_AFSR_PANIC(t_afsr_errs));
	aflt->flt_core = (pflag & SDOCORE) ? 1 : 0;
	aflt->flt_status = ((ttype == T_DATA_ERROR) ? ECC_D_TRAP : ECC_I_TRAP);

	/*
	 * If the trap occurred in privileged mode at TL=0, we need to check to
	 * see if we were executing in the kernel under on_trap() or t_lofault
	 * protection.  If so, modify the saved registers so that we return
	 * from the trap to the appropriate trampoline routine.
	 */
	if (aflt->flt_priv && tl == 0) {
		if (curthread->t_ontrap != NULL) {
			on_trap_data_t *otp = curthread->t_ontrap;

			if (otp->ot_prot & OT_DATA_EC) {
				aflt->flt_prot = AFLT_PROT_EC;
				otp->ot_trap |= OT_DATA_EC;
				rp->r_pc = otp->ot_trampoline;
				rp->r_npc = rp->r_pc + 4;
				trampolined = 1;
			}

			if ((t_afsr & (C_AFSR_TO | C_AFSR_BERR)) &&
			    (otp->ot_prot & OT_DATA_ACCESS)) {
				aflt->flt_prot = AFLT_PROT_ACCESS;
				otp->ot_trap |= OT_DATA_ACCESS;
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
		if (t_afsr_errs &
		    ((C_AFSR_ASYNC_ERRS | C_AFSR_EXT_ASYNC_ERRS) &
		    ~(C_AFSR_BERR | C_AFSR_TO)))
			aflt->flt_panic |= aft_panic;
	} else if (!trampolined) {
			aflt->flt_panic = 1;
	}

	/*
	 * If we've trampolined due to a privileged TO or BERR, or if an
	 * unprivileged TO or BERR occurred, we don't want to enqueue an
	 * event for that TO or BERR.  Queue all other events (if any) besides
	 * the TO/BERR.  Since we may not be enqueing any events, we need to
	 * ignore the number of events queued.  If we haven't trampolined due
	 * to a TO or BERR, just enqueue events normally.
	 */
	log_afsr = t_afsr_errs;
	if (trampolined) {
		log_afsr &= ~(C_AFSR_TO | C_AFSR_BERR);
	} else if (!aflt->flt_priv) {
		/*
		 * User mode, suppress messages if
		 * cpu_berr_to_verbose is not set.
		 */
		if (!cpu_berr_to_verbose)
			log_afsr &= ~(C_AFSR_TO | C_AFSR_BERR);
	}

	/*
	 * Log any errors that occurred
	 */
	if (((log_afsr &
	    ((C_AFSR_ALL_ERRS | C_AFSR_EXT_ALL_ERRS) & ~C_AFSR_ME)) &&
	    cpu_queue_events(&ch_flt, pr_reason, log_afsr, clop) == 0) ||
	    (t_afsr_errs & (C_AFSR_ASYNC_ERRS | C_AFSR_EXT_ASYNC_ERRS)) == 0) {
		ch_flt.flt_type = CPU_INV_AFSR;
		cpu_errorq_dispatch(FM_EREPORT_CPU_USIII_INVALID_AFSR,
		    (void *)&ch_flt, sizeof (ch_async_flt_t), ue_queue,
		    aflt->flt_panic);
	}

	/*
	 * Zero out + invalidate CPU logout.
	 */
	if (clop) {
		bzero(clop, sizeof (ch_cpu_logout_t));
		clop->clo_data.chd_afar = LOGOUT_INVALID;
	}

#if defined(JALAPENO) || defined(SERRANO)
	/*
	 * UE/RUE/BERR/TO: Call our bus nexus friends to check for
	 * IO errors that may have resulted in this trap.
	 */
	if (t_afsr & (C_AFSR_UE|C_AFSR_RUE|C_AFSR_TO|C_AFSR_BERR)) {
		cpu_run_bus_error_handlers(aflt, expected);
	}

	/*
	 * UE/RUE: If UE or RUE is in memory, we need to flush the bad
	 * line from the Ecache.  We also need to query the bus nexus for
	 * fatal errors.  Attempts to do diagnostic read on caches may
	 * introduce more errors (especially when the module is bad).
	 */
	if (t_afsr & (C_AFSR_UE|C_AFSR_RUE)) {
		/*
		 * Ask our bus nexus friends if they have any fatal errors.  If
		 * so, they will log appropriate error messages.
		 */
		if (bus_func_invoke(BF_TYPE_UE) == BF_FATAL)
			aflt->flt_panic = 1;

		/*
		 * We got a UE or RUE and are panicking, save the fault PA in
		 * a known location so that the platform specific panic code
		 * can check for copyback errors.
		 */
		if (aflt->flt_panic && cpu_flt_in_memory(&ch_flt, C_AFSR_UE)) {
			panic_aflt = *aflt;
		}
	}

	/*
	 * Flush Ecache line or entire Ecache
	 */
	if (t_afsr & (C_AFSR_UE | C_AFSR_RUE | C_AFSR_EDU | C_AFSR_BERR))
		cpu_error_ecache_flush(&ch_flt);
#else /* JALAPENO || SERRANO */
	/*
	 * UE/BERR/TO: Call our bus nexus friends to check for
	 * IO errors that may have resulted in this trap.
	 */
	if (t_afsr & (C_AFSR_UE|C_AFSR_TO|C_AFSR_BERR)) {
		cpu_run_bus_error_handlers(aflt, expected);
	}

	/*
	 * UE: If the UE is in memory, we need to flush the bad
	 * line from the Ecache.  We also need to query the bus nexus for
	 * fatal errors.  Attempts to do diagnostic read on caches may
	 * introduce more errors (especially when the module is bad).
	 */
	if (t_afsr & C_AFSR_UE) {
		/*
		 * Ask our legacy bus nexus friends if they have any fatal
		 * errors.  If so, they will log appropriate error messages.
		 */
		if (bus_func_invoke(BF_TYPE_UE) == BF_FATAL)
			aflt->flt_panic = 1;

		/*
		 * We got a UE and are panicking, save the fault PA in a known
		 * location so that the platform specific panic code can check
		 * for copyback errors.
		 */
		if (aflt->flt_panic && cpu_flt_in_memory(&ch_flt, C_AFSR_UE)) {
			panic_aflt = *aflt;
		}
	}

	/*
	 * Flush Ecache line or entire Ecache
	 */
	if (t_afsr_errs &
	    (C_AFSR_UE | C_AFSR_EDU | C_AFSR_BERR | C_AFSR_L3_EDU))
		cpu_error_ecache_flush(&ch_flt);
#endif /* JALAPENO || SERRANO */

	/*
	 * We carefully re-enable NCEEN and CEEN and then check if any deferred
	 * or disrupting errors have happened.  We do this because if a
	 * deferred or disrupting error had occurred with NCEEN/CEEN off, the
	 * trap will not be taken when NCEEN/CEEN is re-enabled.  Note that
	 * CEEN works differently on Cheetah than on Spitfire.  Also, we enable
	 * NCEEN/CEEN *before* checking the AFSR to avoid the small window of a
	 * deferred or disrupting error happening between checking the AFSR and
	 * enabling NCEEN/CEEN.
	 *
	 * Note: CEEN reenabled only if it was on when trap taken.
	 */
	set_error_enable(get_error_enable() | (EN_REG_NCEEN | ceen));
	if (clear_errors(&ch_flt)) {
		/*
		 * Check for secondary errors, and avoid panicking if we
		 * have them
		 */
		if (cpu_check_secondary_errors(&ch_flt, t_afsr_errs,
		    t_afar) == 0) {
			aflt->flt_panic |= ((ch_flt.afsr_errs &
			    (C_AFSR_ASYNC_ERRS | C_AFSR_EXT_ASYNC_ERRS)) != 0);
		}
		(void) cpu_queue_events(&ch_flt, pr_reason, ch_flt.afsr_errs,
		    NULL);
	}

	/*
	 * Panic here if aflt->flt_panic has been set.  Enqueued errors will
	 * be logged as part of the panic flow.
	 */
	if (aflt->flt_panic)
		fm_panic("%sError(s)", pr_reason);

	/*
	 * If we queued an error and we are going to return from the trap and
	 * the error was in user mode or inside of a copy routine, set AST flag
	 * so the queue will be drained before returning to user mode.  The
	 * AST processing will also act on our failure policy.
	 */
	if (!aflt->flt_priv || aflt->flt_prot == AFLT_PROT_COPY) {
		int pcb_flag = 0;

		if (t_afsr_errs &
		    (C_AFSR_ASYNC_ERRS | C_AFSR_EXT_ASYNC_ERRS &
		    ~(C_AFSR_BERR | C_AFSR_TO)))
			pcb_flag |= ASYNC_HWERR;

		if (t_afsr & C_AFSR_BERR)
			pcb_flag |= ASYNC_BERR;

		if (t_afsr & C_AFSR_TO)
			pcb_flag |= ASYNC_BTO;

		ttolwp(curthread)->lwp_pcb.pcb_flags |= pcb_flag;
		aston(curthread);
	}
}

#if defined(CPU_IMP_L1_CACHE_PARITY)
/*
 * Handling of data and instruction parity errors (traps 0x71, 0x72).
 *
 * For Panther, P$ data parity errors during floating point load hits
 * are also detected (reported as TT 0x71) and handled by this trap
 * handler.
 *
 * AFSR/AFAR are not set for parity errors, only TPC (a virtual address)
 * is available.
 */
/*ARGSUSED*/
void
cpu_parity_error(struct regs *rp, uint_t flags, caddr_t tpc)
{
	ch_async_flt_t ch_flt;
	struct async_flt *aflt;
	uchar_t tl = ((flags & CH_ERR_TL) != 0);
	uchar_t iparity = ((flags & CH_ERR_IPE) != 0);
	uchar_t panic = ((flags & CH_ERR_PANIC) != 0);
	char *error_class;
	int index, way, word;
	ch_dc_data_t tmp_dcp;
	int dc_set_size = dcache_size / CH_DCACHE_NWAY;
	uint64_t parity_bits, pbits;
	/* The parity bit array corresponds to the result of summing two bits */
	static int parity_bits_popc[] = { 0, 1, 1, 0 };

	/*
	 * Log the error.
	 * For icache parity errors the fault address is the trap PC.
	 * For dcache/pcache parity errors the instruction would have to
	 * be decoded to determine the address and that isn't possible
	 * at high PIL.
	 */
	bzero(&ch_flt, sizeof (ch_async_flt_t));
	aflt = (struct async_flt *)&ch_flt;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_bus_id = getprocessorid();
	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_pc = tpc;
	aflt->flt_addr = iparity ? (uint64_t)tpc : AFLT_INV_ADDR;
	aflt->flt_prot = AFLT_PROT_NONE;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_priv = (tl || (rp->r_tstate & TSTATE_PRIV)) ?  1 : 0;
	aflt->flt_tl = tl;
	aflt->flt_panic = panic;
	aflt->flt_status = iparity ? ECC_IP_TRAP : ECC_DP_TRAP;
	ch_flt.flt_type = iparity ? CPU_IC_PARITY : CPU_DC_PARITY;

	if (iparity) {
		cpu_icache_parity_info(&ch_flt);
		if (ch_flt.parity_data.ipe.cpl_off != -1)
			error_class = FM_EREPORT_CPU_USIII_IDSPE;
		else if (ch_flt.parity_data.ipe.cpl_way != -1)
			error_class = FM_EREPORT_CPU_USIII_ITSPE;
		else
			error_class = FM_EREPORT_CPU_USIII_IPE;
		aflt->flt_payload = FM_EREPORT_PAYLOAD_ICACHE_PE;
	} else {
		cpu_dcache_parity_info(&ch_flt);
		if (ch_flt.parity_data.dpe.cpl_off != -1) {
			/*
			 * If not at TL 0 and running on a Jalapeno processor,
			 * then process as a true ddspe.  A true
			 * ddspe error can only occur if the way == 0
			 */
			way = ch_flt.parity_data.dpe.cpl_way;
			if ((tl == 0) && (way != 0) &&
			    IS_JALAPENO(cpunodes[CPU->cpu_id].implementation)) {
				for (index = 0; index < dc_set_size;
				    index += dcache_linesize) {
					get_dcache_dtag(index + way *
					    dc_set_size,
					    (uint64_t *)&tmp_dcp);
					/*
					 * Check data array for even parity.
					 * The 8 parity bits are grouped into
					 * 4 pairs each of which covers a 64-bit
					 * word.  The endianness is reversed
					 * -- the low-order parity bits cover
					 *  the high-order data words.
					 */
					parity_bits = tmp_dcp.dc_utag >> 8;
					for (word = 0; word < 4; word++) {
						pbits = (parity_bits >>
						    (6 - word * 2)) & 3;
						if (((popc64(
						    tmp_dcp.dc_data[word]) +
						    parity_bits_popc[pbits]) &
						    1) && (tmp_dcp.dc_tag &
						    VA13)) {
							/* cleanup */
							correct_dcache_parity(
							    dcache_size,
							    dcache_linesize);
							if (cache_boot_state &
							    DCU_DC) {
								flush_dcache();
							}

							set_dcu(get_dcu() |
							    cache_boot_state);
							return;
						}
					}
				}
			} /* (tl == 0) && (way != 0) && IS JALAPENO */
			error_class = FM_EREPORT_CPU_USIII_DDSPE;
		} else if (ch_flt.parity_data.dpe.cpl_way != -1)
			error_class = FM_EREPORT_CPU_USIII_DTSPE;
		else
			error_class = FM_EREPORT_CPU_USIII_DPE;
		aflt->flt_payload = FM_EREPORT_PAYLOAD_DCACHE_PE;
		/*
		 * For panther we also need to check the P$ for parity errors.
		 */
		if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
			cpu_pcache_parity_info(&ch_flt);
			if (ch_flt.parity_data.dpe.cpl_cache == CPU_PC_PARITY) {
				error_class = FM_EREPORT_CPU_USIII_PDSPE;
				aflt->flt_payload =
				    FM_EREPORT_PAYLOAD_PCACHE_PE;
			}
		}
	}

	cpu_errorq_dispatch(error_class, (void *)&ch_flt,
	    sizeof (ch_async_flt_t), ue_queue, aflt->flt_panic);

	if (iparity) {
		/*
		 * Invalidate entire I$.
		 * This is required due to the use of diagnostic ASI
		 * accesses that may result in a loss of I$ coherency.
		 */
		if (cache_boot_state & DCU_IC) {
			flush_icache();
		}
		/*
		 * According to section P.3.1 of the Panther PRM, we
		 * need to do a little more for recovery on those
		 * CPUs after encountering an I$ parity error.
		 */
		if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
			flush_ipb();
			correct_dcache_parity(dcache_size,
			    dcache_linesize);
			flush_pcache();
		}
	} else {
		/*
		 * Since the valid bit is ignored when checking parity the
		 * D$ data and tag must also be corrected.  Set D$ data bits
		 * to zero and set utag to 0, 1, 2, 3.
		 */
		correct_dcache_parity(dcache_size, dcache_linesize);

		/*
		 * According to section P.3.3 of the Panther PRM, we
		 * need to do a little more for recovery on those
		 * CPUs after encountering a D$ or P$ parity error.
		 *
		 * As far as clearing P$ parity errors, it is enough to
		 * simply invalidate all entries in the P$ since P$ parity
		 * error traps are only generated for floating point load
		 * hits.
		 */
		if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
			flush_icache();
			flush_ipb();
			flush_pcache();
		}
	}

	/*
	 * Invalidate entire D$ if it was enabled.
	 * This is done to avoid stale data in the D$ which might
	 * occur with the D$ disabled and the trap handler doing
	 * stores affecting lines already in the D$.
	 */
	if (cache_boot_state & DCU_DC) {
		flush_dcache();
	}

	/*
	 * Restore caches to their bootup state.
	 */
	set_dcu(get_dcu() | cache_boot_state);

	/*
	 * Panic here if aflt->flt_panic has been set.  Enqueued errors will
	 * be logged as part of the panic flow.
	 */
	if (aflt->flt_panic)
		fm_panic("%sError(s)", iparity ? "IPE " : "DPE ");

	/*
	 * If this error occurred at TL>0 then flush the E$ here to reduce
	 * the chance of getting an unrecoverable Fast ECC error.  This
	 * flush will evict the part of the parity trap handler that is run
	 * at TL>1.
	 */
	if (tl) {
		cpu_flush_ecache();
	}
}

/*
 * On an I$ parity error, mark the appropriate entries in the ch_async_flt_t
 * to indicate which portions of the captured data should be in the ereport.
 */
void
cpu_async_log_ic_parity_err(ch_async_flt_t *ch_flt)
{
	int way = ch_flt->parity_data.ipe.cpl_way;
	int offset = ch_flt->parity_data.ipe.cpl_off;
	int tag_index;
	struct async_flt *aflt = (struct async_flt *)ch_flt;


	if ((offset != -1) || (way != -1)) {
		/*
		 * Parity error in I$ tag or data
		 */
		tag_index = ch_flt->parity_data.ipe.cpl_ic[way].ic_idx;
		if (IS_PANTHER(cpunodes[aflt->flt_inst].implementation))
			ch_flt->parity_data.ipe.cpl_ic[way].ic_way =
			    PN_ICIDX_TO_WAY(tag_index);
		else
			ch_flt->parity_data.ipe.cpl_ic[way].ic_way =
			    CH_ICIDX_TO_WAY(tag_index);
		ch_flt->parity_data.ipe.cpl_ic[way].ic_logflag =
		    IC_LOGFLAG_MAGIC;
	} else {
		/*
		 * Parity error was not identified.
		 * Log tags and data for all ways.
		 */
		for (way = 0; way < CH_ICACHE_NWAY; way++) {
			tag_index = ch_flt->parity_data.ipe.cpl_ic[way].ic_idx;
			if (IS_PANTHER(cpunodes[aflt->flt_inst].implementation))
				ch_flt->parity_data.ipe.cpl_ic[way].ic_way =
				    PN_ICIDX_TO_WAY(tag_index);
			else
				ch_flt->parity_data.ipe.cpl_ic[way].ic_way =
				    CH_ICIDX_TO_WAY(tag_index);
			ch_flt->parity_data.ipe.cpl_ic[way].ic_logflag =
			    IC_LOGFLAG_MAGIC;
		}
	}
}

/*
 * On an D$ parity error, mark the appropriate entries in the ch_async_flt_t
 * to indicate which portions of the captured data should be in the ereport.
 */
void
cpu_async_log_dc_parity_err(ch_async_flt_t *ch_flt)
{
	int way = ch_flt->parity_data.dpe.cpl_way;
	int offset = ch_flt->parity_data.dpe.cpl_off;
	int tag_index;

	if (offset != -1) {
		/*
		 * Parity error in D$ or P$ data array.
		 *
		 * First check to see whether the parity error is in D$ or P$
		 * since P$ data parity errors are reported in Panther using
		 * the same trap.
		 */
		if (ch_flt->parity_data.dpe.cpl_cache == CPU_PC_PARITY) {
			tag_index = ch_flt->parity_data.dpe.cpl_pc[way].pc_idx;
			ch_flt->parity_data.dpe.cpl_pc[way].pc_way =
			    CH_PCIDX_TO_WAY(tag_index);
			ch_flt->parity_data.dpe.cpl_pc[way].pc_logflag =
			    PC_LOGFLAG_MAGIC;
		} else {
			tag_index = ch_flt->parity_data.dpe.cpl_dc[way].dc_idx;
			ch_flt->parity_data.dpe.cpl_dc[way].dc_way =
			    CH_DCIDX_TO_WAY(tag_index);
			ch_flt->parity_data.dpe.cpl_dc[way].dc_logflag =
			    DC_LOGFLAG_MAGIC;
		}
	} else if (way != -1) {
		/*
		 * Parity error in D$ tag.
		 */
		tag_index = ch_flt->parity_data.dpe.cpl_dc[way].dc_idx;
		ch_flt->parity_data.dpe.cpl_dc[way].dc_way =
		    CH_DCIDX_TO_WAY(tag_index);
		ch_flt->parity_data.dpe.cpl_dc[way].dc_logflag =
		    DC_LOGFLAG_MAGIC;
	}
}
#endif	/* CPU_IMP_L1_CACHE_PARITY */

/*
 * The cpu_async_log_err() function is called via the [uc]e_drain() function to
 * post-process CPU events that are dequeued.  As such, it can be invoked
 * from softint context, from AST processing in the trap() flow, or from the
 * panic flow.  We decode the CPU-specific data, and take appropriate actions.
 * Historically this entry point was used to log the actual cmn_err(9F) text;
 * now with FMA it is used to prepare 'flt' to be converted into an ereport.
 * With FMA this function now also returns a flag which indicates to the
 * caller whether the ereport should be posted (1) or suppressed (0).
 */
static int
cpu_async_log_err(void *flt, errorq_elem_t *eqep)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)flt;
	struct async_flt *aflt = (struct async_flt *)flt;
	uint64_t errors;
	extern void memscrub_induced_error(void);

	switch (ch_flt->flt_type) {
	case CPU_INV_AFSR:
		/*
		 * If it is a disrupting trap and the AFSR is zero, then
		 * the event has probably already been noted. Do not post
		 * an ereport.
		 */
		if ((aflt->flt_status & ECC_C_TRAP) &&
		    (!(aflt->flt_stat & C_AFSR_MASK)))
			return (0);
		else
			return (1);
	case CPU_TO:
	case CPU_BERR:
	case CPU_FATAL:
	case CPU_FPUERR:
		return (1);

	case CPU_UE_ECACHE_RETIRE:
		cpu_log_err(aflt);
		cpu_page_retire(ch_flt);
		return (1);

	/*
	 * Cases where we may want to suppress logging or perform
	 * extended diagnostics.
	 */
	case CPU_CE:
	case CPU_EMC:
		/*
		 * We want to skip logging and further classification
		 * only if ALL the following conditions are true:
		 *
		 *	1. There is only one error
		 *	2. That error is a correctable memory error
		 *	3. The error is caused by the memory scrubber (in
		 *	   which case the error will have occurred under
		 *	   on_trap protection)
		 *	4. The error is on a retired page
		 *
		 * Note: AFLT_PROT_EC is used places other than the memory
		 * scrubber.  However, none of those errors should occur
		 * on a retired page.
		 */
		if ((ch_flt->afsr_errs &
		    (C_AFSR_ALL_ERRS | C_AFSR_EXT_ALL_ERRS)) == C_AFSR_CE &&
		    aflt->flt_prot == AFLT_PROT_EC) {

			if (page_retire_check(aflt->flt_addr, NULL) == 0) {
				if (ch_flt->flt_trapped_ce & CE_CEEN_DEFER) {

				/*
				 * Since we're skipping logging, we'll need
				 * to schedule the re-enabling of CEEN
				 */
				(void) timeout(cpu_delayed_check_ce_errors,
				    (void *)(uintptr_t)aflt->flt_inst,
				    drv_usectohz((clock_t)cpu_ceen_delay_secs
				    * MICROSEC));
				}

				/*
				 * Inform memscrubber - scrubbing induced
				 * CE on a retired page.
				 */
				memscrub_induced_error();
				return (0);
			}
		}

		/*
		 * Perform/schedule further classification actions, but
		 * only if the page is healthy (we don't want bad
		 * pages inducing too much diagnostic activity).  If we could
		 * not find a page pointer then we also skip this.  If
		 * ce_scrub_xdiag_recirc returns nonzero then it has chosen
		 * to copy and recirculate the event (for further diagnostics)
		 * and we should not proceed to log it here.
		 *
		 * This must be the last step here before the cpu_log_err()
		 * below - if an event recirculates cpu_ce_log_err() will
		 * not call the current function but just proceed directly
		 * to cpu_ereport_post after the cpu_log_err() avoided below.
		 *
		 * Note: Check cpu_impl_async_log_err if changing this
		 */
		if (page_retire_check(aflt->flt_addr, &errors) == EINVAL) {
			CE_XDIAG_SETSKIPCODE(aflt->flt_disp,
			    CE_XDIAG_SKIP_NOPP);
		} else {
			if (errors != PR_OK) {
				CE_XDIAG_SETSKIPCODE(aflt->flt_disp,
				    CE_XDIAG_SKIP_PAGEDET);
			} else if (ce_scrub_xdiag_recirc(aflt, ce_queue, eqep,
			    offsetof(ch_async_flt_t, cmn_asyncflt))) {
				return (0);
			}
		}
		/*FALLTHRU*/

	/*
	 * Cases where we just want to report the error and continue.
	 */
	case CPU_CE_ECACHE:
	case CPU_UE_ECACHE:
	case CPU_IV:
	case CPU_ORPH:
		cpu_log_err(aflt);
		return (1);

	/*
	 * Cases where we want to fall through to handle panicking.
	 */
	case CPU_UE:
		/*
		 * We want to skip logging in the same conditions as the
		 * CE case.  In addition, we want to make sure we're not
		 * panicking.
		 */
		if (!panicstr && (ch_flt->afsr_errs &
		    (C_AFSR_ALL_ERRS | C_AFSR_EXT_ALL_ERRS)) == C_AFSR_UE &&
		    aflt->flt_prot == AFLT_PROT_EC) {
			if (page_retire_check(aflt->flt_addr, NULL) == 0) {
				/* Zero the address to clear the error */
				softcall(ecc_page_zero, (void *)aflt->flt_addr);
				/*
				 * Inform memscrubber - scrubbing induced
				 * UE on a retired page.
				 */
				memscrub_induced_error();
				return (0);
			}
		}
		cpu_log_err(aflt);
		break;

	default:
		/*
		 * If the us3_common.c code doesn't know the flt_type, it may
		 * be an implementation-specific code.  Call into the impldep
		 * backend to find out what to do: if it tells us to continue,
		 * break and handle as if falling through from a UE; if not,
		 * the impldep backend has handled the error and we're done.
		 */
		switch (cpu_impl_async_log_err(flt, eqep)) {
		case CH_ASYNC_LOG_DONE:
			return (1);
		case CH_ASYNC_LOG_RECIRC:
			return (0);
		case CH_ASYNC_LOG_CONTINUE:
			break; /* continue on to handle UE-like error */
		default:
			cmn_err(CE_WARN, "discarding error 0x%p with "
			    "invalid fault type (0x%x)",
			    (void *)aflt, ch_flt->flt_type);
			return (0);
		}
	}

	/* ... fall through from the UE case */

	if (aflt->flt_addr != AFLT_INV_ADDR && aflt->flt_in_memory) {
		if (!panicstr) {
			cpu_page_retire(ch_flt);
		} else {
			/*
			 * Clear UEs on panic so that we don't
			 * get haunted by them during panic or
			 * after reboot
			 */
			cpu_clearphys(aflt);
			(void) clear_errors(NULL);
		}
	}

	return (1);
}

/*
 * Retire the bad page that may contain the flushed error.
 */
void
cpu_page_retire(ch_async_flt_t *ch_flt)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	(void) page_retire(aflt->flt_addr, PR_UE);
}

/*
 * Return true if the error specified in the AFSR indicates
 * an E$ data error (L2$ for Cheetah/Cheetah+/Jaguar, L3$
 * for Panther, none for Jalapeno/Serrano).
 */
/* ARGSUSED */
static int
cpu_error_is_ecache_data(int cpuid, uint64_t t_afsr)
{
#if defined(JALAPENO) || defined(SERRANO)
	return (0);
#elif defined(CHEETAH_PLUS)
	if (IS_PANTHER(cpunodes[cpuid].implementation))
		return ((t_afsr & C_AFSR_EXT_L3_DATA_ERRS) != 0);
	return ((t_afsr & C_AFSR_EC_DATA_ERRS) != 0);
#else	/* CHEETAH_PLUS */
	return ((t_afsr & C_AFSR_EC_DATA_ERRS) != 0);
#endif
}

/*
 * The cpu_log_err() function is called by cpu_async_log_err() to perform the
 * generic event post-processing for correctable and uncorrectable memory,
 * E$, and MTag errors.  Historically this entry point was used to log bits of
 * common cmn_err(9F) text; now with FMA it is used to prepare 'flt' to be
 * converted into an ereport.  In addition, it transmits the error to any
 * platform-specific service-processor FRU logging routines, if available.
 */
void
cpu_log_err(struct async_flt *aflt)
{
	char unum[UNUM_NAMLEN];
	int synd_status, synd_code, afar_status;
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;

	if (cpu_error_is_ecache_data(aflt->flt_inst, ch_flt->flt_bit))
		aflt->flt_status |= ECC_ECACHE;
	else
		aflt->flt_status &= ~ECC_ECACHE;
	/*
	 * Determine syndrome status.
	 */
	synd_status = afsr_to_synd_status(aflt->flt_inst,
	    ch_flt->afsr_errs, ch_flt->flt_bit);

	/*
	 * Determine afar status.
	 */
	if (pf_is_memory(aflt->flt_addr >> MMU_PAGESHIFT))
		afar_status = afsr_to_afar_status(ch_flt->afsr_errs,
		    ch_flt->flt_bit);
	else
		afar_status = AFLT_STAT_INVALID;

	synd_code = synd_to_synd_code(synd_status,
	    aflt->flt_synd, ch_flt->flt_bit);

	/*
	 * If afar status is not invalid do a unum lookup.
	 */
	if (afar_status != AFLT_STAT_INVALID) {
		(void) cpu_get_mem_unum_synd(synd_code, aflt, unum);
	} else {
		unum[0] = '\0';
	}

	/*
	 * Do not send the fruid message (plat_ecc_error_data_t)
	 * to the SC if it can handle the enhanced error information
	 * (plat_ecc_error2_data_t) or when the tunable
	 * ecc_log_fruid_enable is set to 0.
	 */

	if (&plat_ecc_capability_sc_get &&
	    plat_ecc_capability_sc_get(PLAT_ECC_ERROR_MESSAGE)) {
		if (&plat_log_fruid_error)
			plat_log_fruid_error(synd_code, aflt, unum,
			    ch_flt->flt_bit);
	}

	if (aflt->flt_func != NULL)
		aflt->flt_func(aflt, unum);

	if (afar_status != AFLT_STAT_INVALID)
		cpu_log_diag_info(ch_flt);

	/*
	 * If we have a CEEN error , we do not reenable CEEN until after
	 * we exit the trap handler. Otherwise, another error may
	 * occur causing the handler to be entered recursively.
	 * We set a timeout to trigger in cpu_ceen_delay_secs seconds,
	 * to try and ensure that the CPU makes progress in the face
	 * of a CE storm.
	 */
	if (ch_flt->flt_trapped_ce & CE_CEEN_DEFER) {
		(void) timeout(cpu_delayed_check_ce_errors,
		    (void *)(uintptr_t)aflt->flt_inst,
		    drv_usectohz((clock_t)cpu_ceen_delay_secs * MICROSEC));
	}
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
 */
void
cpu_error_init(int items)
{
	/*
	 * Create taskq(s) to reenable CE
	 */
	ch_check_ce_tq = taskq_create("cheetah_check_ce", 1, minclsyspri,
	    items, items, TASKQ_PREPOPULATE);
}

void
cpu_ce_log_err(struct async_flt *aflt, errorq_elem_t *eqep)
{
	char unum[UNUM_NAMLEN];
	int len;

	switch (aflt->flt_class) {
	case CPU_FAULT:
		cpu_ereport_init(aflt);
		if (cpu_async_log_err(aflt, eqep))
			cpu_ereport_post(aflt);
		break;

	case BUS_FAULT:
		if (aflt->flt_func != NULL) {
			(void) cpu_get_mem_unum_aflt(AFLT_STAT_VALID, aflt,
			    unum, UNUM_NAMLEN, &len);
			aflt->flt_func(aflt, unum);
		}
		break;

	case RECIRC_CPU_FAULT:
		aflt->flt_class = CPU_FAULT;
		cpu_log_err(aflt);
		cpu_ereport_post(aflt);
		break;

	case RECIRC_BUS_FAULT:
		ASSERT(aflt->flt_class != RECIRC_BUS_FAULT);
		/*FALLTHRU*/
	default:
		cmn_err(CE_WARN, "discarding CE error 0x%p with invalid "
		    "fault class (0x%x)", (void *)aflt, aflt->flt_class);
		return;
	}
}

/*
 * Scrub and classify a CE.  This function must not modify the
 * fault structure passed to it but instead should return the classification
 * information.
 */

static uchar_t
cpu_ce_scrub_mem_err_common(struct async_flt *ecc, boolean_t logout_tried)
{
	uchar_t disp = CE_XDIAG_EXTALG;
	on_trap_data_t otd;
	uint64_t orig_err;
	ch_cpu_logout_t *clop;

	/*
	 * Clear CEEN.  CPU CE TL > 0 trap handling will already have done
	 * this, but our other callers have not.  Disable preemption to
	 * avoid CPU migration so that we restore CEEN on the correct
	 * cpu later.
	 *
	 * CEEN is cleared so that further CEs that our instruction and
	 * data footprint induce do not cause use to either creep down
	 * kernel stack to the point of overflow, or do so much CE
	 * notification as to make little real forward progress.
	 *
	 * NCEEN must not be cleared.  However it is possible that
	 * our accesses to the flt_addr may provoke a bus error or timeout
	 * if the offending address has just been unconfigured as part of
	 * a DR action.  So we must operate under on_trap protection.
	 */
	kpreempt_disable();
	orig_err = get_error_enable();
	if (orig_err & EN_REG_CEEN)
		set_error_enable(orig_err & ~EN_REG_CEEN);

	/*
	 * Our classification algorithm includes the line state before
	 * the scrub; we'd like this captured after the detection and
	 * before the algorithm below - the earlier the better.
	 *
	 * If we've come from a cpu CE trap then this info already exists
	 * in the cpu logout area.
	 *
	 * For a CE detected by memscrub for which there was no trap
	 * (running with CEEN off) cpu_log_and_clear_ce has called
	 * cpu_ce_delayed_ec_logout to capture some cache data, and
	 * marked the fault structure as incomplete as a flag to later
	 * logging code.
	 *
	 * If called directly from an IO detected CE there has been
	 * no line data capture.  In this case we logout to the cpu logout
	 * area - that's appropriate since it's the cpu cache data we need
	 * for classification.  We thus borrow the cpu logout area for a
	 * short time, and cpu_ce_delayed_ec_logout will mark it as busy in
	 * this time (we will invalidate it again below).
	 *
	 * If called from the partner check xcall handler then this cpu
	 * (the partner) has not necessarily experienced a CE at this
	 * address.  But we want to capture line state before its scrub
	 * attempt since we use that in our classification.
	 */
	if (logout_tried == B_FALSE) {
		if (!cpu_ce_delayed_ec_logout(ecc->flt_addr))
			disp |= CE_XDIAG_NOLOGOUT;
	}

	/*
	 * Scrub memory, then check AFSR for errors.  The AFAR we scrub may
	 * no longer be valid (if DR'd since the initial event) so we
	 * perform this scrub under on_trap protection.  If this access is
	 * ok then further accesses below will also be ok - DR cannot
	 * proceed while this thread is active (preemption is disabled);
	 * to be safe we'll nonetheless use on_trap again below.
	 */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		cpu_scrubphys(ecc);
	} else {
		no_trap();
		if (orig_err & EN_REG_CEEN)
			set_error_enable(orig_err);
		kpreempt_enable();
		return (disp);
	}
	no_trap();

	/*
	 * Did the casx read of the scrub log a CE that matches the AFAR?
	 * Note that it's quite possible that the read sourced the data from
	 * another cpu.
	 */
	if (clear_ecc(ecc))
		disp |= CE_XDIAG_CE1;

	/*
	 * Read the data again.  This time the read is very likely to
	 * come from memory since the scrub induced a writeback to memory.
	 */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		(void) lddphys(P2ALIGN(ecc->flt_addr, 8));
	} else {
		no_trap();
		if (orig_err & EN_REG_CEEN)
			set_error_enable(orig_err);
		kpreempt_enable();
		return (disp);
	}
	no_trap();

	/* Did that read induce a CE that matches the AFAR? */
	if (clear_ecc(ecc))
		disp |= CE_XDIAG_CE2;

	/*
	 * Look at the logout information and record whether we found the
	 * line in l2/l3 cache.  For Panther we are interested in whether
	 * we found it in either cache (it won't reside in both but
	 * it is possible to read it that way given the moving target).
	 */
	clop = CPU_PRIVATE(CPU) ? CPU_PRIVATE_PTR(CPU, chpr_cecc_logout) : NULL;
	if (!(disp & CE_XDIAG_NOLOGOUT) && clop &&
	    clop->clo_data.chd_afar != LOGOUT_INVALID) {
		int hit, level;
		int state;
		int totalsize;
		ch_ec_data_t *ecp;

		/*
		 * If hit is nonzero then a match was found and hit will
		 * be one greater than the index which hit.  For Panther we
		 * also need to pay attention to level to see which of l2$ or
		 * l3$ it hit in.
		 */
		hit = cpu_matching_ecache_line(ecc->flt_addr, &clop->clo_data,
		    0, &level);

		if (hit) {
			--hit;
			disp |= CE_XDIAG_AFARMATCH;

			if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
				if (level == 2)
					ecp = &clop->clo_data.chd_l2_data[hit];
				else
					ecp = &clop->clo_data.chd_ec_data[hit];
			} else {
				ASSERT(level == 2);
				ecp = &clop->clo_data.chd_ec_data[hit];
			}
			totalsize = cpunodes[CPU->cpu_id].ecache_size;
			state = cpu_ectag_pa_to_subblk_state(totalsize,
			    ecc->flt_addr, ecp->ec_tag);

			/*
			 * Cheetah variants use different state encodings -
			 * the CH_ECSTATE_* defines vary depending on the
			 * module we're compiled for.  Translate into our
			 * one true version.  Conflate Owner-Shared state
			 * of SSM mode with Owner as victimisation of such
			 * lines may cause a writeback.
			 */
			switch (state) {
			case CH_ECSTATE_MOD:
				disp |= EC_STATE_M;
				break;

			case CH_ECSTATE_OWN:
			case CH_ECSTATE_OWS:
				disp |= EC_STATE_O;
				break;

			case CH_ECSTATE_EXL:
				disp |= EC_STATE_E;
				break;

			case CH_ECSTATE_SHR:
				disp |= EC_STATE_S;
				break;

			default:
				disp |= EC_STATE_I;
				break;
			}
		}

		/*
		 * If we initiated the delayed logout then we are responsible
		 * for invalidating the logout area.
		 */
		if (logout_tried == B_FALSE) {
			bzero(clop, sizeof (ch_cpu_logout_t));
			clop->clo_data.chd_afar = LOGOUT_INVALID;
		}
	}

	/*
	 * Re-enable CEEN if we turned it off.
	 */
	if (orig_err & EN_REG_CEEN)
		set_error_enable(orig_err);
	kpreempt_enable();

	return (disp);
}

/*
 * Scrub a correctable memory error and collect data for classification
 * of CE type.  This function is called in the detection path, ie tl0 handling
 * of a correctable error trap (cpus) or interrupt (IO) at high PIL.
 */
void
cpu_ce_scrub_mem_err(struct async_flt *ecc, boolean_t logout_tried)
{
	/*
	 * Cheetah CE classification does not set any bits in flt_status.
	 * Instead we will record classification datapoints in flt_disp.
	 */
	ecc->flt_status &= ~(ECC_INTERMITTENT | ECC_PERSISTENT | ECC_STICKY);

	/*
	 * To check if the error detected by IO is persistent, sticky or
	 * intermittent.  This is noticed by clear_ecc().
	 */
	if (ecc->flt_status & ECC_IOBUS)
		ecc->flt_stat = C_AFSR_MEMORY;

	/*
	 * Record information from this first part of the algorithm in
	 * flt_disp.
	 */
	ecc->flt_disp = cpu_ce_scrub_mem_err_common(ecc, logout_tried);
}

/*
 * Select a partner to perform a further CE classification check from.
 * Must be called with kernel preemption disabled (to stop the cpu list
 * from changing).  The detecting cpu we are partnering has cpuid
 * aflt->flt_inst; we might not be running on the detecting cpu.
 *
 * Restrict choice to active cpus in the same cpu partition as ourselves in
 * an effort to stop bad cpus in one partition causing other partitions to
 * perform excessive diagnostic activity.  Actually since the errorq drain
 * is run from a softint most of the time and that is a global mechanism
 * this isolation is only partial.  Return NULL if we fail to find a
 * suitable partner.
 *
 * We prefer a partner that is in a different latency group to ourselves as
 * we will share fewer datapaths.  If such a partner is unavailable then
 * choose one in the same lgroup but prefer a different chip and only allow
 * a sibling core if flags includes PTNR_SIBLINGOK.  If all else fails and
 * flags includes PTNR_SELFOK then permit selection of the original detector.
 *
 * We keep a cache of the last partner selected for a cpu, and we'll try to
 * use that previous partner if no more than cpu_ce_ptnr_cachetime_sec seconds
 * have passed since that selection was made.  This provides the benefit
 * of the point-of-view of different partners over time but without
 * requiring frequent cpu list traversals.
 */

#define	PTNR_SIBLINGOK	0x1	/* Allow selection of sibling core */
#define	PTNR_SELFOK	0x2	/* Allow selection of cpu to "partner" itself */

static cpu_t *
ce_ptnr_select(struct async_flt *aflt, int flags, int *typep)
{
	cpu_t *sp, *dtcr, *ptnr, *locptnr, *sibptnr;
	hrtime_t lasttime, thistime;

	ASSERT(curthread->t_preempt > 0 || getpil() >= DISP_LEVEL);

	dtcr = cpu[aflt->flt_inst];

	/*
	 * Short-circuit for the following cases:
	 *	. the dtcr is not flagged active
	 *	. there is just one cpu present
	 *	. the detector has disappeared
	 *	. we were given a bad flt_inst cpuid; this should not happen
	 *	  (eg PCI code now fills flt_inst) but if it does it is no
	 *	  reason to panic.
	 *	. there is just one cpu left online in the cpu partition
	 *
	 * If we return NULL after this point then we do not update the
	 * chpr_ceptnr_seltime which will cause us to perform a full lookup
	 * again next time; this is the case where the only other cpu online
	 * in the detector's partition is on the same chip as the detector
	 * and since CEEN re-enable is throttled even that case should not
	 * hurt performance.
	 */
	if (dtcr == NULL || !cpu_flagged_active(dtcr->cpu_flags)) {
		return (NULL);
	}
	if (ncpus == 1 || dtcr->cpu_part->cp_ncpus == 1) {
		if (flags & PTNR_SELFOK) {
			*typep = CE_XDIAG_PTNR_SELF;
			return (dtcr);
		} else {
			return (NULL);
		}
	}

	thistime = gethrtime();
	lasttime = CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_seltime);

	/*
	 * Select a starting point.
	 */
	if (!lasttime) {
		/*
		 * We've never selected a partner for this detector before.
		 * Start the scan at the next online cpu in the same cpu
		 * partition.
		 */
		sp = dtcr->cpu_next_part;
	} else if (thistime - lasttime < cpu_ce_ptnr_cachetime_sec * NANOSEC) {
		/*
		 * Our last selection has not aged yet.  If this partner:
		 *	. is still a valid cpu,
		 *	. is still in the same partition as the detector
		 *	. is still marked active
		 *	. satisfies the 'flags' argument criteria
		 * then select it again without updating the timestamp.
		 */
		sp = cpu[CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_id)];
		if (sp == NULL || sp->cpu_part != dtcr->cpu_part ||
		    !cpu_flagged_active(sp->cpu_flags) ||
		    (sp == dtcr && !(flags & PTNR_SELFOK)) ||
		    (pg_plat_cpus_share(sp, dtcr, PGHW_CHIP) &&
		    !(flags & PTNR_SIBLINGOK))) {
			sp = dtcr->cpu_next_part;
		} else {
			if (sp->cpu_lpl->lpl_lgrp != dtcr->cpu_lpl->lpl_lgrp) {
				*typep = CE_XDIAG_PTNR_REMOTE;
			} else if (sp == dtcr) {
				*typep = CE_XDIAG_PTNR_SELF;
			} else if (pg_plat_cpus_share(sp, dtcr, PGHW_CHIP)) {
				*typep = CE_XDIAG_PTNR_SIBLING;
			} else {
				*typep = CE_XDIAG_PTNR_LOCAL;
			}
			return (sp);
		}
	} else {
		/*
		 * Our last selection has aged.  If it is nonetheless still a
		 * valid cpu then start the scan at the next cpu in the
		 * partition after our last partner.  If the last selection
		 * is no longer a valid cpu then go with our default.  In
		 * this way we slowly cycle through possible partners to
		 * obtain multiple viewpoints over time.
		 */
		sp = cpu[CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_id)];
		if (sp == NULL) {
			sp = dtcr->cpu_next_part;
		} else {
			sp = sp->cpu_next_part;		/* may be dtcr */
			if (sp->cpu_part != dtcr->cpu_part)
				sp = dtcr;
		}
	}

	/*
	 * We have a proposed starting point for our search, but if this
	 * cpu is offline then its cpu_next_part will point to itself
	 * so we can't use that to iterate over cpus in this partition in
	 * the loop below.  We still want to avoid iterating over cpus not
	 * in our partition, so in the case that our starting point is offline
	 * we will repoint it to be the detector itself;  and if the detector
	 * happens to be offline we'll return NULL from the following loop.
	 */
	if (!cpu_flagged_active(sp->cpu_flags)) {
		sp = dtcr;
	}

	ptnr = sp;
	locptnr = NULL;
	sibptnr = NULL;
	do {
		if (ptnr == dtcr || !cpu_flagged_active(ptnr->cpu_flags))
			continue;
		if (ptnr->cpu_lpl->lpl_lgrp != dtcr->cpu_lpl->lpl_lgrp) {
			CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_id) = ptnr->cpu_id;
			CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_seltime) = thistime;
			*typep = CE_XDIAG_PTNR_REMOTE;
			return (ptnr);
		}
		if (pg_plat_cpus_share(ptnr, dtcr, PGHW_CHIP)) {
			if (sibptnr == NULL)
				sibptnr = ptnr;
			continue;
		}
		if (locptnr == NULL)
			locptnr = ptnr;
	} while ((ptnr = ptnr->cpu_next_part) != sp);

	/*
	 * A foreign partner has already been returned if one was available.
	 *
	 * If locptnr is not NULL it is a cpu in the same lgroup as the
	 * detector, is active, and is not a sibling of the detector.
	 *
	 * If sibptnr is not NULL it is a sibling of the detector, and is
	 * active.
	 *
	 * If we have to resort to using the detector itself we have already
	 * checked that it is active.
	 */
	if (locptnr) {
		CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_id) = locptnr->cpu_id;
		CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_seltime) = thistime;
		*typep = CE_XDIAG_PTNR_LOCAL;
		return (locptnr);
	} else if (sibptnr && flags & PTNR_SIBLINGOK) {
		CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_id) = sibptnr->cpu_id;
		CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_seltime) = thistime;
		*typep = CE_XDIAG_PTNR_SIBLING;
		return (sibptnr);
	} else if (flags & PTNR_SELFOK) {
		CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_id) = dtcr->cpu_id;
		CPU_PRIVATE_VAL(dtcr, chpr_ceptnr_seltime) = thistime;
		*typep = CE_XDIAG_PTNR_SELF;
		return (dtcr);
	}

	return (NULL);
}

/*
 * Cross call handler that is requested to run on the designated partner of
 * a cpu that experienced a possibly sticky or possibly persistnet CE.
 */
static void
ce_ptnrchk_xc(struct async_flt *aflt, uchar_t *dispp)
{
	*dispp = cpu_ce_scrub_mem_err_common(aflt, B_FALSE);
}

/*
 * The associated errorqs are never destroyed so we do not need to deal with
 * them disappearing before this timeout fires.  If the affected memory
 * has been DR'd out since the original event the scrub algrithm will catch
 * any errors and return null disposition info.  If the original detecting
 * cpu has been DR'd out then ereport detector info will not be able to
 * lookup CPU type;  with a small timeout this is unlikely.
 */
static void
ce_lkychk_cb(ce_lkychk_cb_t *cbarg)
{
	struct async_flt *aflt = cbarg->lkycb_aflt;
	uchar_t disp;
	cpu_t *cp;
	int ptnrtype;

	kpreempt_disable();
	if (cp = ce_ptnr_select(aflt, PTNR_SIBLINGOK | PTNR_SELFOK,
	    &ptnrtype)) {
		xc_one(cp->cpu_id, (xcfunc_t *)ce_ptnrchk_xc, (uint64_t)aflt,
		    (uint64_t)&disp);
		CE_XDIAG_SETLKYINFO(aflt->flt_disp, disp);
		CE_XDIAG_SETPTNRID(aflt->flt_disp, cp->cpu_id);
		CE_XDIAG_SETPTNRTYPE(aflt->flt_disp, ptnrtype);
	} else {
		ce_xdiag_lkydrops++;
		if (ncpus > 1)
			CE_XDIAG_SETSKIPCODE(aflt->flt_disp,
			    CE_XDIAG_SKIP_NOPTNR);
	}
	kpreempt_enable();

	errorq_commit(cbarg->lkycb_eqp, cbarg->lkycb_eqep, ERRORQ_ASYNC);
	kmem_free(cbarg, sizeof (ce_lkychk_cb_t));
}

/*
 * Called from errorq drain code when processing a CE error, both from
 * CPU and PCI drain functions.  Decide what further classification actions,
 * if any, we will perform.  Perform immediate actions now, and schedule
 * delayed actions as required.  Note that we are no longer necessarily running
 * on the detecting cpu, and that the async_flt structure will not persist on
 * return from this function.
 *
 * Calls to this function should aim to be self-throtlling in some way.  With
 * the delayed re-enable of CEEN the absolute rate of calls should not
 * be excessive.  Callers should also avoid performing in-depth classification
 * for events in pages that are already known to be suspect.
 *
 * We return nonzero to indicate that the event has been copied and
 * recirculated for further testing.  The caller should not log the event
 * in this case - it will be logged when further test results are available.
 *
 * Our possible contexts are that of errorq_drain: below lock level or from
 * panic context.  We can assume that the cpu we are running on is online.
 */


#ifdef DEBUG
static int ce_xdiag_forceaction;
#endif

int
ce_scrub_xdiag_recirc(struct async_flt *aflt, errorq_t *eqp,
    errorq_elem_t *eqep, size_t afltoffset)
{
	ce_dispact_t dispact, action;
	cpu_t *cp;
	uchar_t dtcrinfo, disp;
	int ptnrtype;

	if (!ce_disp_inited || panicstr || ce_xdiag_off) {
		ce_xdiag_drops++;
		return (0);
	} else if (!aflt->flt_in_memory) {
		ce_xdiag_drops++;
		CE_XDIAG_SETSKIPCODE(aflt->flt_disp, CE_XDIAG_SKIP_NOTMEM);
		return (0);
	}

	dtcrinfo = CE_XDIAG_DTCRINFO(aflt->flt_disp);

	/*
	 * Some correctable events are not scrubbed/classified, such as those
	 * noticed at the tail of cpu_deferred_error.  So if there is no
	 * initial detector classification go no further.
	 */
	if (!CE_XDIAG_EXT_ALG_APPLIED(dtcrinfo)) {
		ce_xdiag_drops++;
		CE_XDIAG_SETSKIPCODE(aflt->flt_disp, CE_XDIAG_SKIP_NOSCRUB);
		return (0);
	}

	dispact = CE_DISPACT(ce_disp_table,
	    CE_XDIAG_AFARMATCHED(dtcrinfo),
	    CE_XDIAG_STATE(dtcrinfo),
	    CE_XDIAG_CE1SEEN(dtcrinfo),
	    CE_XDIAG_CE2SEEN(dtcrinfo));


	action = CE_ACT(dispact);	/* bad lookup caught below */
#ifdef DEBUG
	if (ce_xdiag_forceaction != 0)
		action = ce_xdiag_forceaction;
#endif

	switch (action) {
	case CE_ACT_LKYCHK: {
		caddr_t ndata;
		errorq_elem_t *neqep;
		struct async_flt *ecc;
		ce_lkychk_cb_t *cbargp;

		if ((ndata = errorq_elem_dup(eqp, eqep, &neqep)) == NULL) {
			ce_xdiag_lkydrops++;
			CE_XDIAG_SETSKIPCODE(aflt->flt_disp,
			    CE_XDIAG_SKIP_DUPFAIL);
			break;
		}
		ecc = (struct async_flt *)(ndata + afltoffset);

		ASSERT(ecc->flt_class == CPU_FAULT ||
		    ecc->flt_class == BUS_FAULT);
		ecc->flt_class = (ecc->flt_class == CPU_FAULT) ?
		    RECIRC_CPU_FAULT : RECIRC_BUS_FAULT;

		cbargp = kmem_alloc(sizeof (ce_lkychk_cb_t), KM_SLEEP);
		cbargp->lkycb_aflt = ecc;
		cbargp->lkycb_eqp = eqp;
		cbargp->lkycb_eqep = neqep;

		(void) timeout((void (*)(void *))ce_lkychk_cb,
		    (void *)cbargp, drv_usectohz(cpu_ce_lkychk_timeout_usec));
		return (1);
	}

	case CE_ACT_PTNRCHK:
		kpreempt_disable();	/* stop cpu list changing */
		if ((cp = ce_ptnr_select(aflt, 0, &ptnrtype)) != NULL) {
			xc_one(cp->cpu_id, (xcfunc_t *)ce_ptnrchk_xc,
			    (uint64_t)aflt, (uint64_t)&disp);
			CE_XDIAG_SETPTNRINFO(aflt->flt_disp, disp);
			CE_XDIAG_SETPTNRID(aflt->flt_disp, cp->cpu_id);
			CE_XDIAG_SETPTNRTYPE(aflt->flt_disp, ptnrtype);
		} else if (ncpus > 1) {
			ce_xdiag_ptnrdrops++;
			CE_XDIAG_SETSKIPCODE(aflt->flt_disp,
			    CE_XDIAG_SKIP_NOPTNR);
		} else {
			ce_xdiag_ptnrdrops++;
			CE_XDIAG_SETSKIPCODE(aflt->flt_disp,
			    CE_XDIAG_SKIP_UNIPROC);
		}
		kpreempt_enable();
		break;

	case CE_ACT_DONE:
		break;

	case CE_ACT(CE_DISP_BAD):
	default:
#ifdef DEBUG
		cmn_err(CE_PANIC, "ce_scrub_post: Bad action '%d'", action);
#endif
		ce_xdiag_bad++;
		CE_XDIAG_SETSKIPCODE(aflt->flt_disp, CE_XDIAG_SKIP_ACTBAD);
		break;
	}

	return (0);
}

/*
 * We route all errors through a single switch statement.
 */
void
cpu_ue_log_err(struct async_flt *aflt)
{
	switch (aflt->flt_class) {
	case CPU_FAULT:
		cpu_ereport_init(aflt);
		if (cpu_async_log_err(aflt, NULL))
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
 */
void
cpu_async_panic_callb(void)
{
	ch_async_flt_t ch_flt;
	struct async_flt *aflt;
	ch_cpu_errors_t cpu_error_regs;
	uint64_t afsr_errs;

	get_cpu_error_state(&cpu_error_regs);

	afsr_errs = (cpu_error_regs.afsr & C_AFSR_ALL_ERRS) |
	    (cpu_error_regs.afsr_ext & C_AFSR_EXT_ALL_ERRS);

	if (afsr_errs) {

		bzero(&ch_flt, sizeof (ch_async_flt_t));
		aflt = (struct async_flt *)&ch_flt;
		aflt->flt_id = gethrtime_waitfree();
		aflt->flt_bus_id = getprocessorid();
		aflt->flt_inst = CPU->cpu_id;
		aflt->flt_stat = cpu_error_regs.afsr;
		aflt->flt_addr = cpu_error_regs.afar;
		aflt->flt_prot = AFLT_PROT_NONE;
		aflt->flt_class = CPU_FAULT;
		aflt->flt_priv = ((cpu_error_regs.afsr & C_AFSR_PRIV) != 0);
		aflt->flt_panic = 1;
		ch_flt.afsr_ext = cpu_error_regs.afsr_ext;
		ch_flt.afsr_errs = afsr_errs;
#if defined(SERRANO)
		ch_flt.afar2 = cpu_error_regs.afar2;
#endif	/* SERRANO */
		(void) cpu_queue_events(&ch_flt, NULL, afsr_errs, NULL);
	}
}

/*
 * Routine to convert a syndrome into a syndrome code.
 */
static int
synd_to_synd_code(int synd_status, ushort_t synd, uint64_t afsr_bit)
{
	if (synd_status == AFLT_STAT_INVALID)
		return (-1);

	/*
	 * Use the syndrome to index the appropriate syndrome table,
	 * to get the code indicating which bit(s) is(are) bad.
	 */
	if (afsr_bit &
	    (C_AFSR_MSYND_ERRS | C_AFSR_ESYND_ERRS | C_AFSR_EXT_ESYND_ERRS)) {
		if (afsr_bit & C_AFSR_MSYND_ERRS) {
#if defined(JALAPENO) || defined(SERRANO)
			if ((synd == 0) || (synd >= BSYND_TBL_SIZE))
				return (-1);
			else
				return (BPAR0 + synd);
#else /* JALAPENO || SERRANO */
			if ((synd == 0) || (synd >= MSYND_TBL_SIZE))
				return (-1);
			else
				return (mtag_syndrome_tab[synd]);
#endif /* JALAPENO || SERRANO */
		} else {
			if ((synd == 0) || (synd >= ESYND_TBL_SIZE))
				return (-1);
			else
				return (ecc_syndrome_tab[synd]);
		}
	} else {
		return (-1);
	}
}

int
cpu_get_mem_sid(char *unum, char *buf, int buflen, int *lenp)
{
	if (&plat_get_mem_sid)
		return (plat_get_mem_sid(unum, buf, buflen, lenp));
	else
		return (ENOTSUP);
}

int
cpu_get_mem_offset(uint64_t flt_addr, uint64_t *offp)
{
	if (&plat_get_mem_offset)
		return (plat_get_mem_offset(flt_addr, offp));
	else
		return (ENOTSUP);
}

int
cpu_get_mem_addr(char *unum, char *sid, uint64_t offset, uint64_t *addrp)
{
	if (&plat_get_mem_addr)
		return (plat_get_mem_addr(unum, sid, offset, addrp));
	else
		return (ENOTSUP);
}

/*
 * Routine to return a string identifying the physical name
 * associated with a memory/cache error.
 */
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
	if (flt_stat == (uint64_t)-1)
		flt_stat = C_AFSR_CE;

	synd_code = synd_to_synd_code(synd_status, flt_synd, flt_stat);

	/*
	 * Syndrome code must be either a single-bit error code
	 * (0...143) or -1 for unum lookup.
	 */
	if (synd_code < 0 || synd_code >= M2)
		synd_code = -1;
	if (&plat_get_mem_unum) {
		if ((ret = plat_get_mem_unum(synd_code, flt_addr, flt_bus_id,
		    flt_in_memory, flt_status, buf, buflen, lenp)) != 0) {
			buf[0] = '\0';
			*lenp = 0;
		}

		return (ret);
	}

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
	 * If we come thru here for an IO bus error aflt->flt_stat will
	 * not be the CPU AFSR, and we pass in a -1 to cpu_get_mem_unum()
	 * so it will interpret this as a memory error.
	 */
	return (cpu_get_mem_unum(synd_status, aflt->flt_synd,
	    (aflt->flt_class == BUS_FAULT) ?
	    (uint64_t)-1 : ((ch_async_flt_t *)aflt)->flt_bit,
	    aflt->flt_addr, aflt->flt_bus_id, aflt->flt_in_memory,
	    aflt->flt_status, buf, buflen, lenp));
}

/*
 * Return unum string given synd_code and async_flt into
 * the buf with size UNUM_NAMLEN
 */
static int
cpu_get_mem_unum_synd(int synd_code, struct async_flt *aflt, char *buf)
{
	int ret, len;

	/*
	 * Syndrome code must be either a single-bit error code
	 * (0...143) or -1 for unum lookup.
	 */
	if (synd_code < 0 || synd_code >= M2)
		synd_code = -1;
	if (&plat_get_mem_unum) {
		if ((ret = plat_get_mem_unum(synd_code, aflt->flt_addr,
		    aflt->flt_bus_id, aflt->flt_in_memory,
		    aflt->flt_status, buf, UNUM_NAMLEN, &len)) != 0) {
			buf[0] = '\0';
		}
		return (ret);
	}

	buf[0] = '\0';
	return (ENOTSUP);
}

/*
 * This routine is a more generic interface to cpu_get_mem_unum()
 * that may be used by other modules (e.g. the 'mm' driver, through
 * the 'MEM_NAME' ioctl, which is used by fmd to resolve unum's
 * for Jalapeno/Serrano FRC/RCE or FRU/RUE paired events).
 */
int
cpu_get_mem_name(uint64_t synd, uint64_t *afsr, uint64_t afar,
    char *buf, int buflen, int *lenp)
{
	int synd_status, flt_in_memory, ret;
	ushort_t flt_status = 0;
	char unum[UNUM_NAMLEN];
	uint64_t t_afsr_errs;

	/*
	 * Check for an invalid address.
	 */
	if (afar == (uint64_t)-1)
		return (ENXIO);

	if (synd == (uint64_t)-1)
		synd_status = AFLT_STAT_INVALID;
	else
		synd_status = AFLT_STAT_VALID;

	flt_in_memory = (*afsr & C_AFSR_MEMORY) &&
	    pf_is_memory(afar >> MMU_PAGESHIFT);

	/*
	 * Get aggregate AFSR for call to cpu_error_is_ecache_data.
	 */
	if (*afsr == (uint64_t)-1)
		t_afsr_errs = C_AFSR_CE;
	else {
		t_afsr_errs = (*afsr & C_AFSR_ALL_ERRS);
#if defined(CHEETAH_PLUS)
		if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation))
			t_afsr_errs |= (*(afsr + 1) & C_AFSR_EXT_ALL_ERRS);
#endif	/* CHEETAH_PLUS */
	}

	/*
	 * Turn on ECC_ECACHE if error type is E$ Data.
	 */
	if (cpu_error_is_ecache_data(CPU->cpu_id, t_afsr_errs))
		flt_status |= ECC_ECACHE;

	ret = cpu_get_mem_unum(synd_status, (ushort_t)synd, t_afsr_errs, afar,
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
int
cpu_get_mem_info(uint64_t synd, uint64_t afar,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp)
{
	int synd_status, synd_code;

	if (afar == (uint64_t)-1)
		return (ENXIO);

	if (synd == (uint64_t)-1)
		synd_status = AFLT_STAT_INVALID;
	else
		synd_status = AFLT_STAT_VALID;

	synd_code = synd_to_synd_code(synd_status, synd, C_AFSR_CE);

	if (p2get_mem_info != NULL)
		return ((p2get_mem_info)(synd_code, afar,
		    mem_sizep, seg_sizep, bank_sizep,
		    segsp, banksp, mcidp));
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
		if ((ret = plat_get_cpu_unum(cpuid, unum, UNUM_NAMLEN, lenp))
		    != 0)
			return (ret);
	} else {
		return (ENOTSUP);
	}

	if (*lenp >= buflen)
		return (ENAMETOOLONG);

	(void) strncpy(buf, unum, buflen);

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
 * Historical function, apparantly not used.
 */
/* ARGSUSED */
void
cpu_read_paddr(struct async_flt *ecc, short verbose, short ce_err)
{}

/*
 * Historical function only called for SBus errors in debugging.
 */
/*ARGSUSED*/
void
read_ecc_data(struct async_flt *aflt, short verbose, short ce_err)
{}

/*
 * Clear the AFSR sticky bits.  The routine returns a non-zero value if
 * any of the AFSR's sticky errors are detected.  If a non-null pointer to
 * an async fault structure argument is passed in, the captured error state
 * (AFSR, AFAR) info will be returned in the structure.
 */
int
clear_errors(ch_async_flt_t *ch_flt)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	ch_cpu_errors_t	cpu_error_regs;

	get_cpu_error_state(&cpu_error_regs);

	if (ch_flt != NULL) {
		aflt->flt_stat = cpu_error_regs.afsr & C_AFSR_MASK;
		aflt->flt_addr = cpu_error_regs.afar;
		ch_flt->afsr_ext = cpu_error_regs.afsr_ext;
		ch_flt->afsr_errs = (cpu_error_regs.afsr & C_AFSR_ALL_ERRS) |
		    (cpu_error_regs.afsr_ext & C_AFSR_EXT_ALL_ERRS);
#if defined(SERRANO)
		ch_flt->afar2 = cpu_error_regs.afar2;
#endif	/* SERRANO */
	}

	set_cpu_error_state(&cpu_error_regs);

	return (((cpu_error_regs.afsr & C_AFSR_ALL_ERRS) |
	    (cpu_error_regs.afsr_ext & C_AFSR_EXT_ALL_ERRS)) != 0);
}

/*
 * Clear any AFSR error bits, and check for persistence.
 *
 * It would be desirable to also insist that syndrome match.  PCI handling
 * has already filled flt_synd.  For errors trapped by CPU we only fill
 * flt_synd when we queue the event, so we do not have a valid flt_synd
 * during initial classification (it is valid if we're called as part of
 * subsequent low-pil additional classification attempts).  We could try
 * to determine which syndrome to use: we know we're only called for
 * CE/RCE (Jalapeno & Serrano) and CE/EMC (others) so the syndrome to use
 * would be esynd/none and esynd/msynd, respectively.  If that is
 * implemented then what do we do in the case that we do experience an
 * error on the same afar but with different syndrome?  At the very least
 * we should count such occurences.  Anyway, for now, we'll leave it as
 * it has been for ages.
 */
static int
clear_ecc(struct async_flt *aflt)
{
	ch_cpu_errors_t	cpu_error_regs;

	/*
	 * Snapshot the AFSR and AFAR and clear any errors
	 */
	get_cpu_error_state(&cpu_error_regs);
	set_cpu_error_state(&cpu_error_regs);

	/*
	 * If any of the same memory access error bits are still on and
	 * the AFAR matches, return that the error is persistent.
	 */
	return ((cpu_error_regs.afsr & (C_AFSR_MEMORY & aflt->flt_stat)) != 0 &&
	    cpu_error_regs.afar == aflt->flt_addr);
}

/*
 * Turn off all cpu error detection, normally only used for panics.
 */
void
cpu_disable_errors(void)
{
	xt_all(set_error_enable_tl1, EN_REG_DISABLE, EER_SET_ABSOLUTE);

	/*
	 * With error detection now turned off, check the other cpus
	 * logout areas for any unlogged errors.
	 */
	if (enable_check_other_cpus_logout) {
		cpu_check_other_cpus_logout();
		/*
		 * Make a second pass over the logout areas, in case
		 * there is a failing CPU in an error-trap loop which
		 * will write to the logout area once it is emptied.
		 */
		cpu_check_other_cpus_logout();
	}
}

/*
 * Enable errors.
 */
void
cpu_enable_errors(void)
{
	xt_all(set_error_enable_tl1, EN_REG_ENABLE, EER_SET_ABSOLUTE);
}

/*
 * Flush the entire ecache using displacement flush by reading through a
 * physical address range twice as large as the Ecache.
 */
void
cpu_flush_ecache(void)
{
	flush_ecache(ecache_flushaddr, cpunodes[CPU->cpu_id].ecache_size,
	    cpunodes[CPU->cpu_id].ecache_linesize);
}

/*
 * Return CPU E$ set size - E$ size divided by the associativity.
 * We use this function in places where the CPU_PRIVATE ptr may not be
 * initialized yet.  Note that for send_mondo and in the Ecache scrubber,
 * we're guaranteed that CPU_PRIVATE is initialized.  Also, cpunodes is set
 * up before the kernel switches from OBP's to the kernel's trap table, so
 * we don't have to worry about cpunodes being unitialized.
 */
int
cpu_ecache_set_size(struct cpu *cp)
{
	if (CPU_PRIVATE(cp))
		return (CPU_PRIVATE_VAL(cp, chpr_ec_set_size));

	return (cpunodes[cp->cpu_id].ecache_size / cpu_ecache_nway());
}

/*
 * Flush Ecache line.
 * Uses ASI_EC_DIAG for Cheetah+ and Jalapeno.
 * Uses normal displacement flush for Cheetah.
 */
static void
cpu_flush_ecache_line(ch_async_flt_t *ch_flt)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	int ec_set_size = cpu_ecache_set_size(CPU);

	ecache_flush_line(aflt->flt_addr, ec_set_size);
}

/*
 * Scrub physical address.
 * Scrub code is different depending upon whether this a Cheetah+ with 2-way
 * Ecache or direct-mapped Ecache.
 */
static void
cpu_scrubphys(struct async_flt *aflt)
{
	int ec_set_size = cpu_ecache_set_size(CPU);

	scrubphys(aflt->flt_addr, ec_set_size);
}

/*
 * Clear physical address.
 * Scrub code is different depending upon whether this a Cheetah+ with 2-way
 * Ecache or direct-mapped Ecache.
 */
void
cpu_clearphys(struct async_flt *aflt)
{
	int lsize = cpunodes[CPU->cpu_id].ecache_linesize;
	int ec_set_size = cpu_ecache_set_size(CPU);


	clearphys(aflt->flt_addr, ec_set_size, lsize);
}

#if defined(CPU_IMP_ECACHE_ASSOC)
/*
 * Check for a matching valid line in all the sets.
 * If found, return set# + 1. Otherwise return 0.
 */
static int
cpu_ecache_line_valid(ch_async_flt_t *ch_flt)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	int totalsize = cpunodes[CPU->cpu_id].ecache_size;
	int ec_set_size = cpu_ecache_set_size(CPU);
	ch_ec_data_t *ecp = &ch_flt->flt_diag_data.chd_ec_data[0];
	int nway = cpu_ecache_nway();
	int i;

	for (i = 0; i < nway; i++, ecp++) {
		if (!cpu_ectag_line_invalid(totalsize, ecp->ec_tag) &&
		    (aflt->flt_addr & P2ALIGN(C_AFAR_PA, ec_set_size)) ==
		    cpu_ectag_to_pa(ec_set_size, ecp->ec_tag))
			return (i+1);
	}
	return (0);
}
#endif /* CPU_IMP_ECACHE_ASSOC */

/*
 * Check whether a line in the given logout info matches the specified
 * fault address.  If reqval is set then the line must not be Invalid.
 * Returns 0 on failure;  on success (way + 1) is returned an *level is
 * set to 2 for l2$ or 3 for l3$.
 */
static int
cpu_matching_ecache_line(uint64_t faddr, void *data, int reqval, int *level)
{
	ch_diag_data_t *cdp = data;
	ch_ec_data_t *ecp;
	int totalsize, ec_set_size;
	int i, ways;
	int match = 0;
	int tagvalid;
	uint64_t addr, tagpa;
	int ispanther = IS_PANTHER(cpunodes[CPU->cpu_id].implementation);

	/*
	 * Check the l2$ logout data
	 */
	if (ispanther) {
		ecp = &cdp->chd_l2_data[0];
		ec_set_size = PN_L2_SET_SIZE;
		ways = PN_L2_NWAYS;
	} else {
		ecp = &cdp->chd_ec_data[0];
		ec_set_size = cpu_ecache_set_size(CPU);
		ways = cpu_ecache_nway();
		totalsize = cpunodes[CPU->cpu_id].ecache_size;
	}
	/* remove low order PA bits from fault address not used in PA tag */
	addr = faddr & P2ALIGN(C_AFAR_PA, ec_set_size);
	for (i = 0; i < ways; i++, ecp++) {
		if (ispanther) {
			tagpa = PN_L2TAG_TO_PA(ecp->ec_tag);
			tagvalid = !PN_L2_LINE_INVALID(ecp->ec_tag);
		} else {
			tagpa = cpu_ectag_to_pa(ec_set_size, ecp->ec_tag);
			tagvalid = !cpu_ectag_line_invalid(totalsize,
			    ecp->ec_tag);
		}
		if (tagpa == addr && (!reqval || tagvalid)) {
			match = i + 1;
			*level = 2;
			break;
		}
	}

	if (match || !ispanther)
		return (match);

	/* For Panther we also check the l3$ */
	ecp = &cdp->chd_ec_data[0];
	ec_set_size = PN_L3_SET_SIZE;
	ways = PN_L3_NWAYS;
	addr = faddr & P2ALIGN(C_AFAR_PA, ec_set_size);

	for (i = 0; i < ways; i++, ecp++) {
		if (PN_L3TAG_TO_PA(ecp->ec_tag) == addr && (!reqval ||
		    !PN_L3_LINE_INVALID(ecp->ec_tag))) {
			match = i + 1;
			*level = 3;
			break;
		}
	}

	return (match);
}

#if defined(CPU_IMP_L1_CACHE_PARITY)
/*
 * Record information related to the source of an Dcache Parity Error.
 */
static void
cpu_dcache_parity_info(ch_async_flt_t *ch_flt)
{
	int dc_set_size = dcache_size / CH_DCACHE_NWAY;
	int index;

	/*
	 * Since instruction decode cannot be done at high PIL
	 * just examine the entire Dcache to locate the error.
	 */
	if (ch_flt->parity_data.dpe.cpl_lcnt == 0) {
		ch_flt->parity_data.dpe.cpl_way = -1;
		ch_flt->parity_data.dpe.cpl_off = -1;
	}
	for (index = 0; index < dc_set_size; index += dcache_linesize)
		cpu_dcache_parity_check(ch_flt, index);
}

/*
 * Check all ways of the Dcache at a specified index for good parity.
 */
static void
cpu_dcache_parity_check(ch_async_flt_t *ch_flt, int index)
{
	int dc_set_size = dcache_size / CH_DCACHE_NWAY;
	uint64_t parity_bits, pbits, data_word;
	static int parity_bits_popc[] = { 0, 1, 1, 0 };
	int way, word, data_byte;
	ch_dc_data_t *dcp = &ch_flt->parity_data.dpe.cpl_dc[0];
	ch_dc_data_t tmp_dcp;

	for (way = 0; way < CH_DCACHE_NWAY; way++, dcp++) {
		/*
		 * Perform diagnostic read.
		 */
		get_dcache_dtag(index + way * dc_set_size,
		    (uint64_t *)&tmp_dcp);

		/*
		 * Check tag for even parity.
		 * Sum of 1 bits (including parity bit) should be even.
		 */
		if (popc64(tmp_dcp.dc_tag & CHP_DCTAG_PARMASK) & 1) {
			/*
			 * If this is the first error log detailed information
			 * about it and check the snoop tag. Otherwise just
			 * record the fact that we found another error.
			 */
			if (ch_flt->parity_data.dpe.cpl_lcnt == 0) {
				ch_flt->parity_data.dpe.cpl_way = way;
				ch_flt->parity_data.dpe.cpl_cache =
				    CPU_DC_PARITY;
				ch_flt->parity_data.dpe.cpl_tag |= CHP_DC_TAG;

				if (popc64(tmp_dcp.dc_sntag &
				    CHP_DCSNTAG_PARMASK) & 1) {
					ch_flt->parity_data.dpe.cpl_tag |=
					    CHP_DC_SNTAG;
					ch_flt->parity_data.dpe.cpl_lcnt++;
				}

				bcopy(&tmp_dcp, dcp, sizeof (ch_dc_data_t));
			}

			ch_flt->parity_data.dpe.cpl_lcnt++;
		}

		if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
			/*
			 * Panther has more parity bits than the other
			 * processors for covering dcache data and so each
			 * byte of data in each word has its own parity bit.
			 */
			parity_bits = tmp_dcp.dc_pn_data_parity;
			for (word = 0; word < 4; word++) {
				data_word = tmp_dcp.dc_data[word];
				pbits = parity_bits & PN_DC_DATA_PARITY_MASK;
				for (data_byte = 0; data_byte < 8;
				    data_byte++) {
					if (((popc64(data_word &
					    PN_DC_DATA_PARITY_MASK)) & 1) ^
					    (pbits & 1)) {
						cpu_record_dc_data_parity(
						    ch_flt, dcp, &tmp_dcp, way,
						    word);
					}
					pbits >>= 1;
					data_word >>= 8;
				}
				parity_bits >>= 8;
			}
		} else {
			/*
			 * Check data array for even parity.
			 * The 8 parity bits are grouped into 4 pairs each
			 * of which covers a 64-bit word.  The endianness is
			 * reversed -- the low-order parity bits cover the
			 * high-order data words.
			 */
			parity_bits = tmp_dcp.dc_utag >> 8;
			for (word = 0; word < 4; word++) {
				pbits = (parity_bits >> (6 - word * 2)) & 3;
				if ((popc64(tmp_dcp.dc_data[word]) +
				    parity_bits_popc[pbits]) & 1) {
					cpu_record_dc_data_parity(ch_flt, dcp,
					    &tmp_dcp, way, word);
				}
			}
		}
	}
}

static void
cpu_record_dc_data_parity(ch_async_flt_t *ch_flt,
    ch_dc_data_t *dest_dcp, ch_dc_data_t *src_dcp, int way, int word)
{
	/*
	 * If this is the first error log detailed information about it.
	 * Otherwise just record the fact that we found another error.
	 */
	if (ch_flt->parity_data.dpe.cpl_lcnt == 0) {
		ch_flt->parity_data.dpe.cpl_way = way;
		ch_flt->parity_data.dpe.cpl_cache = CPU_DC_PARITY;
		ch_flt->parity_data.dpe.cpl_off = word * 8;
		bcopy(src_dcp, dest_dcp, sizeof (ch_dc_data_t));
	}
	ch_flt->parity_data.dpe.cpl_lcnt++;
}

/*
 * Record information related to the source of an Icache Parity Error.
 *
 * Called with the Icache disabled so any diagnostic accesses are safe.
 */
static void
cpu_icache_parity_info(ch_async_flt_t *ch_flt)
{
	int	ic_set_size;
	int	ic_linesize;
	int	index;

	if (CPU_PRIVATE(CPU)) {
		ic_set_size = CPU_PRIVATE_VAL(CPU, chpr_icache_size) /
		    CH_ICACHE_NWAY;
		ic_linesize = CPU_PRIVATE_VAL(CPU, chpr_icache_linesize);
	} else {
		ic_set_size = icache_size / CH_ICACHE_NWAY;
		ic_linesize = icache_linesize;
	}

	ch_flt->parity_data.ipe.cpl_way = -1;
	ch_flt->parity_data.ipe.cpl_off = -1;

	for (index = 0; index < ic_set_size; index += ic_linesize)
		cpu_icache_parity_check(ch_flt, index);
}

/*
 * Check all ways of the Icache at a specified index for good parity.
 */
static void
cpu_icache_parity_check(ch_async_flt_t *ch_flt, int index)
{
	uint64_t parmask, pn_inst_parity;
	int ic_set_size;
	int ic_linesize;
	int flt_index, way, instr, num_instr;
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	ch_ic_data_t *icp = &ch_flt->parity_data.ipe.cpl_ic[0];
	ch_ic_data_t tmp_icp;

	if (CPU_PRIVATE(CPU)) {
		ic_set_size = CPU_PRIVATE_VAL(CPU, chpr_icache_size) /
		    CH_ICACHE_NWAY;
		ic_linesize = CPU_PRIVATE_VAL(CPU, chpr_icache_linesize);
	} else {
		ic_set_size = icache_size / CH_ICACHE_NWAY;
		ic_linesize = icache_linesize;
	}

	/*
	 * Panther has twice as many instructions per icache line and the
	 * instruction parity bit is in a different location.
	 */
	if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
		num_instr = PN_IC_DATA_REG_SIZE / sizeof (uint64_t);
		pn_inst_parity = PN_ICDATA_PARITY_BIT_MASK;
	} else {
		num_instr = CH_IC_DATA_REG_SIZE / sizeof (uint64_t);
		pn_inst_parity = 0;
	}

	/*
	 * Index at which we expect to find the parity error.
	 */
	flt_index = P2ALIGN(aflt->flt_addr % ic_set_size, ic_linesize);

	for (way = 0; way < CH_ICACHE_NWAY; way++, icp++) {
		/*
		 * Diagnostic reads expect address argument in ASI format.
		 */
		get_icache_dtag(2 * (index + way * ic_set_size),
		    (uint64_t *)&tmp_icp);

		/*
		 * If this is the index in which we expect to find the
		 * error log detailed information about each of the ways.
		 * This information will be displayed later if we can't
		 * determine the exact way in which the error is located.
		 */
		if (flt_index == index)
			bcopy(&tmp_icp, icp, sizeof (ch_ic_data_t));

		/*
		 * Check tag for even parity.
		 * Sum of 1 bits (including parity bit) should be even.
		 */
		if (popc64(tmp_icp.ic_patag & CHP_ICPATAG_PARMASK) & 1) {
			/*
			 * If this way is the one in which we expected
			 * to find the error record the way and check the
			 * snoop tag. Otherwise just record the fact we
			 * found another error.
			 */
			if (flt_index == index) {
				ch_flt->parity_data.ipe.cpl_way = way;
				ch_flt->parity_data.ipe.cpl_tag |= CHP_IC_TAG;

				if (popc64(tmp_icp.ic_sntag &
				    CHP_ICSNTAG_PARMASK) & 1) {
					ch_flt->parity_data.ipe.cpl_tag |=
					    CHP_IC_SNTAG;
					ch_flt->parity_data.ipe.cpl_lcnt++;
				}

			}
			ch_flt->parity_data.ipe.cpl_lcnt++;
			continue;
		}

		/*
		 * Check instruction data for even parity.
		 * Bits participating in parity differ for PC-relative
		 * versus non-PC-relative instructions.
		 */
		for (instr = 0; instr < num_instr; instr++) {
			parmask = (tmp_icp.ic_data[instr] &
			    CH_ICDATA_PRED_ISPCREL) ?
			    (CHP_ICDATA_PCREL_PARMASK | pn_inst_parity) :
			    (CHP_ICDATA_NPCREL_PARMASK | pn_inst_parity);
			if (popc64(tmp_icp.ic_data[instr] & parmask) & 1) {
				/*
				 * If this way is the one in which we expected
				 * to find the error record the way and offset.
				 * Otherwise just log the fact we found another
				 * error.
				 */
				if (flt_index == index) {
					ch_flt->parity_data.ipe.cpl_way = way;
					ch_flt->parity_data.ipe.cpl_off =
					    instr * 4;
				}
				ch_flt->parity_data.ipe.cpl_lcnt++;
				continue;
			}
		}
	}
}

/*
 * Record information related to the source of an Pcache Parity Error.
 */
static void
cpu_pcache_parity_info(ch_async_flt_t *ch_flt)
{
	int pc_set_size = CH_PCACHE_SIZE / CH_PCACHE_NWAY;
	int index;

	/*
	 * Since instruction decode cannot be done at high PIL just
	 * examine the entire Pcache to check for any parity errors.
	 */
	if (ch_flt->parity_data.dpe.cpl_lcnt == 0) {
		ch_flt->parity_data.dpe.cpl_way = -1;
		ch_flt->parity_data.dpe.cpl_off = -1;
	}
	for (index = 0; index < pc_set_size; index += CH_PCACHE_LSIZE)
		cpu_pcache_parity_check(ch_flt, index);
}

/*
 * Check all ways of the Pcache at a specified index for good parity.
 */
static void
cpu_pcache_parity_check(ch_async_flt_t *ch_flt, int index)
{
	int pc_set_size = CH_PCACHE_SIZE / CH_PCACHE_NWAY;
	int pc_data_words = CH_PC_DATA_REG_SIZE / sizeof (uint64_t);
	int way, word, pbit, parity_bits;
	ch_pc_data_t *pcp = &ch_flt->parity_data.dpe.cpl_pc[0];
	ch_pc_data_t tmp_pcp;

	for (way = 0; way < CH_PCACHE_NWAY; way++, pcp++) {
		/*
		 * Perform diagnostic read.
		 */
		get_pcache_dtag(index + way * pc_set_size,
		    (uint64_t *)&tmp_pcp);
		/*
		 * Check data array for odd parity. There are 8 parity
		 * bits (bits 57:50 of ASI_PCACHE_STATUS_DATA) and each
		 * of those bits covers exactly 8 bytes of the data
		 * array:
		 *
		 *	parity bit	P$ data bytes covered
		 *	----------	---------------------
		 *	50		63:56
		 *	51		55:48
		 *	52		47:40
		 *	53		39:32
		 *	54		31:24
		 *	55		23:16
		 *	56		15:8
		 *	57		7:0
		 */
		parity_bits = PN_PC_PARITY_BITS(tmp_pcp.pc_status);
		for (word = 0; word < pc_data_words; word++) {
			pbit = (parity_bits >> (pc_data_words - word - 1)) & 1;
			if ((popc64(tmp_pcp.pc_data[word]) & 1) ^ pbit) {
				/*
				 * If this is the first error log detailed
				 * information about it. Otherwise just record
				 * the fact that we found another error.
				 */
				if (ch_flt->parity_data.dpe.cpl_lcnt == 0) {
					ch_flt->parity_data.dpe.cpl_way = way;
					ch_flt->parity_data.dpe.cpl_cache =
					    CPU_PC_PARITY;
					ch_flt->parity_data.dpe.cpl_off =
					    word * sizeof (uint64_t);
					bcopy(&tmp_pcp, pcp,
					    sizeof (ch_pc_data_t));
				}
				ch_flt->parity_data.dpe.cpl_lcnt++;
			}
		}
	}
}


/*
 * Add L1 Data cache data to the ereport payload.
 */
static void
cpu_payload_add_dcache(struct async_flt *aflt, nvlist_t *nvl)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;
	ch_dc_data_t *dcp;
	ch_dc_data_t dcdata[CH_DCACHE_NWAY];
	uint_t nelem;
	int i, ways_to_check, ways_logged = 0;

	/*
	 * If this is an D$ fault then there may be multiple
	 * ways captured in the ch_parity_log_t structure.
	 * Otherwise, there will be at most one way captured
	 * in the ch_diag_data_t struct.
	 * Check each way to see if it should be encoded.
	 */
	if (ch_flt->flt_type == CPU_DC_PARITY)
		ways_to_check = CH_DCACHE_NWAY;
	else
		ways_to_check = 1;
	for (i = 0; i < ways_to_check; i++) {
		if (ch_flt->flt_type == CPU_DC_PARITY)
			dcp = &ch_flt->parity_data.dpe.cpl_dc[i];
		else
			dcp = &ch_flt->flt_diag_data.chd_dc_data;
		if (dcp->dc_logflag == DC_LOGFLAG_MAGIC) {
			bcopy(dcp, &dcdata[ways_logged],
			    sizeof (ch_dc_data_t));
			ways_logged++;
		}
	}

	/*
	 * Add the dcache data to the payload.
	 */
	fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L1D_WAYS,
	    DATA_TYPE_UINT8, (uint8_t)ways_logged, NULL);
	if (ways_logged != 0) {
		nelem = sizeof (ch_dc_data_t) / sizeof (uint64_t) * ways_logged;
		fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L1D_DATA,
		    DATA_TYPE_UINT64_ARRAY, nelem, (uint64_t *)dcdata, NULL);
	}
}

/*
 * Add L1 Instruction cache data to the ereport payload.
 */
static void
cpu_payload_add_icache(struct async_flt *aflt, nvlist_t *nvl)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;
	ch_ic_data_t *icp;
	ch_ic_data_t icdata[CH_ICACHE_NWAY];
	uint_t nelem;
	int i, ways_to_check, ways_logged = 0;

	/*
	 * If this is an I$ fault then there may be multiple
	 * ways captured in the ch_parity_log_t structure.
	 * Otherwise, there will be at most one way captured
	 * in the ch_diag_data_t struct.
	 * Check each way to see if it should be encoded.
	 */
	if (ch_flt->flt_type == CPU_IC_PARITY)
		ways_to_check = CH_ICACHE_NWAY;
	else
		ways_to_check = 1;
	for (i = 0; i < ways_to_check; i++) {
		if (ch_flt->flt_type == CPU_IC_PARITY)
			icp = &ch_flt->parity_data.ipe.cpl_ic[i];
		else
			icp = &ch_flt->flt_diag_data.chd_ic_data;
		if (icp->ic_logflag == IC_LOGFLAG_MAGIC) {
			bcopy(icp, &icdata[ways_logged],
			    sizeof (ch_ic_data_t));
			ways_logged++;
		}
	}

	/*
	 * Add the icache data to the payload.
	 */
	fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L1I_WAYS,
	    DATA_TYPE_UINT8, (uint8_t)ways_logged, NULL);
	if (ways_logged != 0) {
		nelem = sizeof (ch_ic_data_t) / sizeof (uint64_t) * ways_logged;
		fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L1I_DATA,
		    DATA_TYPE_UINT64_ARRAY, nelem, (uint64_t *)icdata, NULL);
	}
}

#endif	/* CPU_IMP_L1_CACHE_PARITY */

/*
 * Add ecache data to payload.
 */
static void
cpu_payload_add_ecache(struct async_flt *aflt, nvlist_t *nvl)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;
	ch_ec_data_t *ecp;
	ch_ec_data_t ecdata[CHD_EC_DATA_SETS];
	uint_t nelem;
	int i, ways_logged = 0;

	/*
	 * Check each way to see if it should be encoded
	 * and concatinate it into a temporary buffer.
	 */
	for (i = 0; i < CHD_EC_DATA_SETS; i++) {
		ecp = &ch_flt->flt_diag_data.chd_ec_data[i];
		if (ecp->ec_logflag == EC_LOGFLAG_MAGIC) {
			bcopy(ecp, &ecdata[ways_logged],
			    sizeof (ch_ec_data_t));
			ways_logged++;
		}
	}

	/*
	 * Panther CPUs have an additional level of cache and so
	 * what we just collected was the L3 (ecache) and not the
	 * L2 cache.
	 */
	if (IS_PANTHER(cpunodes[aflt->flt_inst].implementation)) {
		/*
		 * Add the L3 (ecache) data to the payload.
		 */
		fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L3_WAYS,
		    DATA_TYPE_UINT8, (uint8_t)ways_logged, NULL);
		if (ways_logged != 0) {
			nelem = sizeof (ch_ec_data_t) /
			    sizeof (uint64_t) * ways_logged;
			fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L3_DATA,
			    DATA_TYPE_UINT64_ARRAY, nelem,
			    (uint64_t *)ecdata, NULL);
		}

		/*
		 * Now collect the L2 cache.
		 */
		ways_logged = 0;
		for (i = 0; i < PN_L2_NWAYS; i++) {
			ecp = &ch_flt->flt_diag_data.chd_l2_data[i];
			if (ecp->ec_logflag == EC_LOGFLAG_MAGIC) {
				bcopy(ecp, &ecdata[ways_logged],
				    sizeof (ch_ec_data_t));
				ways_logged++;
			}
		}
	}

	/*
	 * Add the L2 cache data to the payload.
	 */
	fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L2_WAYS,
	    DATA_TYPE_UINT8, (uint8_t)ways_logged, NULL);
	if (ways_logged != 0) {
		nelem = sizeof (ch_ec_data_t) /
		    sizeof (uint64_t) * ways_logged;
		fm_payload_set(nvl, FM_EREPORT_PAYLOAD_NAME_L2_DATA,
		    DATA_TYPE_UINT64_ARRAY, nelem,  (uint64_t *)ecdata, NULL);
	}
}

/*
 * Initialize cpu scheme for specified cpu.
 */
static void
cpu_fmri_cpu_set(nvlist_t *cpu_fmri, int cpuid)
{
	char sbuf[21]; /* sizeof (UINT64_MAX) + '\0' */
	uint8_t mask;

	mask = cpunodes[cpuid].version;
	(void) snprintf(sbuf, sizeof (sbuf), "%llX",
	    (u_longlong_t)cpunodes[cpuid].device_id);
	(void) fm_fmri_cpu_set(cpu_fmri, FM_CPU_SCHEME_VERSION, NULL,
	    cpuid, &mask, (const char *)sbuf);
}

/*
 * Returns ereport resource type.
 */
static int
cpu_error_to_resource_type(struct async_flt *aflt)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;

	switch (ch_flt->flt_type) {

	case CPU_CE_ECACHE:
	case CPU_UE_ECACHE:
	case CPU_UE_ECACHE_RETIRE:
	case CPU_ORPH:
		/*
		 * If AFSR error bit indicates L2$ Data for Cheetah,
		 * Cheetah+ or Jaguar, or L3$ Data for Panther, return
		 * E$ Data type, otherwise, return CPU type.
		 */
		if (cpu_error_is_ecache_data(aflt->flt_inst,
		    ch_flt->flt_bit))
			return (ERRTYPE_ECACHE_DATA);
		return (ERRTYPE_CPU);

	case CPU_CE:
	case CPU_UE:
	case CPU_EMC:
	case CPU_DUE:
	case CPU_RCE:
	case CPU_RUE:
	case CPU_FRC:
	case CPU_FRU:
		return (ERRTYPE_MEMORY);

	case CPU_IC_PARITY:
	case CPU_DC_PARITY:
	case CPU_FPUERR:
	case CPU_PC_PARITY:
	case CPU_ITLB_PARITY:
	case CPU_DTLB_PARITY:
		return (ERRTYPE_CPU);
	}
	return (ERRTYPE_UNKNOWN);
}

/*
 * Encode the data saved in the ch_async_flt_t struct into
 * the FM ereport payload.
 */
static void
cpu_payload_add_aflt(struct async_flt *aflt, nvlist_t *payload,
	nvlist_t *resource, int *afar_status, int *synd_status)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;
	*synd_status = AFLT_STAT_INVALID;
	*afar_status = AFLT_STAT_INVALID;

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_AFSR) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_AFSR,
		    DATA_TYPE_UINT64, aflt->flt_stat, NULL);
	}

	if ((aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_AFSR_EXT) &&
	    IS_PANTHER(cpunodes[aflt->flt_inst].implementation)) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_AFSR_EXT,
		    DATA_TYPE_UINT64, ch_flt->afsr_ext, NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_AFAR_STATUS) {
		*afar_status = afsr_to_afar_status(ch_flt->afsr_errs,
		    ch_flt->flt_bit);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_AFAR_STATUS,
		    DATA_TYPE_UINT8, (uint8_t)*afar_status, NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_AFAR) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_AFAR,
		    DATA_TYPE_UINT64, aflt->flt_addr, NULL);
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

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_ME) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ME,
		    DATA_TYPE_BOOLEAN_VALUE,
		    (aflt->flt_stat & C_AFSR_ME) ? B_TRUE : B_FALSE, NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_SYND_STATUS) {
		*synd_status = afsr_to_synd_status(aflt->flt_inst,
		    ch_flt->afsr_errs, ch_flt->flt_bit);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SYND_STATUS,
		    DATA_TYPE_UINT8, (uint8_t)*synd_status, NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_SYND) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SYND,
		    DATA_TYPE_UINT16, (uint16_t)aflt->flt_synd, NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_ERR_TYPE) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ERR_TYPE,
		    DATA_TYPE_STRING, flt_to_error_type(aflt), NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_ERR_DISP) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ERR_DISP,
		    DATA_TYPE_UINT64, aflt->flt_disp, NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAGS_L2)
		cpu_payload_add_ecache(aflt, payload);

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_COPYFUNCTION) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_COPYFUNCTION,
		    DATA_TYPE_UINT8, (uint8_t)aflt->flt_status & 0xff, NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_HOWDETECTED) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_HOWDETECTED,
		    DATA_TYPE_UINT8, (uint8_t)(aflt->flt_status >> 8), NULL);
	}

	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_INSTRBLOCK) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_INSTRBLOCK,
		    DATA_TYPE_UINT32_ARRAY, 16,
		    (uint32_t *)&ch_flt->flt_fpdata, NULL);
	}

#if defined(CPU_IMP_L1_CACHE_PARITY)
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAGS_L1D)
		cpu_payload_add_dcache(aflt, payload);
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAGS_L1I)
		cpu_payload_add_icache(aflt, payload);
#endif	/* CPU_IMP_L1_CACHE_PARITY */

#if defined(CHEETAH_PLUS)
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAGS_L1P)
		cpu_payload_add_pcache(aflt, payload);
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAGS_TLB)
		cpu_payload_add_tlb(aflt, payload);
#endif	/* CHEETAH_PLUS */
	/*
	 * Create the FMRI that goes into the payload
	 * and contains the unum info if necessary.
	 */
	if (aflt->flt_payload & FM_EREPORT_PAYLOAD_FLAG_RESOURCE) {
		char unum[UNUM_NAMLEN] = "";
		char sid[DIMM_SERIAL_ID_LEN] = "";
		int len, ret, rtype, synd_code;
		uint64_t offset = (uint64_t)-1;

		rtype = cpu_error_to_resource_type(aflt);
		switch (rtype) {

		case ERRTYPE_MEMORY:
		case ERRTYPE_ECACHE_DATA:

			/*
			 * Memory errors, do unum lookup
			 */
			if (*afar_status == AFLT_STAT_INVALID)
				break;

			if (rtype == ERRTYPE_ECACHE_DATA)
				aflt->flt_status |= ECC_ECACHE;
			else
				aflt->flt_status &= ~ECC_ECACHE;

			synd_code = synd_to_synd_code(*synd_status,
			    aflt->flt_synd, ch_flt->flt_bit);

			if (cpu_get_mem_unum_synd(synd_code, aflt, unum) != 0)
				break;

			ret = cpu_get_mem_sid(unum, sid, DIMM_SERIAL_ID_LEN,
			    &len);

			if (ret == 0) {
				(void) cpu_get_mem_offset(aflt->flt_addr,
				    &offset);
			}

			fm_fmri_mem_set(resource, FM_MEM_SCHEME_VERSION,
			    NULL, unum, (ret == 0) ? sid : NULL, offset);
			fm_payload_set(payload,
			    FM_EREPORT_PAYLOAD_NAME_RESOURCE,
			    DATA_TYPE_NVLIST, resource, NULL);
			break;

		case ERRTYPE_CPU:
			/*
			 * On-board processor array error, add cpu resource.
			 */
			cpu_fmri_cpu_set(resource, aflt->flt_inst);
			fm_payload_set(payload,
			    FM_EREPORT_PAYLOAD_NAME_RESOURCE,
			    DATA_TYPE_NVLIST, resource, NULL);
			break;
		}
	}
}

/*
 * Initialize the way info if necessary.
 */
void
cpu_ereport_init(struct async_flt *aflt)
{
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;
	ch_ec_data_t *ecp = &ch_flt->flt_diag_data.chd_ec_data[0];
	ch_ec_data_t *l2p = &ch_flt->flt_diag_data.chd_l2_data[0];
	int i;

	/*
	 * Initialize the info in the CPU logout structure.
	 * The I$/D$ way information is not initialized here
	 * since it is captured in the logout assembly code.
	 */
	for (i = 0; i < CHD_EC_DATA_SETS; i++)
		(ecp + i)->ec_way = i;

	for (i = 0; i < PN_L2_NWAYS; i++)
		(l2p + i)->ec_way = i;
}

/*
 * Returns whether fault address is valid for this error bit and
 * whether the address is "in memory" (i.e. pf_is_memory returns 1).
 */
int
cpu_flt_in_memory(ch_async_flt_t *ch_flt, uint64_t t_afsr_bit)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;

	return ((t_afsr_bit & C_AFSR_MEMORY) &&
	    afsr_to_afar_status(ch_flt->afsr_errs, t_afsr_bit) ==
	    AFLT_STAT_VALID &&
	    pf_is_memory(aflt->flt_addr >> MMU_PAGESHIFT));
}

/*
 * Returns whether fault address is valid based on the error bit for the
 * one event being queued and whether the address is "in memory".
 */
static int
cpu_flt_in_memory_one_event(ch_async_flt_t *ch_flt, uint64_t t_afsr_bit)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	int afar_status;
	uint64_t afsr_errs, afsr_ow, *ow_bits;

	if (!(t_afsr_bit & C_AFSR_MEMORY) ||
	    !pf_is_memory(aflt->flt_addr >> MMU_PAGESHIFT))
		return (0);

	afsr_errs = ch_flt->afsr_errs;
	afar_status = afsr_to_afar_status(afsr_errs, t_afsr_bit);

	switch (afar_status) {
	case AFLT_STAT_VALID:
		return (1);

	case AFLT_STAT_AMBIGUOUS:
		/*
		 * Status is ambiguous since another error bit (or bits)
		 * of equal priority to the specified bit on in the afsr,
		 * so check those bits. Return 1 only if the bits on in the
		 * same class as the t_afsr_bit are also C_AFSR_MEMORY bits.
		 * Otherwise not all the equal priority bits are for memory
		 * errors, so return 0.
		 */
		ow_bits = afar_overwrite;
		while ((afsr_ow = *ow_bits++) != 0) {
			/*
			 * Get other bits that are on in t_afsr_bit's priority
			 * class to check for Memory Error bits only.
			 */
			if (afsr_ow & t_afsr_bit) {
				if ((afsr_errs & afsr_ow) & ~C_AFSR_MEMORY)
					return (0);
				else
					return (1);
			}
		}
		/*FALLTHRU*/

	default:
		return (0);
	}
}

static void
cpu_log_diag_info(ch_async_flt_t *ch_flt)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	ch_dc_data_t *dcp = &ch_flt->flt_diag_data.chd_dc_data;
	ch_ic_data_t *icp = &ch_flt->flt_diag_data.chd_ic_data;
	ch_ec_data_t *ecp = &ch_flt->flt_diag_data.chd_ec_data[0];
#if defined(CPU_IMP_ECACHE_ASSOC)
	int i, nway;
#endif /* CPU_IMP_ECACHE_ASSOC */

	/*
	 * Check if the CPU log out captured was valid.
	 */
	if (ch_flt->flt_diag_data.chd_afar == LOGOUT_INVALID ||
	    ch_flt->flt_data_incomplete)
		return;

#if defined(CPU_IMP_ECACHE_ASSOC)
	nway = cpu_ecache_nway();
	i =  cpu_ecache_line_valid(ch_flt);
	if (i == 0 || i > nway) {
		for (i = 0; i < nway; i++)
			ecp[i].ec_logflag = EC_LOGFLAG_MAGIC;
	} else
		ecp[i - 1].ec_logflag = EC_LOGFLAG_MAGIC;
#else /* CPU_IMP_ECACHE_ASSOC */
	ecp->ec_logflag = EC_LOGFLAG_MAGIC;
#endif /* CPU_IMP_ECACHE_ASSOC */

#if defined(CHEETAH_PLUS)
	pn_cpu_log_diag_l2_info(ch_flt);
#endif /* CHEETAH_PLUS */

	if (CH_DCTAG_MATCH(dcp->dc_tag, aflt->flt_addr)) {
		dcp->dc_way = CH_DCIDX_TO_WAY(dcp->dc_idx);
		dcp->dc_logflag = DC_LOGFLAG_MAGIC;
	}

	if (CH_ICTAG_MATCH(icp, aflt->flt_addr)) {
		if (IS_PANTHER(cpunodes[aflt->flt_inst].implementation))
			icp->ic_way = PN_ICIDX_TO_WAY(icp->ic_idx);
		else
			icp->ic_way = CH_ICIDX_TO_WAY(icp->ic_idx);
		icp->ic_logflag = IC_LOGFLAG_MAGIC;
	}
}

/*
 * Cheetah ECC calculation.
 *
 * We only need to do the calculation on the data bits and can ignore check
 * bit and Mtag bit terms in the calculation.
 */
static uint64_t ch_ecc_table[9][2] = {
	/*
	 * low order 64-bits   high-order 64-bits
	 */
	{ 0x46bffffeccd1177f, 0x488800022100014c },
	{ 0x42fccc81331ff77f, 0x14424f1010249184 },
	{ 0x8898827c222f1ffe, 0x22c1222808184aaf },
	{ 0xf7632203e131ccf1, 0xe1241121848292b8 },
	{ 0x7f5511421b113809, 0x901c88d84288aafe },
	{ 0x1d49412184882487, 0x8f338c87c044c6ef },
	{ 0xf552181014448344, 0x7ff8f4443e411911 },
	{ 0x2189240808f24228, 0xfeeff8cc81333f42 },
	{ 0x3280008440001112, 0xfee88b337ffffd62 },
};

/*
 * 64-bit population count, use well-known popcnt trick.
 * We could use the UltraSPARC V9 POPC instruction, but some
 * CPUs including Cheetahplus and Jaguar do not support that
 * instruction.
 */
int
popc64(uint64_t val)
{
	int cnt;

	for (cnt = 0; val != 0; val &= val - 1)
		cnt++;
	return (cnt);
}

/*
 * Generate the 9 ECC bits for the 128-bit chunk based on the table above.
 * Note that xor'ing an odd number of 1 bits == 1 and xor'ing an even number
 * of 1 bits == 0, so we can just use the least significant bit of the popcnt
 * instead of doing all the xor's.
 */
uint32_t
us3_gen_ecc(uint64_t data_low, uint64_t data_high)
{
	int bitno, s;
	int synd = 0;

	for (bitno = 0; bitno < 9; bitno++) {
		s = (popc64(data_low & ch_ecc_table[bitno][0]) +
		    popc64(data_high & ch_ecc_table[bitno][1])) & 1;
		synd |= (s << bitno);
	}
	return (synd);

}

/*
 * Queue one event based on ecc_type_to_info entry.  If the event has an AFT1
 * tag associated with it or is a fatal event (aflt_panic set), it is sent to
 * the UE event queue.  Otherwise it is dispatched to the CE event queue.
 */
static void
cpu_queue_one_event(ch_async_flt_t *ch_flt, char *reason,
    ecc_type_to_info_t *eccp, ch_diag_data_t *cdp)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;

	if (reason &&
	    strlen(reason) + strlen(eccp->ec_reason) < MAX_REASON_STRING) {
		(void) strcat(reason, eccp->ec_reason);
	}

	ch_flt->flt_bit = eccp->ec_afsr_bit;
	ch_flt->flt_type = eccp->ec_flt_type;
	if (cdp != NULL && cdp->chd_afar != LOGOUT_INVALID)
		ch_flt->flt_diag_data = *cdp;
	else
		ch_flt->flt_diag_data.chd_afar = LOGOUT_INVALID;
	aflt->flt_in_memory =
	    cpu_flt_in_memory_one_event(ch_flt, ch_flt->flt_bit);

	if (ch_flt->flt_bit & C_AFSR_MSYND_ERRS)
		aflt->flt_synd = GET_M_SYND(aflt->flt_stat);
	else if (ch_flt->flt_bit & (C_AFSR_ESYND_ERRS | C_AFSR_EXT_ESYND_ERRS))
		aflt->flt_synd = GET_E_SYND(aflt->flt_stat);
	else
		aflt->flt_synd = 0;

	aflt->flt_payload = eccp->ec_err_payload;

	if (aflt->flt_panic || (eccp->ec_afsr_bit &
	    (C_AFSR_LEVEL1 | C_AFSR_EXT_LEVEL1)))
		cpu_errorq_dispatch(eccp->ec_err_class,
		    (void *)ch_flt, sizeof (ch_async_flt_t), ue_queue,
		    aflt->flt_panic);
	else
		cpu_errorq_dispatch(eccp->ec_err_class,
		    (void *)ch_flt, sizeof (ch_async_flt_t), ce_queue,
		    aflt->flt_panic);
}

/*
 * Queue events on async event queue one event per error bit.  First we
 * queue the events that we "expect" for the given trap, then we queue events
 * that we may not expect.  Return number of events queued.
 */
int
cpu_queue_events(ch_async_flt_t *ch_flt, char *reason, uint64_t t_afsr_errs,
    ch_cpu_logout_t *clop)
{
	struct async_flt *aflt = (struct async_flt *)ch_flt;
	ecc_type_to_info_t *eccp;
	int nevents = 0;
	uint64_t primary_afar = aflt->flt_addr, primary_afsr = aflt->flt_stat;
#if defined(CHEETAH_PLUS)
	uint64_t orig_t_afsr_errs;
#endif
	uint64_t primary_afsr_ext = ch_flt->afsr_ext;
	uint64_t primary_afsr_errs = ch_flt->afsr_errs;
	ch_diag_data_t *cdp = NULL;

	t_afsr_errs &= ((C_AFSR_ALL_ERRS & ~C_AFSR_ME) | C_AFSR_EXT_ALL_ERRS);

#if defined(CHEETAH_PLUS)
	orig_t_afsr_errs = t_afsr_errs;

	/*
	 * For Cheetah+, log the shadow AFSR/AFAR bits first.
	 */
	if (clop != NULL) {
		/*
		 * Set the AFSR and AFAR fields to the shadow registers.  The
		 * flt_addr and flt_stat fields will be reset to the primaries
		 * below, but the sdw_addr and sdw_stat will stay as the
		 * secondaries.
		 */
		cdp = &clop->clo_sdw_data;
		aflt->flt_addr = ch_flt->flt_sdw_afar = cdp->chd_afar;
		aflt->flt_stat = ch_flt->flt_sdw_afsr = cdp->chd_afsr;
		ch_flt->afsr_ext = ch_flt->flt_sdw_afsr_ext = cdp->chd_afsr_ext;
		ch_flt->afsr_errs = (cdp->chd_afsr_ext & C_AFSR_EXT_ALL_ERRS) |
		    (cdp->chd_afsr & C_AFSR_ALL_ERRS);

		/*
		 * If the primary and shadow AFSR differ, tag the shadow as
		 * the first fault.
		 */
		if ((primary_afar != cdp->chd_afar) ||
		    (primary_afsr_errs != ch_flt->afsr_errs)) {
			aflt->flt_stat |= (1ull << C_AFSR_FIRSTFLT_SHIFT);
		}

		/*
		 * Check AFSR bits as well as AFSR_EXT bits in order of
		 * the AFAR overwrite priority. Our stored AFSR_EXT value
		 * is expected to be zero for those CPUs which do not have
		 * an AFSR_EXT register.
		 */
		for (eccp = ecc_type_to_info; eccp->ec_desc != NULL; eccp++) {
			if ((eccp->ec_afsr_bit &
			    (ch_flt->afsr_errs & t_afsr_errs)) &&
			    ((eccp->ec_flags & aflt->flt_status) != 0)) {
				cpu_queue_one_event(ch_flt, reason, eccp, cdp);
				cdp = NULL;
				t_afsr_errs &= ~eccp->ec_afsr_bit;
				nevents++;
			}
		}

		/*
		 * If the ME bit is on in the primary AFSR turn all the
		 * error bits on again that may set the ME bit to make
		 * sure we see the ME AFSR error logs.
		 */
		if ((primary_afsr & C_AFSR_ME) != 0)
			t_afsr_errs = (orig_t_afsr_errs & C_AFSR_ALL_ME_ERRS);
	}
#endif	/* CHEETAH_PLUS */

	if (clop != NULL)
		cdp = &clop->clo_data;

	/*
	 * Queue expected errors, error bit and fault type must match
	 * in the ecc_type_to_info table.
	 */
	for (eccp = ecc_type_to_info; t_afsr_errs != 0 && eccp->ec_desc != NULL;
	    eccp++) {
		if ((eccp->ec_afsr_bit & t_afsr_errs) != 0 &&
		    (eccp->ec_flags & aflt->flt_status) != 0) {
#if defined(SERRANO)
			/*
			 * For FRC/FRU errors on Serrano the afar2 captures
			 * the address and the associated data is
			 * in the shadow logout area.
			 */
			if (eccp->ec_afsr_bit  & (C_AFSR_FRC | C_AFSR_FRU)) {
				if (clop != NULL)
					cdp = &clop->clo_sdw_data;
				aflt->flt_addr = ch_flt->afar2;
			} else {
				if (clop != NULL)
					cdp = &clop->clo_data;
				aflt->flt_addr = primary_afar;
			}
#else	/* SERRANO */
			aflt->flt_addr = primary_afar;
#endif	/* SERRANO */
			aflt->flt_stat = primary_afsr;
			ch_flt->afsr_ext = primary_afsr_ext;
			ch_flt->afsr_errs = primary_afsr_errs;
			cpu_queue_one_event(ch_flt, reason, eccp, cdp);
			cdp = NULL;
			t_afsr_errs &= ~eccp->ec_afsr_bit;
			nevents++;
		}
	}

	/*
	 * Queue unexpected errors, error bit only match.
	 */
	for (eccp = ecc_type_to_info; t_afsr_errs != 0 && eccp->ec_desc != NULL;
	    eccp++) {
		if (eccp->ec_afsr_bit & t_afsr_errs) {
#if defined(SERRANO)
			/*
			 * For FRC/FRU errors on Serrano the afar2 captures
			 * the address and the associated data is
			 * in the shadow logout area.
			 */
			if (eccp->ec_afsr_bit  & (C_AFSR_FRC | C_AFSR_FRU)) {
				if (clop != NULL)
					cdp = &clop->clo_sdw_data;
				aflt->flt_addr = ch_flt->afar2;
			} else {
				if (clop != NULL)
					cdp = &clop->clo_data;
				aflt->flt_addr = primary_afar;
			}
#else	/* SERRANO */
			aflt->flt_addr = primary_afar;
#endif	/* SERRANO */
			aflt->flt_stat = primary_afsr;
			ch_flt->afsr_ext = primary_afsr_ext;
			ch_flt->afsr_errs = primary_afsr_errs;
			cpu_queue_one_event(ch_flt, reason, eccp, cdp);
			cdp = NULL;
			t_afsr_errs &= ~eccp->ec_afsr_bit;
			nevents++;
		}
	}
	return (nevents);
}

/*
 * Return trap type number.
 */
uint8_t
flt_to_trap_type(struct async_flt *aflt)
{
	if (aflt->flt_status & ECC_I_TRAP)
		return (TRAP_TYPE_ECC_I);
	if (aflt->flt_status & ECC_D_TRAP)
		return (TRAP_TYPE_ECC_D);
	if (aflt->flt_status & ECC_F_TRAP)
		return (TRAP_TYPE_ECC_F);
	if (aflt->flt_status & ECC_C_TRAP)
		return (TRAP_TYPE_ECC_C);
	if (aflt->flt_status & ECC_DP_TRAP)
		return (TRAP_TYPE_ECC_DP);
	if (aflt->flt_status & ECC_IP_TRAP)
		return (TRAP_TYPE_ECC_IP);
	if (aflt->flt_status & ECC_ITLB_TRAP)
		return (TRAP_TYPE_ECC_ITLB);
	if (aflt->flt_status & ECC_DTLB_TRAP)
		return (TRAP_TYPE_ECC_DTLB);
	return (TRAP_TYPE_UNKNOWN);
}

/*
 * Decide an error type based on detector and leaky/partner tests.
 * The following array is used for quick translation - it must
 * stay in sync with ce_dispact_t.
 */

static char *cetypes[] = {
	CE_DISP_DESC_U,
	CE_DISP_DESC_I,
	CE_DISP_DESC_PP,
	CE_DISP_DESC_P,
	CE_DISP_DESC_L,
	CE_DISP_DESC_PS,
	CE_DISP_DESC_S
};

char *
flt_to_error_type(struct async_flt *aflt)
{
	ce_dispact_t dispact, disp;
	uchar_t dtcrinfo, ptnrinfo, lkyinfo;

	/*
	 * The memory payload bundle is shared by some events that do
	 * not perform any classification.  For those flt_disp will be
	 * 0 and we will return "unknown".
	 */
	if (!ce_disp_inited || !aflt->flt_in_memory || aflt->flt_disp == 0)
		return (cetypes[CE_DISP_UNKNOWN]);

	dtcrinfo = CE_XDIAG_DTCRINFO(aflt->flt_disp);

	/*
	 * It is also possible that no scrub/classification was performed
	 * by the detector, for instance where a disrupting error logged
	 * in the AFSR while CEEN was off in cpu_deferred_error.
	 */
	if (!CE_XDIAG_EXT_ALG_APPLIED(dtcrinfo))
		return (cetypes[CE_DISP_UNKNOWN]);

	/*
	 * Lookup type in initial classification/action table
	 */
	dispact = CE_DISPACT(ce_disp_table,
	    CE_XDIAG_AFARMATCHED(dtcrinfo),
	    CE_XDIAG_STATE(dtcrinfo),
	    CE_XDIAG_CE1SEEN(dtcrinfo),
	    CE_XDIAG_CE2SEEN(dtcrinfo));

	/*
	 * A bad lookup is not something to panic production systems for.
	 */
	ASSERT(dispact != CE_DISP_BAD);
	if (dispact == CE_DISP_BAD)
		return (cetypes[CE_DISP_UNKNOWN]);

	disp = CE_DISP(dispact);

	switch (disp) {
	case CE_DISP_UNKNOWN:
	case CE_DISP_INTERMITTENT:
		break;

	case CE_DISP_POSS_PERS:
		/*
		 * "Possible persistent" errors to which we have applied a valid
		 * leaky test can be separated into "persistent" or "leaky".
		 */
		lkyinfo = CE_XDIAG_LKYINFO(aflt->flt_disp);
		if (CE_XDIAG_TESTVALID(lkyinfo)) {
			if (CE_XDIAG_CE1SEEN(lkyinfo) ||
			    CE_XDIAG_CE2SEEN(lkyinfo))
				disp = CE_DISP_LEAKY;
			else
				disp = CE_DISP_PERS;
		}
		break;

	case CE_DISP_POSS_STICKY:
		/*
		 * Promote "possible sticky" results that have been
		 * confirmed by a partner test to "sticky".  Unconfirmed
		 * "possible sticky" events are left at that status - we do not
		 * guess at any bad reader/writer etc status here.
		 */
		ptnrinfo = CE_XDIAG_PTNRINFO(aflt->flt_disp);
		if (CE_XDIAG_TESTVALID(ptnrinfo) &&
		    CE_XDIAG_CE1SEEN(ptnrinfo) && CE_XDIAG_CE2SEEN(ptnrinfo))
			disp = CE_DISP_STICKY;

		/*
		 * Promote "possible sticky" results on a uniprocessor
		 * to "sticky"
		 */
		if (disp == CE_DISP_POSS_STICKY &&
		    CE_XDIAG_SKIPCODE(disp) == CE_XDIAG_SKIP_UNIPROC)
			disp = CE_DISP_STICKY;
		break;

	default:
		disp = CE_DISP_UNKNOWN;
		break;
	}

	return (cetypes[disp]);
}

/*
 * Given the entire afsr, the specific bit to check and a prioritized list of
 * error bits, determine the validity of the various overwrite priority
 * features of the AFSR/AFAR: AFAR, ESYND and MSYND, each of which have
 * different overwrite priorities.
 *
 * Given a specific afsr error bit and the entire afsr, there are three cases:
 *   INVALID:	The specified bit is lower overwrite priority than some other
 *		error bit which is on in the afsr (or IVU/IVC).
 *   VALID:	The specified bit is higher priority than all other error bits
 *		which are on in the afsr.
 *   AMBIGUOUS: Another error bit (or bits) of equal priority to the specified
 *		bit is on in the afsr.
 */
int
afsr_to_overw_status(uint64_t afsr, uint64_t afsr_bit, uint64_t *ow_bits)
{
	uint64_t afsr_ow;

	while ((afsr_ow = *ow_bits++) != 0) {
		/*
		 * If bit is in the priority class, check to see if another
		 * bit in the same class is on => ambiguous.  Otherwise,
		 * the value is valid.  If the bit is not on at this priority
		 * class, but a higher priority bit is on, then the value is
		 * invalid.
		 */
		if (afsr_ow & afsr_bit) {
			/*
			 * If equal pri bit is on, ambiguous.
			 */
			if (afsr & (afsr_ow & ~afsr_bit))
				return (AFLT_STAT_AMBIGUOUS);
			return (AFLT_STAT_VALID);
		} else if (afsr & afsr_ow)
			break;
	}

	/*
	 * We didn't find a match or a higher priority bit was on.  Not
	 * finding a match handles the case of invalid AFAR for IVC, IVU.
	 */
	return (AFLT_STAT_INVALID);
}

static int
afsr_to_afar_status(uint64_t afsr, uint64_t afsr_bit)
{
#if defined(SERRANO)
	if (afsr_bit & (C_AFSR_FRC | C_AFSR_FRU))
		return (afsr_to_overw_status(afsr, afsr_bit, afar2_overwrite));
	else
#endif	/* SERRANO */
		return (afsr_to_overw_status(afsr, afsr_bit, afar_overwrite));
}

static int
afsr_to_esynd_status(uint64_t afsr, uint64_t afsr_bit)
{
	return (afsr_to_overw_status(afsr, afsr_bit, esynd_overwrite));
}

static int
afsr_to_msynd_status(uint64_t afsr, uint64_t afsr_bit)
{
	return (afsr_to_overw_status(afsr, afsr_bit, msynd_overwrite));
}

static int
afsr_to_synd_status(uint_t cpuid, uint64_t afsr, uint64_t afsr_bit)
{
#ifdef lint
	cpuid = cpuid;
#endif
#if defined(CHEETAH_PLUS)
	/*
	 * The M_SYND overwrite policy is combined with the E_SYND overwrite
	 * policy for Cheetah+ and separate for Panther CPUs.
	 */
	if (afsr_bit & C_AFSR_MSYND_ERRS) {
		if (IS_PANTHER(cpunodes[cpuid].implementation))
			return (afsr_to_msynd_status(afsr, afsr_bit));
		else
			return (afsr_to_esynd_status(afsr, afsr_bit));
	} else if (afsr_bit & (C_AFSR_ESYND_ERRS | C_AFSR_EXT_ESYND_ERRS)) {
		if (IS_PANTHER(cpunodes[cpuid].implementation))
			return (afsr_to_pn_esynd_status(afsr, afsr_bit));
		else
			return (afsr_to_esynd_status(afsr, afsr_bit));
#else /* CHEETAH_PLUS */
	if (afsr_bit & C_AFSR_MSYND_ERRS) {
		return (afsr_to_msynd_status(afsr, afsr_bit));
	} else if (afsr_bit & (C_AFSR_ESYND_ERRS | C_AFSR_EXT_ESYND_ERRS)) {
		return (afsr_to_esynd_status(afsr, afsr_bit));
#endif /* CHEETAH_PLUS */
	} else {
		return (AFLT_STAT_INVALID);
	}
}

/*
 * Slave CPU stick synchronization.
 */
void
sticksync_slave(void)
{
	int 		i;
	int		tries = 0;
	int64_t		tskew;
	int64_t		av_tskew;

	kpreempt_disable();
	/* wait for the master side */
	while (stick_sync_cmd != SLAVE_START)
		;
	/*
	 * Synchronization should only take a few tries at most. But in the
	 * odd case where the cpu isn't cooperating we'll keep trying. A cpu
	 * without it's stick synchronized wouldn't be a good citizen.
	 */
	while (slave_done == 0) {
		/*
		 * Time skew calculation.
		 */
		av_tskew = tskew = 0;

		for (i = 0; i < stick_iter; i++) {
			/* make location hot */
			timestamp[EV_A_START] = 0;
			stick_timestamp(&timestamp[EV_A_START]);

			/* tell the master we're ready */
			stick_sync_cmd = MASTER_START;

			/* and wait */
			while (stick_sync_cmd != SLAVE_CONT)
				;
			/* Event B end */
			stick_timestamp(&timestamp[EV_B_END]);

			/* calculate time skew */
			tskew = ((timestamp[EV_B_END] - timestamp[EV_B_START])
			    - (timestamp[EV_A_END] - timestamp[EV_A_START]))
			    / 2;

			/* keep running count */
			av_tskew += tskew;
		} /* for */

		/*
		 * Adjust stick for time skew if not within the max allowed;
		 * otherwise we're all done.
		 */
		if (stick_iter != 0)
			av_tskew = av_tskew/stick_iter;
		if (ABS(av_tskew) > stick_tsk) {
			/*
			 * If the skew is 1 (the slave's STICK register
			 * is 1 STICK ahead of the master's), stick_adj
			 * could fail to adjust the slave's STICK register
			 * if the STICK read on the slave happens to
			 * align with the increment of the STICK.
			 * Therefore, we increment the skew to 2.
			 */
			if (av_tskew == 1)
				av_tskew++;
			stick_adj(-av_tskew);
		} else
			slave_done = 1;
#ifdef DEBUG
		if (tries < DSYNC_ATTEMPTS)
			stick_sync_stats[CPU->cpu_id].skew_val[tries] =
			    av_tskew;
		++tries;
#endif /* DEBUG */
#ifdef lint
		tries = tries;
#endif

	} /* while */

	/* allow the master to finish */
	stick_sync_cmd = EVENT_NULL;
	kpreempt_enable();
}

/*
 * Master CPU side of stick synchronization.
 *  - timestamp end of Event A
 *  - timestamp beginning of Event B
 */
void
sticksync_master(void)
{
	int		i;

	kpreempt_disable();
	/* tell the slave we've started */
	slave_done = 0;
	stick_sync_cmd = SLAVE_START;

	while (slave_done == 0) {
		for (i = 0; i < stick_iter; i++) {
			/* wait for the slave */
			while (stick_sync_cmd != MASTER_START)
				;
			/* Event A end */
			stick_timestamp(&timestamp[EV_A_END]);

			/* make location hot */
			timestamp[EV_B_START] = 0;
			stick_timestamp(&timestamp[EV_B_START]);

			/* tell the slave to continue */
			stick_sync_cmd = SLAVE_CONT;
		} /* for */

		/* wait while slave calculates time skew */
		while (stick_sync_cmd == SLAVE_CONT)
			;
	} /* while */
	kpreempt_enable();
}

/*
 * Cheetah/Cheetah+ have disrupting error for copyback's, so we don't need to
 * do Spitfire hack of xcall'ing all the cpus to ask to check for them.  Also,
 * in cpu_async_panic_callb, each cpu checks for CPU events on its way to
 * panic idle.
 */
/*ARGSUSED*/
void
cpu_check_allcpus(struct async_flt *aflt)
{}

struct kmem_cache *ch_private_cache;

/*
 * Cpu private unitialization.  Uninitialize the Ecache scrubber and
 * deallocate the scrubber data structures and cpu_private data structure.
 */
void
cpu_uninit_private(struct cpu *cp)
{
	cheetah_private_t *chprp = CPU_PRIVATE(cp);

	ASSERT(chprp);
	cpu_uninit_ecache_scrub_dr(cp);
	CPU_PRIVATE(cp) = NULL;
	ch_err_tl1_paddrs[cp->cpu_id] = NULL;
	kmem_cache_free(ch_private_cache, chprp);
	cmp_delete_cpu(cp->cpu_id);

}

/*
 * Cheetah Cache Scrubbing
 *
 * The primary purpose of Cheetah cache scrubbing is to reduce the exposure
 * of E$ tags, D$ data, and I$ data to cosmic ray events since they are not
 * protected by either parity or ECC.
 *
 * We currently default the E$ and D$ scan rate to 100 (scan 10% of the
 * cache per second). Due to the the specifics of how the I$ control
 * logic works with respect to the ASI used to scrub I$ lines, the entire
 * I$ is scanned at once.
 */

/*
 * Tuneables to enable and disable the scrubbing of the caches, and to tune
 * scrubbing behavior.  These may be changed via /etc/system or using mdb
 * on a running system.
 */
int dcache_scrub_enable = 1;		/* D$ scrubbing is on by default */

/*
 * The following are the PIL levels that the softints/cross traps will fire at.
 */
uint_t ecache_scrub_pil = PIL_9;	/* E$ scrub PIL for cross traps */
uint_t dcache_scrub_pil = PIL_9;	/* D$ scrub PIL for cross traps */
uint_t icache_scrub_pil = PIL_9;	/* I$ scrub PIL for cross traps */

#if defined(JALAPENO)

/*
 * Due to several errata (82, 85, 86), we don't enable the L2$ scrubber
 * on Jalapeno.
 */
int ecache_scrub_enable = 0;

#else	/* JALAPENO */

/*
 * With all other cpu types, E$ scrubbing is on by default
 */
int ecache_scrub_enable = 1;

#endif	/* JALAPENO */


#if defined(CHEETAH_PLUS) || defined(JALAPENO) || defined(SERRANO)

/*
 * The I$ scrubber tends to cause latency problems for real-time SW, so it
 * is disabled by default on non-Cheetah systems
 */
int icache_scrub_enable = 0;

/*
 * Tuneables specifying the scrub calls per second and the scan rate
 * for each cache
 *
 * The cyclic times are set during boot based on the following values.
 * Changing these values in mdb after this time will have no effect.  If
 * a different value is desired, it must be set in /etc/system before a
 * reboot.
 */
int ecache_calls_a_sec = 1;
int dcache_calls_a_sec = 2;
int icache_calls_a_sec = 2;

int ecache_scan_rate_idle = 1;
int ecache_scan_rate_busy = 1;
int dcache_scan_rate_idle = 1;
int dcache_scan_rate_busy = 1;
int icache_scan_rate_idle = 1;
int icache_scan_rate_busy = 1;

#else	/* CHEETAH_PLUS || JALAPENO || SERRANO */

int icache_scrub_enable = 1;		/* I$ scrubbing is on by default */

int ecache_calls_a_sec = 100;		/* E$ scrub calls per seconds */
int dcache_calls_a_sec = 100;		/* D$ scrub calls per seconds */
int icache_calls_a_sec = 100;		/* I$ scrub calls per seconds */

int ecache_scan_rate_idle = 100;	/* E$ scan rate (in tenths of a %) */
int ecache_scan_rate_busy = 100;	/* E$ scan rate (in tenths of a %) */
int dcache_scan_rate_idle = 100;	/* D$ scan rate (in tenths of a %) */
int dcache_scan_rate_busy = 100;	/* D$ scan rate (in tenths of a %) */
int icache_scan_rate_idle = 100;	/* I$ scan rate (in tenths of a %) */
int icache_scan_rate_busy = 100;	/* I$ scan rate (in tenths of a %) */

#endif	/* CHEETAH_PLUS || JALAPENO || SERRANO */

/*
 * In order to scrub on offline cpus, a cross trap is sent.  The handler will
 * increment the outstanding request counter and schedule a softint to run
 * the scrubber.
 */
extern xcfunc_t cache_scrubreq_tl1;

/*
 * These are the softint functions for each cache scrubber
 */
static uint_t scrub_ecache_line_intr(caddr_t arg1, caddr_t arg2);
static uint_t scrub_dcache_line_intr(caddr_t arg1, caddr_t arg2);
static uint_t scrub_icache_line_intr(caddr_t arg1, caddr_t arg2);

/*
 * The cache scrub info table contains cache specific information
 * and allows for some of the scrub code to be table driven, reducing
 * duplication of cache similar code.
 *
 * This table keeps a copy of the value in the calls per second variable
 * (?cache_calls_a_sec).  This makes it much more difficult for someone
 * to cause us problems (for example, by setting ecache_calls_a_sec to 0 in
 * mdb in a misguided attempt to disable the scrubber).
 */
struct scrub_info {
	int		*csi_enable;	/* scrubber enable flag */
	int		csi_freq;	/* scrubber calls per second */
	int		csi_index;	/* index to chsm_outstanding[] */
	uint64_t	csi_inum;	/* scrubber interrupt number */
	cyclic_id_t	csi_omni_cyc_id;	/* omni cyclic ID */
	cyclic_id_t	csi_offline_cyc_id;	/* offline cyclic ID */
	char		csi_name[3];	/* cache name for this scrub entry */
} cache_scrub_info[] = {
{ &ecache_scrub_enable, 0, CACHE_SCRUBBER_INFO_E, 0, 0, 0, "E$"},
{ &dcache_scrub_enable, 0, CACHE_SCRUBBER_INFO_D, 0, 0, 0, "D$"},
{ &icache_scrub_enable, 0, CACHE_SCRUBBER_INFO_I, 0, 0, 0, "I$"}
};

/*
 * If scrubbing is enabled, increment the outstanding request counter.  If it
 * is 1 (meaning there were no previous requests outstanding), call
 * setsoftint_tl1 through xt_one_unchecked, which eventually ends up doing
 * a self trap.
 */
static void
do_scrub(struct scrub_info *csi)
{
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);
	int index = csi->csi_index;
	uint32_t *outstanding = &csmp->chsm_outstanding[index];

	if (*(csi->csi_enable) && (csmp->chsm_enable[index])) {
		if (atomic_inc_32_nv(outstanding) == 1) {
			xt_one_unchecked(CPU->cpu_id, setsoftint_tl1,
			    csi->csi_inum, 0);
		}
	}
}

/*
 * Omni cyclics don't fire on offline cpus, so we use another cyclic to
 * cross-trap the offline cpus.
 */
static void
do_scrub_offline(struct scrub_info *csi)
{
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);

	if (CPUSET_ISNULL(cpu_offline_set)) {
		/*
		 * No offline cpus - nothing to do
		 */
		return;
	}

	if (*(csi->csi_enable) && (csmp->chsm_enable[csi->csi_index])) {
		xt_some(cpu_offline_set, cache_scrubreq_tl1, csi->csi_inum,
		    csi->csi_index);
	}
}

/*
 * This is the initial setup for the scrubber cyclics - it sets the
 * interrupt level, frequency, and function to call.
 */
/*ARGSUSED*/
static void
cpu_scrub_cyclic_setup(void *arg, cpu_t *cpu, cyc_handler_t *hdlr,
    cyc_time_t *when)
{
	struct scrub_info *csi = (struct scrub_info *)arg;

	ASSERT(csi != NULL);
	hdlr->cyh_func = (cyc_func_t)do_scrub;
	hdlr->cyh_level = CY_LOW_LEVEL;
	hdlr->cyh_arg = arg;

	when->cyt_when = 0;	/* Start immediately */
	when->cyt_interval = NANOSEC / csi->csi_freq;
}

/*
 * Initialization for cache scrubbing.
 * This routine is called AFTER all cpus have had cpu_init_private called
 * to initialize their private data areas.
 */
void
cpu_init_cache_scrub(void)
{
	int i;
	struct scrub_info *csi;
	cyc_omni_handler_t omni_hdlr;
	cyc_handler_t offline_hdlr;
	cyc_time_t when;

	/*
	 * save away the maximum number of lines for the D$
	 */
	dcache_nlines = dcache_size / dcache_linesize;

	/*
	 * register the softints for the cache scrubbing
	 */
	cache_scrub_info[CACHE_SCRUBBER_INFO_E].csi_inum =
	    add_softintr(ecache_scrub_pil, scrub_ecache_line_intr,
	    (caddr_t)&cache_scrub_info[CACHE_SCRUBBER_INFO_E], SOFTINT_MT);
	cache_scrub_info[CACHE_SCRUBBER_INFO_E].csi_freq = ecache_calls_a_sec;

	cache_scrub_info[CACHE_SCRUBBER_INFO_D].csi_inum =
	    add_softintr(dcache_scrub_pil, scrub_dcache_line_intr,
	    (caddr_t)&cache_scrub_info[CACHE_SCRUBBER_INFO_D], SOFTINT_MT);
	cache_scrub_info[CACHE_SCRUBBER_INFO_D].csi_freq = dcache_calls_a_sec;

	cache_scrub_info[CACHE_SCRUBBER_INFO_I].csi_inum =
	    add_softintr(icache_scrub_pil, scrub_icache_line_intr,
	    (caddr_t)&cache_scrub_info[CACHE_SCRUBBER_INFO_I], SOFTINT_MT);
	cache_scrub_info[CACHE_SCRUBBER_INFO_I].csi_freq = icache_calls_a_sec;

	/*
	 * start the scrubbing for all the caches
	 */
	mutex_enter(&cpu_lock);
	for (i = 0; i < CACHE_SCRUBBER_COUNT; i++) {

		csi = &cache_scrub_info[i];

		if (!(*csi->csi_enable))
			continue;

		/*
		 * force the following to be true:
		 *	1 <= calls_a_sec <= hz
		 */
		if (csi->csi_freq > hz) {
			cmn_err(CE_NOTE, "%s scrub calls_a_sec set too high "
			    "(%d); resetting to hz (%d)", csi->csi_name,
			    csi->csi_freq, hz);
			csi->csi_freq = hz;
		} else if (csi->csi_freq < 1) {
			cmn_err(CE_NOTE, "%s scrub calls_a_sec set too low "
			    "(%d); resetting to 1", csi->csi_name,
			    csi->csi_freq);
			csi->csi_freq = 1;
		}

		omni_hdlr.cyo_online = cpu_scrub_cyclic_setup;
		omni_hdlr.cyo_offline = NULL;
		omni_hdlr.cyo_arg = (void *)csi;

		offline_hdlr.cyh_func = (cyc_func_t)do_scrub_offline;
		offline_hdlr.cyh_arg = (void *)csi;
		offline_hdlr.cyh_level = CY_LOW_LEVEL;

		when.cyt_when = 0;	/* Start immediately */
		when.cyt_interval = NANOSEC / csi->csi_freq;

		csi->csi_omni_cyc_id = cyclic_add_omni(&omni_hdlr);
		csi->csi_offline_cyc_id = cyclic_add(&offline_hdlr, &when);
	}
	register_cpu_setup_func(cpu_scrub_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
}

/*
 * Indicate that the specified cpu is idle.
 */
void
cpu_idle_ecache_scrub(struct cpu *cp)
{
	if (CPU_PRIVATE(cp) != NULL) {
		ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(cp, chpr_scrub_misc);
		csmp->chsm_ecache_busy = ECACHE_CPU_IDLE;
	}
}

/*
 * Indicate that the specified cpu is busy.
 */
void
cpu_busy_ecache_scrub(struct cpu *cp)
{
	if (CPU_PRIVATE(cp) != NULL) {
		ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(cp, chpr_scrub_misc);
		csmp->chsm_ecache_busy = ECACHE_CPU_BUSY;
	}
}

/*
 * Initialization for cache scrubbing for the specified cpu.
 */
void
cpu_init_ecache_scrub_dr(struct cpu *cp)
{
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(cp, chpr_scrub_misc);
	int cpuid = cp->cpu_id;

	/* initialize the number of lines in the caches */
	csmp->chsm_ecache_nlines = cpunodes[cpuid].ecache_size /
	    cpunodes[cpuid].ecache_linesize;
	csmp->chsm_icache_nlines = CPU_PRIVATE_VAL(cp, chpr_icache_size) /
	    CPU_PRIVATE_VAL(cp, chpr_icache_linesize);

	/*
	 * do_scrub() and do_scrub_offline() check both the global
	 * ?cache_scrub_enable and this per-cpu enable variable.  All scrubbers
	 * check this value before scrubbing.  Currently, we use it to
	 * disable the E$ scrubber on multi-core cpus or while running at
	 * slowed speed.  For now, just turn everything on and allow
	 * cpu_init_private() to change it if necessary.
	 */
	csmp->chsm_enable[CACHE_SCRUBBER_INFO_E] = 1;
	csmp->chsm_enable[CACHE_SCRUBBER_INFO_D] = 1;
	csmp->chsm_enable[CACHE_SCRUBBER_INFO_I] = 1;

	cpu_busy_ecache_scrub(cp);
}

/*
 * Un-initialization for cache scrubbing for the specified cpu.
 */
static void
cpu_uninit_ecache_scrub_dr(struct cpu *cp)
{
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(cp, chpr_scrub_misc);

	/*
	 * un-initialize bookkeeping for cache scrubbing
	 */
	bzero(csmp, sizeof (ch_scrub_misc_t));

	cpu_idle_ecache_scrub(cp);
}

/*
 * Called periodically on each CPU to scrub the D$.
 */
static void
scrub_dcache(int how_many)
{
	int i;
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);
	int index = csmp->chsm_flush_index[CACHE_SCRUBBER_INFO_D];

	/*
	 * scrub the desired number of lines
	 */
	for (i = 0; i < how_many; i++) {
		/*
		 * scrub a D$ line
		 */
		dcache_inval_line(index);

		/*
		 * calculate the next D$ line to scrub, assumes
		 * that dcache_nlines is a power of 2
		 */
		index = (index + 1) & (dcache_nlines - 1);
	}

	/*
	 * set the scrub index for the next visit
	 */
	csmp->chsm_flush_index[CACHE_SCRUBBER_INFO_D] = index;
}

/*
 * Handler for D$ scrub inum softint. Call scrub_dcache until
 * we decrement the outstanding request count to zero.
 */
/*ARGSUSED*/
static uint_t
scrub_dcache_line_intr(caddr_t arg1, caddr_t arg2)
{
	int i;
	int how_many;
	int outstanding;
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);
	uint32_t *countp = &csmp->chsm_outstanding[CACHE_SCRUBBER_INFO_D];
	struct scrub_info *csi = (struct scrub_info *)arg1;
	int scan_rate = (csmp->chsm_ecache_busy == ECACHE_CPU_IDLE) ?
	    dcache_scan_rate_idle : dcache_scan_rate_busy;

	/*
	 * The scan rates are expressed in units of tenths of a
	 * percent.  A scan rate of 1000 (100%) means the whole
	 * cache is scanned every second.
	 */
	how_many = (dcache_nlines * scan_rate) / (1000 * csi->csi_freq);

	do {
		outstanding = *countp;
		for (i = 0; i < outstanding; i++) {
			scrub_dcache(how_many);
		}
	} while (atomic_add_32_nv(countp, -outstanding));

	return (DDI_INTR_CLAIMED);
}

/*
 * Called periodically on each CPU to scrub the I$. The I$ is scrubbed
 * by invalidating lines. Due to the characteristics of the ASI which
 * is used to invalidate an I$ line, the entire I$ must be invalidated
 * vs. an individual I$ line.
 */
static void
scrub_icache(int how_many)
{
	int i;
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);
	int index = csmp->chsm_flush_index[CACHE_SCRUBBER_INFO_I];
	int icache_nlines = csmp->chsm_icache_nlines;

	/*
	 * scrub the desired number of lines
	 */
	for (i = 0; i < how_many; i++) {
		/*
		 * since the entire I$ must be scrubbed at once,
		 * wait until the index wraps to zero to invalidate
		 * the entire I$
		 */
		if (index == 0) {
			icache_inval_all();
		}

		/*
		 * calculate the next I$ line to scrub, assumes
		 * that chsm_icache_nlines is a power of 2
		 */
		index = (index + 1) & (icache_nlines - 1);
	}

	/*
	 * set the scrub index for the next visit
	 */
	csmp->chsm_flush_index[CACHE_SCRUBBER_INFO_I] = index;
}

/*
 * Handler for I$ scrub inum softint. Call scrub_icache until
 * we decrement the outstanding request count to zero.
 */
/*ARGSUSED*/
static uint_t
scrub_icache_line_intr(caddr_t arg1, caddr_t arg2)
{
	int i;
	int how_many;
	int outstanding;
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);
	uint32_t *countp = &csmp->chsm_outstanding[CACHE_SCRUBBER_INFO_I];
	struct scrub_info *csi = (struct scrub_info *)arg1;
	int scan_rate = (csmp->chsm_ecache_busy == ECACHE_CPU_IDLE) ?
	    icache_scan_rate_idle : icache_scan_rate_busy;
	int icache_nlines = csmp->chsm_icache_nlines;

	/*
	 * The scan rates are expressed in units of tenths of a
	 * percent.  A scan rate of 1000 (100%) means the whole
	 * cache is scanned every second.
	 */
	how_many = (icache_nlines * scan_rate) / (1000 * csi->csi_freq);

	do {
		outstanding = *countp;
		for (i = 0; i < outstanding; i++) {
			scrub_icache(how_many);
		}
	} while (atomic_add_32_nv(countp, -outstanding));

	return (DDI_INTR_CLAIMED);
}

/*
 * Called periodically on each CPU to scrub the E$.
 */
static void
scrub_ecache(int how_many)
{
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);
	int i;
	int cpuid = CPU->cpu_id;
	int index = csmp->chsm_flush_index[CACHE_SCRUBBER_INFO_E];
	int nlines = csmp->chsm_ecache_nlines;
	int linesize = cpunodes[cpuid].ecache_linesize;
	int ec_set_size = cpu_ecache_set_size(CPU);

	/*
	 * scrub the desired number of lines
	 */
	for (i = 0; i < how_many; i++) {
		/*
		 * scrub the E$ line
		 */
		ecache_flush_line(ecache_flushaddr + (index * linesize),
		    ec_set_size);

		/*
		 * calculate the next E$ line to scrub based on twice
		 * the number of E$ lines (to displace lines containing
		 * flush area data), assumes that the number of lines
		 * is a power of 2
		 */
		index = (index + 1) & ((nlines << 1) - 1);
	}

	/*
	 * set the ecache scrub index for the next visit
	 */
	csmp->chsm_flush_index[CACHE_SCRUBBER_INFO_E] = index;
}

/*
 * Handler for E$ scrub inum softint. Call the E$ scrubber until
 * we decrement the outstanding request count to zero.
 *
 * Due to interactions with cpu_scrub_cpu_setup(), the outstanding count may
 * become negative after the atomic_add_32_nv().  This is not a problem, as
 * the next trip around the loop won't scrub anything, and the next add will
 * reset the count back to zero.
 */
/*ARGSUSED*/
static uint_t
scrub_ecache_line_intr(caddr_t arg1, caddr_t arg2)
{
	int i;
	int how_many;
	int outstanding;
	ch_scrub_misc_t *csmp = CPU_PRIVATE_PTR(CPU, chpr_scrub_misc);
	uint32_t *countp = &csmp->chsm_outstanding[CACHE_SCRUBBER_INFO_E];
	struct scrub_info *csi = (struct scrub_info *)arg1;
	int scan_rate = (csmp->chsm_ecache_busy == ECACHE_CPU_IDLE) ?
	    ecache_scan_rate_idle : ecache_scan_rate_busy;
	int ecache_nlines = csmp->chsm_ecache_nlines;

	/*
	 * The scan rates are expressed in units of tenths of a
	 * percent.  A scan rate of 1000 (100%) means the whole
	 * cache is scanned every second.
	 */
	how_many = (ecache_nlines * scan_rate) / (1000 * csi->csi_freq);

	do {
		outstanding = *countp;
		for (i = 0; i < outstanding; i++) {
			scrub_ecache(how_many);
		}
	} while (atomic_add_32_nv(countp, -outstanding));

	return (DDI_INTR_CLAIMED);
}

/*
 * Timeout function to reenable CE
 */
static void
cpu_delayed_check_ce_errors(void *arg)
{
	if (!taskq_dispatch(ch_check_ce_tq, cpu_check_ce_errors, arg,
	    TQ_NOSLEEP)) {
		(void) timeout(cpu_delayed_check_ce_errors, arg,
		    drv_usectohz((clock_t)cpu_ceen_delay_secs * MICROSEC));
	}
}

/*
 * CE Deferred Re-enable after trap.
 *
 * When the CPU gets a disrupting trap for any of the errors
 * controlled by the CEEN bit, CEEN is disabled in the trap handler
 * immediately. To eliminate the possibility of multiple CEs causing
 * recursive stack overflow in the trap handler, we cannot
 * reenable CEEN while still running in the trap handler. Instead,
 * after a CE is logged on a CPU, we schedule a timeout function,
 * cpu_check_ce_errors(), to trigger after cpu_ceen_delay_secs
 * seconds. This function will check whether any further CEs
 * have occurred on that CPU, and if none have, will reenable CEEN.
 *
 * If further CEs have occurred while CEEN is disabled, another
 * timeout will be scheduled. This is to ensure that the CPU can
 * make progress in the face of CE 'storms', and that it does not
 * spend all its time logging CE errors.
 */
static void
cpu_check_ce_errors(void *arg)
{
	int	cpuid = (int)(uintptr_t)arg;
	cpu_t	*cp;

	/*
	 * We acquire cpu_lock.
	 */
	ASSERT(curthread->t_pil == 0);

	/*
	 * verify that the cpu is still around, DR
	 * could have got there first ...
	 */
	mutex_enter(&cpu_lock);
	cp = cpu_get(cpuid);
	if (cp == NULL) {
		mutex_exit(&cpu_lock);
		return;
	}
	/*
	 * make sure we don't migrate across CPUs
	 * while checking our CE status.
	 */
	kpreempt_disable();

	/*
	 * If we are running on the CPU that got the
	 * CE, we can do the checks directly.
	 */
	if (cp->cpu_id == CPU->cpu_id) {
		mutex_exit(&cpu_lock);
		cpu_check_ce(TIMEOUT_CEEN_CHECK, 0, 0, 0);
		kpreempt_enable();
		return;
	}
	kpreempt_enable();

	/*
	 * send an x-call to get the CPU that originally
	 * got the CE to do the necessary checks. If we can't
	 * send the x-call, reschedule the timeout, otherwise we
	 * lose CEEN forever on that CPU.
	 */
	if (CPU_XCALL_READY(cp->cpu_id) && (!(cp->cpu_flags & CPU_QUIESCED))) {
		xc_one(cp->cpu_id, (xcfunc_t *)cpu_check_ce,
		    TIMEOUT_CEEN_CHECK, 0);
		mutex_exit(&cpu_lock);
	} else {
		/*
		 * When the CPU is not accepting xcalls, or
		 * the processor is offlined, we don't want to
		 * incur the extra overhead of trying to schedule the
		 * CE timeout indefinitely. However, we don't want to lose
		 * CE checking forever.
		 *
		 * Keep rescheduling the timeout, accepting the additional
		 * overhead as the cost of correctness in the case where we get
		 * a CE, disable CEEN, offline the CPU during the
		 * the timeout interval, and then online it at some
		 * point in the future. This is unlikely given the short
		 * cpu_ceen_delay_secs.
		 */
		mutex_exit(&cpu_lock);
		(void) timeout(cpu_delayed_check_ce_errors,
		    (void *)(uintptr_t)cp->cpu_id,
		    drv_usectohz((clock_t)cpu_ceen_delay_secs * MICROSEC));
	}
}

/*
 * This routine will check whether CEs have occurred while
 * CEEN is disabled. Any CEs detected will be logged and, if
 * possible, scrubbed.
 *
 * The memscrubber will also use this routine to clear any errors
 * caused by its scrubbing with CEEN disabled.
 *
 * flag == SCRUBBER_CEEN_CHECK
 *		called from memscrubber, just check/scrub, no reset
 *		paddr 	physical addr. for start of scrub pages
 *		vaddr 	virtual addr. for scrub area
 *		psz	page size of area to be scrubbed
 *
 * flag == TIMEOUT_CEEN_CHECK
 *		timeout function has triggered, reset timeout or CEEN
 *
 * Note: We must not migrate cpus during this function.  This can be
 * achieved by one of:
 *    - invoking as target of an x-call in which case we're at XCALL_PIL
 *	The flag value must be first xcall argument.
 *    - disabling kernel preemption.  This should be done for very short
 *	periods so is not suitable for SCRUBBER_CEEN_CHECK where we might
 *	scrub an extended area with cpu_check_block.  The call for
 *	TIMEOUT_CEEN_CHECK uses this so cpu_check_ce must be kept
 *	brief for this case.
 *    - binding to a cpu, eg with thread_affinity_set().  This is used
 *	in the SCRUBBER_CEEN_CHECK case, but is not practical for
 *	the TIMEOUT_CEEN_CHECK because both need cpu_lock.
 */
void
cpu_check_ce(int flag, uint64_t pa, caddr_t va, uint_t psz)
{
	ch_cpu_errors_t	cpu_error_regs;
	uint64_t	ec_err_enable;
	uint64_t	page_offset;

	/* Read AFSR */
	get_cpu_error_state(&cpu_error_regs);

	/*
	 * If no CEEN errors have occurred during the timeout
	 * interval, it is safe to re-enable CEEN and exit.
	 */
	if (((cpu_error_regs.afsr & C_AFSR_CECC_ERRS) |
	    (cpu_error_regs.afsr_ext & C_AFSR_EXT_CECC_ERRS)) == 0) {
		if (flag == TIMEOUT_CEEN_CHECK &&
		    !((ec_err_enable = get_error_enable()) & EN_REG_CEEN))
			set_error_enable(ec_err_enable | EN_REG_CEEN);
		return;
	}

	/*
	 * Ensure that CEEN was not reenabled (maybe by DR) before
	 * we log/clear the error.
	 */
	if ((ec_err_enable = get_error_enable()) & EN_REG_CEEN)
		set_error_enable(ec_err_enable & ~EN_REG_CEEN);

	/*
	 * log/clear the CE. If CE_CEEN_DEFER is passed, the
	 * timeout will be rescheduled when the error is logged.
	 */
	if (!((cpu_error_regs.afsr & cpu_ce_not_deferred) |
	    (cpu_error_regs.afsr_ext & cpu_ce_not_deferred_ext)))
		cpu_ce_detected(&cpu_error_regs,
		    CE_CEEN_DEFER | CE_CEEN_TIMEOUT);
	else
		cpu_ce_detected(&cpu_error_regs, CE_CEEN_TIMEOUT);

	/*
	 * If the memory scrubber runs while CEEN is
	 * disabled, (or if CEEN is disabled during the
	 * scrub as a result of a CE being triggered by
	 * it), the range being scrubbed will not be
	 * completely cleaned. If there are multiple CEs
	 * in the range at most two of these will be dealt
	 * with, (one by the trap handler and one by the
	 * timeout). It is also possible that none are dealt
	 * with, (CEEN disabled and another CE occurs before
	 * the timeout triggers). So to ensure that the
	 * memory is actually scrubbed, we have to access each
	 * memory location in the range and then check whether
	 * that access causes a CE.
	 */
	if (flag == SCRUBBER_CEEN_CHECK && va) {
		if ((cpu_error_regs.afar >= pa) &&
		    (cpu_error_regs.afar < (pa + psz))) {
			/*
			 * Force a load from physical memory for each
			 * 64-byte block, then check AFSR to determine
			 * whether this access caused an error.
			 *
			 * This is a slow way to do a scrub, but as it will
			 * only be invoked when the memory scrubber actually
			 * triggered a CE, it should not happen too
			 * frequently.
			 *
			 * cut down what we need to check as the scrubber
			 * has verified up to AFAR, so get it's offset
			 * into the page and start there.
			 */
			page_offset = (uint64_t)(cpu_error_regs.afar &
			    (psz - 1));
			va = (caddr_t)(va + (P2ALIGN(page_offset, 64)));
			psz -= (uint_t)(P2ALIGN(page_offset, 64));
			cpu_check_block((caddr_t)(P2ALIGN((uint64_t)va, 64)),
			    psz);
		}
	}

	/*
	 * Reset error enable if this CE is not masked.
	 */
	if ((flag == TIMEOUT_CEEN_CHECK) &&
	    (cpu_error_regs.afsr & cpu_ce_not_deferred))
		set_error_enable(ec_err_enable | EN_REG_CEEN);

}

/*
 * Attempt a cpu logout for an error that we did not trap for, such
 * as a CE noticed with CEEN off.  It is assumed that we are still running
 * on the cpu that took the error and that we cannot migrate.  Returns
 * 0 on success, otherwise nonzero.
 */
static int
cpu_ce_delayed_ec_logout(uint64_t afar)
{
	ch_cpu_logout_t *clop;

	if (CPU_PRIVATE(CPU) == NULL)
		return (0);

	clop = CPU_PRIVATE_PTR(CPU, chpr_cecc_logout);
	if (atomic_cas_64(&clop->clo_data.chd_afar, LOGOUT_INVALID, afar) !=
	    LOGOUT_INVALID)
		return (0);

	cpu_delayed_logout(afar, clop);
	return (1);
}

/*
 * We got an error while CEEN was disabled. We
 * need to clean up after it and log whatever
 * information we have on the CE.
 */
void
cpu_ce_detected(ch_cpu_errors_t *cpu_error_regs, int flag)
{
	ch_async_flt_t 	ch_flt;
	struct async_flt *aflt;
	char 		pr_reason[MAX_REASON_STRING];

	bzero(&ch_flt, sizeof (ch_async_flt_t));
	ch_flt.flt_trapped_ce = flag;
	aflt = (struct async_flt *)&ch_flt;
	aflt->flt_stat = cpu_error_regs->afsr & C_AFSR_MASK;
	ch_flt.afsr_ext = cpu_error_regs->afsr_ext;
	ch_flt.afsr_errs = (cpu_error_regs->afsr_ext & C_AFSR_EXT_ALL_ERRS) |
	    (cpu_error_regs->afsr & C_AFSR_ALL_ERRS);
	aflt->flt_addr = cpu_error_regs->afar;
#if defined(SERRANO)
	ch_flt.afar2 = cpu_error_regs->afar2;
#endif	/* SERRANO */
	aflt->flt_pc = NULL;
	aflt->flt_priv = ((cpu_error_regs->afsr & C_AFSR_PRIV) != 0);
	aflt->flt_tl = 0;
	aflt->flt_panic = 0;
	cpu_log_and_clear_ce(&ch_flt);

	/*
	 * check if we caused any errors during cleanup
	 */
	if (clear_errors(&ch_flt)) {
		pr_reason[0] = '\0';
		(void) cpu_queue_events(&ch_flt, pr_reason, ch_flt.afsr_errs,
		    NULL);
	}
}

/*
 * Log/clear CEEN-controlled disrupting errors
 */
static void
cpu_log_and_clear_ce(ch_async_flt_t *ch_flt)
{
	struct async_flt *aflt;
	uint64_t afsr, afsr_errs;
	ch_cpu_logout_t *clop;
	char 		pr_reason[MAX_REASON_STRING];
	on_trap_data_t	*otp = curthread->t_ontrap;

	aflt = (struct async_flt *)ch_flt;
	afsr = aflt->flt_stat;
	afsr_errs = ch_flt->afsr_errs;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_bus_id = getprocessorid();
	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_prot = AFLT_PROT_NONE;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_status = ECC_C_TRAP;

	pr_reason[0] = '\0';
	/*
	 * Get the CPU log out info for Disrupting Trap.
	 */
	if (CPU_PRIVATE(CPU) == NULL) {
		clop = NULL;
		ch_flt->flt_diag_data.chd_afar = LOGOUT_INVALID;
	} else {
		clop = CPU_PRIVATE_PTR(CPU, chpr_cecc_logout);
	}

	if (clop && ch_flt->flt_trapped_ce & CE_CEEN_TIMEOUT) {
		ch_cpu_errors_t cpu_error_regs;

		get_cpu_error_state(&cpu_error_regs);
		(void) cpu_ce_delayed_ec_logout(cpu_error_regs.afar);
		clop->clo_data.chd_afsr = cpu_error_regs.afsr;
		clop->clo_data.chd_afar = cpu_error_regs.afar;
		clop->clo_data.chd_afsr_ext = cpu_error_regs.afsr_ext;
		clop->clo_sdw_data.chd_afsr = cpu_error_regs.shadow_afsr;
		clop->clo_sdw_data.chd_afar = cpu_error_regs.shadow_afar;
		clop->clo_sdw_data.chd_afsr_ext =
		    cpu_error_regs.shadow_afsr_ext;
#if defined(SERRANO)
		clop->clo_data.chd_afar2 = cpu_error_regs.afar2;
#endif	/* SERRANO */
		ch_flt->flt_data_incomplete = 1;

		/*
		 * The logging/clear code expects AFSR/AFAR to be cleared.
		 * The trap handler does it for CEEN enabled errors
		 * so we need to do it here.
		 */
		set_cpu_error_state(&cpu_error_regs);
	}

#if defined(JALAPENO) || defined(SERRANO)
	/*
	 * FRC: Can't scrub memory as we don't have AFAR for Jalapeno.
	 * For Serrano, even thou we do have the AFAR, we still do the
	 * scrub on the RCE side since that's where the error type can
	 * be properly classified as intermittent, persistent, etc.
	 *
	 * CE/RCE:  If error is in memory and AFAR is valid, scrub the memory.
	 * Must scrub memory before cpu_queue_events, as scrubbing memory sets
	 * the flt_status bits.
	 */
	if ((afsr & (C_AFSR_CE|C_AFSR_RCE)) &&
	    (cpu_flt_in_memory(ch_flt, (afsr & C_AFSR_CE)) ||
	    cpu_flt_in_memory(ch_flt, (afsr & C_AFSR_RCE)))) {
		cpu_ce_scrub_mem_err(aflt, B_TRUE);
	}
#else /* JALAPENO || SERRANO */
	/*
	 * CE/EMC:  If error is in memory and AFAR is valid, scrub the memory.
	 * Must scrub memory before cpu_queue_events, as scrubbing memory sets
	 * the flt_status bits.
	 */
	if (afsr & (C_AFSR_CE|C_AFSR_EMC)) {
		if (cpu_flt_in_memory(ch_flt, (afsr & C_AFSR_CE)) ||
		    cpu_flt_in_memory(ch_flt, (afsr & C_AFSR_EMC))) {
			cpu_ce_scrub_mem_err(aflt, B_TRUE);
		}
	}

#endif /* JALAPENO || SERRANO */

	/*
	 * Update flt_prot if this error occurred under on_trap protection.
	 */
	if (otp != NULL && (otp->ot_prot & OT_DATA_EC))
		aflt->flt_prot = AFLT_PROT_EC;

	/*
	 * Queue events on the async event queue, one event per error bit.
	 */
	if (cpu_queue_events(ch_flt, pr_reason, afsr_errs, clop) == 0 ||
	    (afsr_errs & (C_AFSR_CECC_ERRS | C_AFSR_EXT_CECC_ERRS)) == 0) {
		ch_flt->flt_type = CPU_INV_AFSR;
		cpu_errorq_dispatch(FM_EREPORT_CPU_USIII_INVALID_AFSR,
		    (void *)ch_flt, sizeof (ch_async_flt_t), ue_queue,
		    aflt->flt_panic);
	}

	/*
	 * Zero out + invalidate CPU logout.
	 */
	if (clop) {
		bzero(clop, sizeof (ch_cpu_logout_t));
		clop->clo_data.chd_afar = LOGOUT_INVALID;
	}

	/*
	 * If either a CPC, WDC or EDC error has occurred while CEEN
	 * was disabled, we need to flush either the entire
	 * E$ or an E$ line.
	 */
#if defined(JALAPENO) || defined(SERRANO)
	if (afsr & (C_AFSR_EDC | C_AFSR_CPC | C_AFSR_CPU | C_AFSR_WDC))
#else	/* JALAPENO || SERRANO */
	if (afsr_errs & (C_AFSR_EDC | C_AFSR_CPC | C_AFSR_WDC | C_AFSR_L3_EDC |
	    C_AFSR_L3_CPC | C_AFSR_L3_WDC))
#endif	/* JALAPENO || SERRANO */
		cpu_error_ecache_flush(ch_flt);

}

/*
 * depending on the error type, we determine whether we
 * need to flush the entire ecache or just a line.
 */
static int
cpu_error_ecache_flush_required(ch_async_flt_t *ch_flt)
{
	struct async_flt *aflt;
	uint64_t	afsr;
	uint64_t	afsr_errs = ch_flt->afsr_errs;

	aflt = (struct async_flt *)ch_flt;
	afsr = aflt->flt_stat;

	/*
	 * If we got multiple errors, no point in trying
	 * the individual cases, just flush the whole cache
	 */
	if (afsr & C_AFSR_ME) {
		return (ECACHE_FLUSH_ALL);
	}

	/*
	 * If either a CPC, WDC or EDC error has occurred while CEEN
	 * was disabled, we need to flush entire E$. We can't just
	 * flush the cache line affected as the ME bit
	 * is not set when multiple correctable errors of the same
	 * type occur, so we might have multiple CPC or EDC errors,
	 * with only the first recorded.
	 */
#if defined(JALAPENO) || defined(SERRANO)
	if (afsr & (C_AFSR_CPC | C_AFSR_CPU | C_AFSR_EDC | C_AFSR_WDC)) {
#else	/* JALAPENO || SERRANO */
	if (afsr_errs & (C_AFSR_CPC | C_AFSR_EDC | C_AFSR_WDC | C_AFSR_L3_CPC |
	    C_AFSR_L3_EDC | C_AFSR_L3_WDC)) {
#endif	/* JALAPENO || SERRANO */
		return (ECACHE_FLUSH_ALL);
	}

#if defined(JALAPENO) || defined(SERRANO)
	/*
	 * If only UE or RUE is set, flush the Ecache line, otherwise
	 * flush the entire Ecache.
	 */
	if (afsr & (C_AFSR_UE|C_AFSR_RUE)) {
		if ((afsr & C_AFSR_ALL_ERRS) == C_AFSR_UE ||
		    (afsr & C_AFSR_ALL_ERRS) == C_AFSR_RUE) {
			return (ECACHE_FLUSH_LINE);
		} else {
			return (ECACHE_FLUSH_ALL);
		}
	}
#else /* JALAPENO || SERRANO */
	/*
	 * If UE only is set, flush the Ecache line, otherwise
	 * flush the entire Ecache.
	 */
	if (afsr_errs & C_AFSR_UE) {
		if ((afsr_errs & (C_AFSR_ALL_ERRS | C_AFSR_EXT_ALL_ERRS)) ==
		    C_AFSR_UE) {
			return (ECACHE_FLUSH_LINE);
		} else {
			return (ECACHE_FLUSH_ALL);
		}
	}
#endif /* JALAPENO || SERRANO */

	/*
	 * EDU: If EDU only is set, flush the ecache line, otherwise
	 * flush the entire Ecache.
	 */
	if (afsr_errs & (C_AFSR_EDU | C_AFSR_L3_EDU)) {
		if (((afsr_errs & ~C_AFSR_EDU) == 0) ||
		    ((afsr_errs & ~C_AFSR_L3_EDU) == 0)) {
			return (ECACHE_FLUSH_LINE);
		} else {
			return (ECACHE_FLUSH_ALL);
		}
	}

	/*
	 * BERR: If BERR only is set, flush the Ecache line, otherwise
	 * flush the entire Ecache.
	 */
	if (afsr_errs & C_AFSR_BERR) {
		if ((afsr_errs & ~C_AFSR_BERR) == 0) {
			return (ECACHE_FLUSH_LINE);
		} else {
			return (ECACHE_FLUSH_ALL);
		}
	}

	return (0);
}

void
cpu_error_ecache_flush(ch_async_flt_t *ch_flt)
{
	int	ecache_flush_flag =
	    cpu_error_ecache_flush_required(ch_flt);

	/*
	 * Flush Ecache line or entire Ecache based on above checks.
	 */
	if (ecache_flush_flag == ECACHE_FLUSH_ALL)
		cpu_flush_ecache();
	else if (ecache_flush_flag == ECACHE_FLUSH_LINE) {
		cpu_flush_ecache_line(ch_flt);
	}

}

/*
 * Extract the PA portion from the E$ tag.
 */
uint64_t
cpu_ectag_to_pa(int setsize, uint64_t tag)
{
	if (IS_JAGUAR(cpunodes[CPU->cpu_id].implementation))
		return (JG_ECTAG_TO_PA(setsize, tag));
	else if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation))
		return (PN_L3TAG_TO_PA(tag));
	else
		return (CH_ECTAG_TO_PA(setsize, tag));
}

/*
 * Convert the E$ tag PA into an E$ subblock index.
 */
int
cpu_ectag_pa_to_subblk(int cachesize, uint64_t subaddr)
{
	if (IS_JAGUAR(cpunodes[CPU->cpu_id].implementation))
		return (JG_ECTAG_PA_TO_SUBBLK(cachesize, subaddr));
	else if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation))
		/* Panther has only one subblock per line */
		return (0);
	else
		return (CH_ECTAG_PA_TO_SUBBLK(cachesize, subaddr));
}

/*
 * All subblocks in an E$ line must be invalid for
 * the line to be invalid.
 */
int
cpu_ectag_line_invalid(int cachesize, uint64_t tag)
{
	if (IS_JAGUAR(cpunodes[CPU->cpu_id].implementation))
		return (JG_ECTAG_LINE_INVALID(cachesize, tag));
	else if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation))
		return (PN_L3_LINE_INVALID(tag));
	else
		return (CH_ECTAG_LINE_INVALID(cachesize, tag));
}

/*
 * Extract state bits for a subblock given the tag.  Note that for Panther
 * this works on both l2 and l3 tags.
 */
int
cpu_ectag_pa_to_subblk_state(int cachesize, uint64_t subaddr, uint64_t tag)
{
	if (IS_JAGUAR(cpunodes[CPU->cpu_id].implementation))
		return (JG_ECTAG_PA_TO_SUBBLK_STATE(cachesize, subaddr, tag));
	else if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation))
		return (tag & CH_ECSTATE_MASK);
	else
		return (CH_ECTAG_PA_TO_SUBBLK_STATE(cachesize, subaddr, tag));
}

/*
 * Cpu specific initialization.
 */
void
cpu_mp_init(void)
{
#ifdef	CHEETAHPLUS_ERRATUM_25
	if (cheetah_sendmondo_recover) {
		cheetah_nudge_init();
	}
#endif
}

void
cpu_ereport_post(struct async_flt *aflt)
{
	char *cpu_type, buf[FM_MAX_CLASS];
	nv_alloc_t *nva = NULL;
	nvlist_t *ereport, *detector, *resource;
	errorq_elem_t *eqep;
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;
	char unum[UNUM_NAMLEN];
	int synd_code;
	uint8_t msg_type;
	plat_ecc_ch_async_flt_t	plat_ecc_ch_flt;

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
	case CHEETAH_IMPL:
		cpu_type = FM_EREPORT_CPU_USIII;
		break;
	case CHEETAH_PLUS_IMPL:
		cpu_type = FM_EREPORT_CPU_USIIIplus;
		break;
	case JALAPENO_IMPL:
		cpu_type = FM_EREPORT_CPU_USIIIi;
		break;
	case SERRANO_IMPL:
		cpu_type = FM_EREPORT_CPU_USIIIiplus;
		break;
	case JAGUAR_IMPL:
		cpu_type = FM_EREPORT_CPU_USIV;
		break;
	case PANTHER_IMPL:
		cpu_type = FM_EREPORT_CPU_USIVplus;
		break;
	default:
		cpu_type = FM_EREPORT_CPU_UNSUPPORTED;
		break;
	}

	cpu_fmri_cpu_set(detector, aflt->flt_inst);

	/*
	 * Encode all the common data into the ereport.
	 */
	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s.%s",
	    FM_ERROR_CPU, cpu_type, aflt->flt_erpt_class);

	fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
	    fm_ena_generate_cpu(aflt->flt_id, aflt->flt_inst, FM_ENA_FMT1),
	    detector, NULL);

	/*
	 * Encode the error specific data that was saved in
	 * the async_flt structure into the ereport.
	 */
	cpu_payload_add_aflt(aflt, ereport, resource,
	    &plat_ecc_ch_flt.ecaf_afar_status,
	    &plat_ecc_ch_flt.ecaf_synd_status);

	if (aflt->flt_panic || panicstr) {
		errorq_commit(ereport_errorq, eqep, ERRORQ_SYNC);
	} else {
		(void) fm_ereport_post(ereport, EVCH_TRYHARD);
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
		fm_nvlist_destroy(detector, FM_NVA_FREE);
		fm_nvlist_destroy(resource, FM_NVA_FREE);
	}
	/*
	 * Send the enhanced error information (plat_ecc_error2_data_t)
	 * to the SC olny if it can process it.
	 */

	if (&plat_ecc_capability_sc_get &&
	    plat_ecc_capability_sc_get(PLAT_ECC_ERROR2_MESSAGE)) {
		msg_type = cpu_flt_bit_to_plat_error(aflt);
		if (msg_type != PLAT_ECC_ERROR2_NONE) {
			/*
			 * If afar status is not invalid do a unum lookup.
			 */
			if (plat_ecc_ch_flt.ecaf_afar_status !=
			    AFLT_STAT_INVALID) {
				synd_code = synd_to_synd_code(
				    plat_ecc_ch_flt.ecaf_synd_status,
				    aflt->flt_synd, ch_flt->flt_bit);
				(void) cpu_get_mem_unum_synd(synd_code,
				    aflt, unum);
			} else {
				unum[0] = '\0';
			}
			plat_ecc_ch_flt.ecaf_sdw_afar = ch_flt->flt_sdw_afar;
			plat_ecc_ch_flt.ecaf_sdw_afsr = ch_flt->flt_sdw_afsr;
			plat_ecc_ch_flt.ecaf_afsr_ext = ch_flt->afsr_ext;
			plat_ecc_ch_flt.ecaf_sdw_afsr_ext =
			    ch_flt->flt_sdw_afsr_ext;

			if (&plat_log_fruid_error2)
				plat_log_fruid_error2(msg_type, unum, aflt,
				    &plat_ecc_ch_flt);
		}
	}
}

void
cpu_run_bus_error_handlers(struct async_flt *aflt, int expected)
{
	int status;
	ddi_fm_error_t de;

	bzero(&de, sizeof (ddi_fm_error_t));

	de.fme_version = DDI_FME_VERSION;
	de.fme_ena = fm_ena_generate_cpu(aflt->flt_id, aflt->flt_inst,
	    FM_ENA_FMT1);
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

/*
 * This routine may be called by the IO module, but does not do
 * anything in this cpu module. The SERD algorithm is handled by
 * cpumem-diagnosis engine instead.
 */
/*ARGSUSED*/
void
cpu_ce_count_unum(struct async_flt *ecc, int len, char *unum)
{}

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

/*
 * Called from illegal instruction trap handler to see if we can attribute
 * the trap to a fpras check.
 */
int
fpras_chktrap(struct regs *rp)
{
	int op;
	struct fpras_chkfngrp *cgp;
	uintptr_t tpc = (uintptr_t)rp->r_pc;

	if (fpras_chkfngrps == NULL)
		return (0);

	cgp = &fpras_chkfngrps[CPU->cpu_id];
	for (op = 0; op < FPRAS_NCOPYOPS; ++op) {
		if (tpc >= (uintptr_t)&cgp->fpras_fn[op].fpras_blk0 &&
		    tpc < (uintptr_t)&cgp->fpras_fn[op].fpras_chkresult)
			break;
	}
	if (op == FPRAS_NCOPYOPS)
		return (0);

	/*
	 * This is an fpRAS failure caught through an illegal
	 * instruction - trampoline.
	 */
	rp->r_pc = (uintptr_t)&cgp->fpras_fn[op].fpras_trampoline;
	rp->r_npc = rp->r_pc + 4;
	return (1);
}

/*
 * fpras_failure is called when a fpras check detects a bad calculation
 * result or an illegal instruction trap is attributed to an fpras
 * check.  In all cases we are still bound to CPU.
 */
int
fpras_failure(int op, int how)
{
	int use_hw_bcopy_orig, use_hw_bzero_orig;
	uint_t hcl1_orig, hcl2_orig, hcl4_orig, hcl8_orig;
	ch_async_flt_t ch_flt;
	struct async_flt *aflt = (struct async_flt *)&ch_flt;
	struct fpras_chkfn *sfp, *cfp;
	uint32_t *sip, *cip;
	int i;

	/*
	 * We're running on a sick CPU.  Avoid further FPU use at least for
	 * the time in which we dispatch an ereport and (if applicable) panic.
	 */
	use_hw_bcopy_orig = use_hw_bcopy;
	use_hw_bzero_orig = use_hw_bzero;
	hcl1_orig = hw_copy_limit_1;
	hcl2_orig = hw_copy_limit_2;
	hcl4_orig = hw_copy_limit_4;
	hcl8_orig = hw_copy_limit_8;
	use_hw_bcopy = use_hw_bzero = 0;
	hw_copy_limit_1 = hw_copy_limit_2 = hw_copy_limit_4 =
	    hw_copy_limit_8 = 0;

	bzero(&ch_flt, sizeof (ch_async_flt_t));
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_class = CPU_FAULT;
	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_status = (how << 8) | op;
	aflt->flt_payload = FM_EREPORT_PAYLOAD_FPU_HWCOPY;
	ch_flt.flt_type = CPU_FPUERR;

	/*
	 * We must panic if the copy operation had no lofault protection -
	 * ie, don't panic for copyin, copyout, kcopy and bcopy called
	 * under on_fault and do panic for unprotected bcopy and hwblkpagecopy.
	 */
	aflt->flt_panic = (curthread->t_lofault == NULL);

	/*
	 * XOR the source instruction block with the copied instruction
	 * block - this will show us which bit(s) are corrupted.
	 */
	sfp = (struct fpras_chkfn *)fpras_chkfn_type1;
	cfp = &fpras_chkfngrps[CPU->cpu_id].fpras_fn[op];
	if (op == FPRAS_BCOPY || op == FPRAS_COPYOUT) {
		sip = &sfp->fpras_blk0[0];
		cip = &cfp->fpras_blk0[0];
	} else {
		sip = &sfp->fpras_blk1[0];
		cip = &cfp->fpras_blk1[0];
	}
	for (i = 0; i < 16; ++i, ++sip, ++cip)
		ch_flt.flt_fpdata[i] = *sip ^ *cip;

	cpu_errorq_dispatch(FM_EREPORT_CPU_USIII_FPU_HWCOPY, (void *)&ch_flt,
	    sizeof (ch_async_flt_t), ue_queue, aflt->flt_panic);

	if (aflt->flt_panic)
		fm_panic("FPU failure on CPU %d", CPU->cpu_id);

	/*
	 * We get here for copyin/copyout and kcopy or bcopy where the
	 * caller has used on_fault.  We will flag the error so that
	 * the process may be killed  The trap_async_hwerr mechanism will
	 * take appropriate further action (such as a reboot, contract
	 * notification etc).  Since we may be continuing we will
	 * restore the global hardware copy acceleration switches.
	 *
	 * When we return from this function to the copy function we want to
	 * avoid potentially bad data being used, ie we want the affected
	 * copy function to return an error.  The caller should therefore
	 * invoke its lofault handler (which always exists for these functions)
	 * which will return the appropriate error.
	 */
	ttolwp(curthread)->lwp_pcb.pcb_flags |= ASYNC_HWERR;
	aston(curthread);

	use_hw_bcopy = use_hw_bcopy_orig;
	use_hw_bzero = use_hw_bzero_orig;
	hw_copy_limit_1 = hcl1_orig;
	hw_copy_limit_2 = hcl2_orig;
	hw_copy_limit_4 = hcl4_orig;
	hw_copy_limit_8 = hcl8_orig;

	return (1);
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

/*
 * Called when a cpu enters the CPU_FAULTED state (by the cpu placing the
 * faulted cpu into that state).  Cross-trap to the faulted cpu to clear
 * CEEN from the EER to disable traps for further disrupting error types
 * on that cpu.  We could cross-call instead, but that has a larger
 * instruction and data footprint than cross-trapping, and the cpu is known
 * to be faulted.
 */

void
cpu_faulted_enter(struct cpu *cp)
{
	xt_one(cp->cpu_id, set_error_enable_tl1, EN_REG_CEEN, EER_SET_CLRBITS);
}

/*
 * Called when a cpu leaves the CPU_FAULTED state to return to one of
 * offline, spare, or online (by the cpu requesting this state change).
 * First we cross-call to clear the AFSR (and AFSR_EXT on Panther) of
 * disrupting error bits that have accumulated without trapping, then
 * we cross-trap to re-enable CEEN controlled traps.
 */
void
cpu_faulted_exit(struct cpu *cp)
{
	ch_cpu_errors_t cpu_error_regs;

	cpu_error_regs.afsr = C_AFSR_CECC_ERRS;
	if (IS_PANTHER(cpunodes[cp->cpu_id].implementation))
		cpu_error_regs.afsr_ext &= C_AFSR_EXT_CECC_ERRS;
	xc_one(cp->cpu_id, (xcfunc_t *)set_cpu_error_state,
	    (uint64_t)&cpu_error_regs, 0);

	xt_one(cp->cpu_id, set_error_enable_tl1, EN_REG_CEEN, EER_SET_SETBITS);
}

/*
 * Return 1 if the errors in ch_flt's AFSR are secondary errors caused by
 * the errors in the original AFSR, 0 otherwise.
 *
 * For all procs if the initial error was a BERR or TO, then it is possible
 * that we may have caused a secondary BERR or TO in the process of logging the
 * inital error via cpu_run_bus_error_handlers().  If this is the case then
 * if the request was protected then a panic is still not necessary, if not
 * protected then aft_panic is already set - so either way there's no need
 * to set aft_panic for the secondary error.
 *
 * For Cheetah and Jalapeno, if the original error was a UE which occurred on
 * a store merge, then the error handling code will call cpu_deferred_error().
 * When clear_errors() is called, it will determine that secondary errors have
 * occurred - in particular, the store merge also caused a EDU and WDU that
 * weren't discovered until this point.
 *
 * We do three checks to verify that we are in this case.  If we pass all three
 * checks, we return 1 to indicate that we should not panic.  If any unexpected
 * errors occur, we return 0.
 *
 * For Cheetah+ and derivative procs, the store merge causes a DUE, which is
 * handled in cpu_disrupting_errors().  Since this function is not even called
 * in the case we are interested in, we just return 0 for these processors.
 */
/*ARGSUSED*/
static int
cpu_check_secondary_errors(ch_async_flt_t *ch_flt, uint64_t t_afsr_errs,
    uint64_t t_afar)
{
#if defined(CHEETAH_PLUS)
#else	/* CHEETAH_PLUS */
	struct async_flt *aflt = (struct async_flt *)ch_flt;
#endif	/* CHEETAH_PLUS */

	/*
	 * Was the original error a BERR or TO and only a BERR or TO
	 * (multiple errors are also OK)
	 */
	if ((t_afsr_errs & ~(C_AFSR_BERR | C_AFSR_TO | C_AFSR_ME)) == 0) {
		/*
		 * Is the new error a BERR or TO and only a BERR or TO
		 * (multiple errors are also OK)
		 */
		if ((ch_flt->afsr_errs &
		    ~(C_AFSR_BERR | C_AFSR_TO | C_AFSR_ME)) == 0)
			return (1);
	}

#if defined(CHEETAH_PLUS)
	return (0);
#else	/* CHEETAH_PLUS */
	/*
	 * Now look for secondary effects of a UE on cheetah/jalapeno
	 *
	 * Check the original error was a UE, and only a UE.  Note that
	 * the ME bit will cause us to fail this check.
	 */
	if (t_afsr_errs != C_AFSR_UE)
		return (0);

	/*
	 * Check the secondary errors were exclusively an EDU and/or WDU.
	 */
	if ((ch_flt->afsr_errs & ~(C_AFSR_EDU|C_AFSR_WDU)) != 0)
		return (0);

	/*
	 * Check the AFAR of the original error and secondary errors
	 * match to the 64-byte boundary
	 */
	if (P2ALIGN(aflt->flt_addr, 64) != P2ALIGN(t_afar, 64))
		return (0);

	/*
	 * We've passed all the checks, so it's a secondary error!
	 */
	return (1);
#endif	/* CHEETAH_PLUS */
}

/*
 * Translate the flt_bit or flt_type into an error type.  First, flt_bit
 * is checked for any valid errors.  If found, the error type is
 * returned. If not found, the flt_type is checked for L1$ parity errors.
 */
/*ARGSUSED*/
static uint8_t
cpu_flt_bit_to_plat_error(struct async_flt *aflt)
{
#if defined(JALAPENO)
	/*
	 * Currently, logging errors to the SC is not supported on Jalapeno
	 */
	return (PLAT_ECC_ERROR2_NONE);
#else
	ch_async_flt_t *ch_flt = (ch_async_flt_t *)aflt;

	switch (ch_flt->flt_bit) {
	case C_AFSR_CE:
		return (PLAT_ECC_ERROR2_CE);
	case C_AFSR_UCC:
	case C_AFSR_EDC:
	case C_AFSR_WDC:
	case C_AFSR_CPC:
		return (PLAT_ECC_ERROR2_L2_CE);
	case C_AFSR_EMC:
		return (PLAT_ECC_ERROR2_EMC);
	case C_AFSR_IVC:
		return (PLAT_ECC_ERROR2_IVC);
	case C_AFSR_UE:
		return (PLAT_ECC_ERROR2_UE);
	case C_AFSR_UCU:
	case C_AFSR_EDU:
	case C_AFSR_WDU:
	case C_AFSR_CPU:
		return (PLAT_ECC_ERROR2_L2_UE);
	case C_AFSR_IVU:
		return (PLAT_ECC_ERROR2_IVU);
	case C_AFSR_TO:
		return (PLAT_ECC_ERROR2_TO);
	case C_AFSR_BERR:
		return (PLAT_ECC_ERROR2_BERR);
#if defined(CHEETAH_PLUS)
	case C_AFSR_L3_EDC:
	case C_AFSR_L3_UCC:
	case C_AFSR_L3_CPC:
	case C_AFSR_L3_WDC:
		return (PLAT_ECC_ERROR2_L3_CE);
	case C_AFSR_IMC:
		return (PLAT_ECC_ERROR2_IMC);
	case C_AFSR_TSCE:
		return (PLAT_ECC_ERROR2_L2_TSCE);
	case C_AFSR_THCE:
		return (PLAT_ECC_ERROR2_L2_THCE);
	case C_AFSR_L3_MECC:
		return (PLAT_ECC_ERROR2_L3_MECC);
	case C_AFSR_L3_THCE:
		return (PLAT_ECC_ERROR2_L3_THCE);
	case C_AFSR_L3_CPU:
	case C_AFSR_L3_EDU:
	case C_AFSR_L3_UCU:
	case C_AFSR_L3_WDU:
		return (PLAT_ECC_ERROR2_L3_UE);
	case C_AFSR_DUE:
		return (PLAT_ECC_ERROR2_DUE);
	case C_AFSR_DTO:
		return (PLAT_ECC_ERROR2_DTO);
	case C_AFSR_DBERR:
		return (PLAT_ECC_ERROR2_DBERR);
#endif	/* CHEETAH_PLUS */
	default:
		switch (ch_flt->flt_type) {
#if defined(CPU_IMP_L1_CACHE_PARITY)
		case CPU_IC_PARITY:
			return (PLAT_ECC_ERROR2_IPE);
		case CPU_DC_PARITY:
			if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation)) {
				if (ch_flt->parity_data.dpe.cpl_cache ==
				    CPU_PC_PARITY) {
					return (PLAT_ECC_ERROR2_PCACHE);
				}
			}
			return (PLAT_ECC_ERROR2_DPE);
#endif /* CPU_IMP_L1_CACHE_PARITY */
		case CPU_ITLB_PARITY:
			return (PLAT_ECC_ERROR2_ITLB);
		case CPU_DTLB_PARITY:
			return (PLAT_ECC_ERROR2_DTLB);
		default:
			return (PLAT_ECC_ERROR2_NONE);
		}
	}
#endif	/* JALAPENO */
}
