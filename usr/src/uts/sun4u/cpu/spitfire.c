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
#include <sys/archsystm.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/cpu.h>
#include <sys/elf_SPARC.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kpm.h>
#include <vm/page.h>
#include <vm/vm_dep.h>
#include <sys/cpuvar.h>
#include <sys/spitregs.h>
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
#include <sys/ndifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/cpu/UltraSPARC-II.h>
#include <sys/ddi.h>
#include <sys/ecc_kstat.h>
#include <sys/watchpoint.h>
#include <sys/dtrace.h>
#include <sys/errclassify.h>

uint_t	cpu_impl_dual_pgsz = 0;

/*
 * Structure for the 8 byte ecache data dump and the associated AFSR state.
 * There will be 8 of these structures used to dump an ecache line (64 bytes).
 */
typedef struct sf_ec_data_elm {
	uint64_t ec_d8;
	uint64_t ec_afsr;
} ec_data_t;

/*
 * Define spitfire (Ultra I/II) specific asynchronous error structure
 */
typedef struct spitfire_async_flt {
	struct async_flt cmn_asyncflt;	/* common - see sun4u/sys/async.h */
	ushort_t flt_type;		/* types of faults - cpu specific */
	ec_data_t flt_ec_data[8];	/* for E$ or mem dump/state */
	uint64_t flt_ec_tag;		/* E$ tag info */
	int flt_ec_lcnt;		/* number of bad E$ lines */
	ushort_t flt_sdbh;		/* UDBH reg */
	ushort_t flt_sdbl;		/* UDBL reg */
} spitf_async_flt;

/*
 * Prototypes for support routines in spitfire_asm.s:
 */
extern void flush_ecache(uint64_t physaddr, size_t size, size_t linesize);
extern uint64_t get_lsu(void);
extern void set_lsu(uint64_t ncc);
extern void get_ecache_dtag(uint32_t ecache_idx, uint64_t *data, uint64_t *tag,
				uint64_t *oafsr, uint64_t *acc_afsr);
extern uint64_t check_ecache_line(uint32_t id, uint64_t *acc_afsr);
extern uint64_t get_ecache_tag(uint32_t id, uint64_t *nafsr,
				uint64_t *acc_afsr);
extern uint64_t read_and_clear_afsr();
extern void write_ec_tag_parity(uint32_t id);
extern void write_hb_ec_tag_parity(uint32_t id);

/*
 * Spitfire module routines:
 */
static void cpu_async_log_err(void *flt);
/*PRINTFLIKE6*/
static void cpu_aflt_log(int ce_code, int tagnum, spitf_async_flt *spflt,
    uint_t logflags, const char *endstr, const char *fmt, ...);

static void cpu_read_paddr(struct async_flt *aflt, short verbose, short ce_err);
static void cpu_ce_log_status(spitf_async_flt *spf_flt, char *unum);
static void cpu_log_ecmem_info(spitf_async_flt *spf_flt);

static void log_ce_err(struct async_flt *aflt, char *unum);
static void log_ue_err(struct async_flt *aflt, char *unum);
static void check_misc_err(spitf_async_flt *spf_flt);
static ushort_t ecc_gen(uint_t high_bytes, uint_t low_bytes);
static int check_ecc(struct async_flt *aflt);
static uint_t get_cpu_status(uint64_t arg);
static uint64_t clear_errors(spitf_async_flt *spf_flt, uint64_t *acc_afsr);
static void scan_ecache(uint64_t *afar, ec_data_t *data, uint64_t *tag,
		int *m, uint64_t *afsr);
static void ecache_kstat_init(struct cpu *cp);
static void ecache_scrub_log(ec_data_t *ec_data, uint64_t ec_tag,
		uint64_t paddr, int mpb, uint64_t);
static uint64_t ecache_scrub_misc_err(int, uint64_t);
static void ecache_scrub_tag_err(uint64_t, uchar_t, uint32_t);
static void ecache_page_retire(void *);
static int ecc_kstat_update(kstat_t *ksp, int rw);
static int ce_count_unum(int status, int len, char *unum);
static void add_leaky_bucket_timeout(void);
static int synd_to_synd_code(int synd_status, ushort_t synd);

extern uint_t read_all_memscrub;
extern void memscrub_run(void);

static uchar_t	isus2i;			/* set if sabre */
static uchar_t	isus2e;			/* set if hummingbird */

/*
 * Default ecache mask and shift settings for Spitfire.  If we detect a
 * different CPU implementation, we will modify these values at boot time.
 */
static uint64_t cpu_ec_tag_mask		= S_ECTAG_MASK;
static uint64_t cpu_ec_state_mask	= S_ECSTATE_MASK;
static uint64_t cpu_ec_par_mask		= S_ECPAR_MASK;
static int cpu_ec_par_shift		= S_ECPAR_SHIFT;
static int cpu_ec_tag_shift		= S_ECTAG_SHIFT;
static int cpu_ec_state_shift		= S_ECSTATE_SHIFT;
static uchar_t cpu_ec_state_exl		= S_ECSTATE_EXL;
static uchar_t cpu_ec_state_mod		= S_ECSTATE_MOD;
static uchar_t cpu_ec_state_shr		= S_ECSTATE_SHR;
static uchar_t cpu_ec_state_own		= S_ECSTATE_OWN;

/*
 * Default ecache state bits for Spitfire.  These individual bits indicate if
 * the given line is in any of the valid or modified states, respectively.
 * Again, we modify these at boot if we detect a different CPU.
 */
static uchar_t cpu_ec_state_valid	= S_ECSTATE_VALID;
static uchar_t cpu_ec_state_dirty	= S_ECSTATE_DIRTY;
static uchar_t cpu_ec_parity		= S_EC_PARITY;
static uchar_t cpu_ec_state_parity	= S_ECSTATE_PARITY;

/*
 * This table is used to determine which bit(s) is(are) bad when an ECC
 * error occurrs.  The array is indexed an 8-bit syndrome.  The entries
 * of this array have the following semantics:
 *
 *      00-63   The number of the bad bit, when only one bit is bad.
 *      64      ECC bit C0 is bad.
 *      65      ECC bit C1 is bad.
 *      66      ECC bit C2 is bad.
 *      67      ECC bit C3 is bad.
 *      68      ECC bit C4 is bad.
 *      69      ECC bit C5 is bad.
 *      70      ECC bit C6 is bad.
 *      71      ECC bit C7 is bad.
 *      72      Two bits are bad.
 *      73      Three bits are bad.
 *      74      Four bits are bad.
 *      75      More than Four bits are bad.
 *      76      NO bits are bad.
 * Based on "Galaxy Memory Subsystem SPECIFICATION" rev 0.6, pg. 28.
 */

#define	C0	64
#define	C1	65
#define	C2	66
#define	C3	67
#define	C4	68
#define	C5	69
#define	C6	70
#define	C7	71
#define	M2	72
#define	M3	73
#define	M4	74
#define	MX	75
#define	NA	76

#define	SYND_IS_SINGLE_BIT_DATA(synd_code)	((synd_code >= 0) && \
						    (synd_code < C0))
#define	SYND_IS_SINGLE_BIT_CHK(synd_code)	((synd_code >= C0) && \
						    (synd_code <= C7))

static char ecc_syndrome_tab[] =
{
	NA, C0, C1, M2, C2, M2, M2, M3, C3, M2, M2, M3, M2, M3, M3, M4,
	C4, M2, M2, 32, M2, 57, MX, M2, M2, 37, 49, M2, 40, M2, M2, 44,
	C5, M2, M2, 33, M2, 61,  4, M2, M2, MX, 53, M2, 45, M2, M2, 41,
	M2,  0,  1, M2, 10, M2, M2, MX, 15, M2, M2, MX, M2, M3, M3, M2,
	C6, M2, M2, 42, M2, 59, 39, M2, M2, MX, 51, M2, 34, M2, M2, 46,
	M2, 25, 29, M2, 27, M4, M2, MX, 31, M2, M4, MX, M2, MX, MX, M2,
	M2, MX, 36, M2,  7, M2, M2, 54, MX, M2, M2, 62, M2, 48, 56, M2,
	M3, M2, M2, MX, M2, MX, 22, M2, M2, 18, MX, M2, M3, M2, M2, MX,
	C7, M2, M2, 47, M2, 63, MX, M2, M2,  6, 55, M2, 35, M2, M2, 43,
	M2,  5, MX, M2, MX, M2, M2, 50, 38, M2, M2, 58, M2, 52, 60, M2,
	M2, 17, 21, M2, 19, M4, M2, MX, 23, M2, M4, MX, M2, MX, MX, M2,
	M3, M2, M2, MX, M2, MX, 30, M2, M2, 26, MX, M2, M3, M2, M2, MX,
	M2,  8, 13, M2,  2, M2, M2, M3,  3, M2, M2, M3, M2, MX, MX, M2,
	M3, M2, M2, M3, M2, MX, 16, M2, M2, 20, MX, M2, MX, M2, M2, MX,
	M3, M2, M2, M3, M2, MX, 24, M2, M2, 28, MX, M2, MX, M2, M2, MX,
	M4, 12,  9, M2, 14, M2, M2, MX, 11, M2, M2, MX, M2, MX, MX, M4
};

#define	SYND_TBL_SIZE 256

/*
 * Hack for determining UDBH/UDBL, for later cpu-specific error reporting.
 * Cannot use bit 3 in afar, because it is a valid bit on a Sabre/Hummingbird.
 */
#define	UDBL_REG	0x8000
#define	UDBL(synd)	((synd & UDBL_REG) >> 15)
#define	SYND(synd)	(synd & 0x7FFF)

/*
 * These error types are specific to Spitfire and are used internally for the
 * spitfire fault structure flt_type field.
 */
#define	CPU_UE_ERR		0	/* uncorrectable errors - UEs */
#define	CPU_EDP_LDP_ERR		1	/* LDP or EDP parity error */
#define	CPU_WP_ERR		2	/* WP parity error */
#define	CPU_BTO_BERR_ERR	3	/* bus timeout errors */
#define	CPU_PANIC_CP_ERR	4	/* cp error from panic polling */
#define	CPU_TRAPPING_CP_ERR	5	/* for sabre/hbird only, cp error */
#define	CPU_BADLINE_CI_ERR	6	/* E$ clean_bad line when idle */
#define	CPU_BADLINE_CB_ERR	7	/* E$ clean_bad line when busy */
#define	CPU_BADLINE_DI_ERR	8	/* E$ dirty_bad line when idle */
#define	CPU_BADLINE_DB_ERR	9	/* E$ dirty_bad line when busy */
#define	CPU_ORPHAN_CP_ERR	10	/* Orphan CP error */
#define	CPU_ECACHE_ADDR_PAR_ERR	11	/* Ecache Address parity error */
#define	CPU_ECACHE_STATE_ERR	12	/* Ecache state error */
#define	CPU_ECACHE_ETP_ETS_ERR	13	/* ETP set but ETS is zero */
#define	CPU_ECACHE_TAG_ERR	14	/* Scrub the E$ tag, if state clean */
#define	CPU_ADDITIONAL_ERR	15	/* Additional errors occurred */

/*
 * Macro to access the "Spitfire cpu private" data structure.
 */
#define	CPU_PRIVATE_PTR(cp, x)	(&(((spitfire_private_t *)CPU_PRIVATE(cp))->x))

/*
 * set to 0 to disable automatic retiring of pages on
 * DIMMs that have excessive soft errors
 */
int automatic_page_removal = 1;

/*
 * Heuristic for figuring out which module to replace.
 * Relative likelihood that this P_SYND indicates that this module is bad.
 * We call it a "score", though, not a relative likelihood.
 *
 * Step 1.
 * Assign a score to each byte of P_SYND according to the following rules:
 * If no bits on (0x00) or all bits on (0xFF), then give it a 5.
 * If one bit on, give it a 95.
 * If seven bits on, give it a 10.
 * If two bits on:
 *   in different nybbles, a 90
 *   in same nybble, but unaligned, 85
 *   in same nybble and as an aligned pair, 80
 * If six bits on, look at the bits that are off:
 *   in same nybble and as an aligned pair, 15
 *   in same nybble, but unaligned, 20
 *   in different nybbles, a 25
 * If three bits on:
 *   in diferent nybbles, no aligned pairs, 75
 *   in diferent nybbles, one aligned pair, 70
 *   in the same nybble, 65
 * If five bits on, look at the bits that are off:
 *   in the same nybble, 30
 *   in diferent nybbles, one aligned pair, 35
 *   in diferent nybbles, no aligned pairs, 40
 * If four bits on:
 *   all in one nybble, 45
 *   as two aligned pairs, 50
 *   one aligned pair, 55
 *   no aligned pairs, 60
 *
 * Step 2:
 * Take the higher of the two scores (one for each byte) as the score
 * for the module.
 *
 * Print the score for each module, and field service should replace the
 * module with the highest score.
 */

/*
 * In the table below, the first row/column comment indicates the
 * number of bits on in that nybble; the second row/column comment is
 * the hex digit.
 */

static int
p_synd_score_table[256] = {
	/* 0   1   1   2   1   2   2   3   1   2   2   3   2   3   3   4 */
	/* 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  A,  B,  C,  D,  E,  F */
/* 0 0 */  5, 95, 95, 80, 95, 85, 85, 65, 95, 85, 85, 65, 80, 65, 65, 45,
/* 1 1 */ 95, 90, 90, 70, 90, 75, 75, 55, 90, 75, 75, 55, 70, 55, 55, 30,
/* 1 2 */ 95, 90, 90, 70, 90, 75, 75, 55, 90, 75, 75, 55, 70, 55, 55, 30,
/* 2 3 */ 80, 70, 70, 50, 70, 55, 55, 35, 70, 55, 55, 35, 50, 35, 35, 15,
/* 1 4 */ 95, 90, 90, 70, 90, 75, 75, 55, 90, 75, 75, 55, 70, 55, 55, 30,
/* 2 5 */ 85, 75, 75, 55, 75, 60, 60, 40, 75, 60, 60, 40, 55, 40, 40, 20,
/* 2 6 */ 85, 75, 75, 55, 75, 60, 60, 40, 75, 60, 60, 40, 55, 40, 40, 20,
/* 3 7 */ 65, 55, 55, 35, 55, 40, 40, 25, 55, 40, 40, 25, 35, 25, 25, 10,
/* 1 8 */ 95, 90, 90, 70, 90, 75, 75, 55, 90, 75, 75, 55, 70, 55, 55, 30,
/* 2 9 */ 85, 75, 75, 55, 75, 60, 60, 40, 75, 60, 60, 40, 55, 40, 40, 20,
/* 2 A */ 85, 75, 75, 55, 75, 60, 60, 40, 75, 60, 60, 40, 55, 40, 40, 20,
/* 3 B */ 65, 55, 55, 35, 55, 40, 40, 25, 55, 40, 40, 25, 35, 25, 25, 10,
/* 2 C */ 80, 70, 70, 50, 70, 55, 55, 35, 70, 55, 55, 35, 50, 35, 35, 15,
/* 3 D */ 65, 55, 55, 35, 55, 40, 40, 25, 55, 40, 40, 25, 35, 25, 25, 10,
/* 3 E */ 65, 55, 55, 35, 55, 40, 40, 25, 55, 40, 40, 25, 35, 25, 25, 10,
/* 4 F */ 45, 30, 30, 15, 30, 20, 20, 10, 30, 20, 20, 10, 15, 10, 10,  5,
};

int
ecc_psynd_score(ushort_t p_synd)
{
	int i, j, a, b;

	i = p_synd & 0xFF;
	j = (p_synd >> 8) & 0xFF;

	a = p_synd_score_table[i];
	b = p_synd_score_table[j];

	return (a > b ? a : b);
}

/*
 * Async Fault Logging
 *
 * To ease identifying, reading, and filtering async fault log messages, the
 * label [AFT#] is now prepended to each async fault message.  These messages
 * and the logging rules are implemented by cpu_aflt_log(), below.
 *
 * [AFT0] - Tag for log messages that are associated with corrected ECC errors.
 *          This includes both corrected ECC memory and ecache faults.
 *
 * [AFT1] - Tag for log messages that are not ECC corrected (i.e. everything
 *          else except CE errors) with a priority of 1 (highest).  This tag
 *          is also used for panic messages that result from an async fault.
 *
 * [AFT2] - These are lower priority diagnostic messages for uncorrected ECC
 * [AFT3]   or parity errors.  For example, AFT2 is used for the actual dump
 *          of the E-$ data and tags.
 *
 * In a non-DEBUG kernel, AFT > 1 logs will be sent to the system log but not
 * printed on the console.  To send all AFT logs to both the log and the
 * console, set aft_verbose = 1.
 */

#define	CPU_FLTCPU		0x0001	/* print flt_inst as a CPU id */
#define	CPU_SPACE		0x0002	/* print flt_status (data or instr) */
#define	CPU_ERRID		0x0004	/* print flt_id */
#define	CPU_TL			0x0008	/* print flt_tl */
#define	CPU_ERRID_FIRST 	0x0010	/* print flt_id first in message */
#define	CPU_AFSR		0x0020	/* print flt_stat as decoded %afsr */
#define	CPU_AFAR		0x0040	/* print flt_addr as %afar */
#define	CPU_AF_PSYND		0x0080	/* print flt_stat %afsr.PSYND */
#define	CPU_AF_ETS		0x0100	/* print flt_stat %afsr.ETS */
#define	CPU_UDBH		0x0200	/* print flt_sdbh and syndrome */
#define	CPU_UDBL		0x0400	/* print flt_sdbl and syndrome */
#define	CPU_FAULTPC		0x0800	/* print flt_pc */
#define	CPU_SYND		0x1000	/* print flt_synd and unum */

#define	CMN_LFLAGS	(CPU_FLTCPU | CPU_SPACE | CPU_ERRID | CPU_TL |	\
				CPU_AFSR | CPU_AFAR | CPU_AF_PSYND |	\
				CPU_AF_ETS | CPU_UDBH | CPU_UDBL |	\
				CPU_FAULTPC)
#define	UE_LFLAGS	(CMN_LFLAGS | CPU_SYND)
#define	CE_LFLAGS	(UE_LFLAGS & ~CPU_UDBH & ~CPU_UDBL & ~CPU_TL &	\
				~CPU_SPACE)
#define	PARERR_LFLAGS	(CMN_LFLAGS)
#define	WP_LFLAGS	(CMN_LFLAGS & ~CPU_SPACE & ~CPU_TL)
#define	CP_LFLAGS	(CMN_LFLAGS & ~CPU_SPACE & ~CPU_TL &		\
				~CPU_FLTCPU & ~CPU_FAULTPC)
#define	BERRTO_LFLAGS	(CMN_LFLAGS)
#define	NO_LFLAGS	(0)

#define	AFSR_FMTSTR0	"\020\1ME"
#define	AFSR_FMTSTR1	"\020\040PRIV\037ISAP\036ETP\035IVUE\034TO"	\
			"\033BERR\032LDP\031CP\030WP\027EDP\026UE\025CE"
#define	UDB_FMTSTR	"\020\012UE\011CE"

/*
 * Save the cache bootup state for use when internal
 * caches are to be re-enabled after an error occurs.
 */
uint64_t	cache_boot_state = 0;

/*
 * PA[31:0] represent Displacement in UPA configuration space.
 */
uint_t	root_phys_addr_lo_mask = 0xffffffff;

/*
 * Spitfire legacy globals
 */
int	itlb_entries;
int	dtlb_entries;

void
cpu_setup(void)
{
	extern int page_retire_messages;
	extern int page_retire_first_ue;
	extern int at_flags;
#if defined(SF_ERRATA_57)
	extern caddr_t errata57_limit;
#endif
	cache |= (CACHE_VAC | CACHE_PTAG | CACHE_IOCOHERENT);

	at_flags = EF_SPARC_32PLUS | EF_SPARC_SUN_US1;

	/*
	 * Spitfire isn't currently FMA-aware, so we have to enable the
	 * page retirement messages. We also change the default policy
	 * for UE retirement to allow clearing of transient errors.
	 */
	page_retire_messages = 1;
	page_retire_first_ue = 0;

	/*
	 * save the cache bootup state.
	 */
	cache_boot_state = get_lsu() & (LSU_IC | LSU_DC);

	if (use_page_coloring) {
		do_pg_coloring = 1;
	}

	/*
	 * Tune pp_slots to use up to 1/8th of the tlb entries.
	 */
	pp_slots = MIN(8, MAXPP_SLOTS);

	/*
	 * Block stores invalidate all pages of the d$ so pagecopy
	 * et. al. do not need virtual translations with virtual
	 * coloring taken into consideration.
	 */
	pp_consistent_coloring = 0;

	isa_list =
	    "sparcv9+vis sparcv9 "
	    "sparcv8plus+vis sparcv8plus "
	    "sparcv8 sparcv8-fsmuld sparcv7 sparc";

	cpu_hwcap_flags = AV_SPARC_VIS;

	/*
	 * On Spitfire, there's a hole in the address space
	 * that we must never map (the hardware only support 44-bits of
	 * virtual address).  Later CPUs are expected to have wider
	 * supported address ranges.
	 *
	 * See address map on p23 of the UltraSPARC 1 user's manual.
	 */
	hole_start = (caddr_t)0x80000000000ull;
	hole_end = (caddr_t)0xfffff80000000000ull;

	/*
	 * A spitfire call bug requires us to be a further 4Gbytes of
	 * firewall from the spec.
	 *
	 * See Spitfire Errata #21
	 */
	hole_start = (caddr_t)((uintptr_t)hole_start - (1ul << 32));
	hole_end = (caddr_t)((uintptr_t)hole_end + (1ul << 32));

	/*
	 * The kpm mapping window.
	 * kpm_size:
	 *	The size of a single kpm range.
	 *	The overall size will be: kpm_size * vac_colors.
	 * kpm_vbase:
	 *	The virtual start address of the kpm range within the kernel
	 *	virtual address space. kpm_vbase has to be kpm_size aligned.
	 */
	kpm_size = (size_t)(2ull * 1024 * 1024 * 1024 * 1024); /* 2TB */
	kpm_size_shift = 41;
	kpm_vbase = (caddr_t)0xfffffa0000000000ull; /* 16EB - 6TB */

	/*
	 * All UltraSPARC platforms should use small kpm page as default, as
	 * the KPM large page VAC conflict code has no value to maintain. The
	 * new generation of SPARC no longer have VAC conflict issue.
	 */
	kpm_smallpages = 1;

#if defined(SF_ERRATA_57)
	errata57_limit = (caddr_t)0x80000000ul;
#endif

	/*
	 * Disable text by default.
	 * Note that the other defaults are set in sun4u/vm/mach_vm_dep.c.
	 */
	max_utext_lpsize = MMU_PAGESIZE;
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
 * Set the magic constants of the implementation.
 */
void
cpu_fiximp(pnode_t dnode)
{
	extern int vac_size, vac_shift;
	extern uint_t vac_mask;
	extern int dcache_line_mask;
	int i, a;
	static struct {
		char	*name;
		int	*var;
	} prop[] = {
		"dcache-size",		&dcache_size,
		"dcache-line-size",	&dcache_linesize,
		"icache-size",		&icache_size,
		"icache-line-size",	&icache_linesize,
		"ecache-size",		&ecache_size,
		"ecache-line-size",	&ecache_alignsize,
		"ecache-associativity", &ecache_associativity,
		"#itlb-entries",	&itlb_entries,
		"#dtlb-entries",	&dtlb_entries,
		};

	for (i = 0; i < sizeof (prop) / sizeof (prop[0]); i++) {
		if ((a = getintprop(dnode, prop[i].name, -1)) != -1) {
			*prop[i].var = a;
		}
	}

	ecache_setsize = ecache_size / ecache_associativity;

	vac_size = S_VAC_SIZE;
	vac_mask = MMU_PAGEMASK & (vac_size - 1);
	i = 0; a = vac_size;
	while (a >>= 1)
		++i;
	vac_shift = i;
	shm_alignment = vac_size;
	vac = 1;

	dcache_line_mask = (dcache_size - 1) & ~(dcache_linesize - 1);

	/*
	 * UltraSPARC I & II have ecache sizes running
	 * as follows: .25 MB, .5 MB, 1 MB, 2 MB, 4 MB
	 * and 8 MB. Adjust the copyin/copyout limits
	 * according to the cache size. The magic number
	 * of VIS_COPY_THRESHOLD comes from the copyin/copyout code
	 * and its floor of VIS_COPY_THRESHOLD bytes before it will use
	 * VIS instructions.
	 *
	 * We assume that all CPUs on the system have the same size
	 * ecache. We're also called very early in the game.
	 * /etc/system will be parsed *after* we're called so
	 * these values can be overwritten.
	 */

	hw_copy_limit_1 = VIS_COPY_THRESHOLD;
	if (ecache_size <= 524288) {
		hw_copy_limit_2 = VIS_COPY_THRESHOLD;
		hw_copy_limit_4 = VIS_COPY_THRESHOLD;
		hw_copy_limit_8 = VIS_COPY_THRESHOLD;
	} else if (ecache_size == 1048576) {
		hw_copy_limit_2 = 1024;
		hw_copy_limit_4 = 1280;
		hw_copy_limit_8 = 1536;
	} else if (ecache_size == 2097152) {
		hw_copy_limit_2 = 1536;
		hw_copy_limit_4 = 2048;
		hw_copy_limit_8 = 2560;
	} else if (ecache_size == 4194304) {
		hw_copy_limit_2 = 2048;
		hw_copy_limit_4 = 2560;
		hw_copy_limit_8 = 3072;
	} else {
		hw_copy_limit_2 = 2560;
		hw_copy_limit_4 = 3072;
		hw_copy_limit_8 = 3584;
	}
}

/*
 * Called by setcpudelay
 */
void
cpu_init_tick_freq(void)
{
	/*
	 * Determine the cpu frequency by calling
	 * tod_get_cpufrequency. Use an approximate freqency
	 * value computed by the prom if the tod module
	 * is not initialized and loaded yet.
	 */
	if (tod_ops.tod_get_cpufrequency != NULL) {
		mutex_enter(&tod_lock);
		sys_tick_freq = tod_ops.tod_get_cpufrequency();
		mutex_exit(&tod_lock);
	} else {
#if defined(HUMMINGBIRD)
		/*
		 * the hummingbird version of %stick is used as the basis for
		 * low level timing; this provides an independent constant-rate
		 * clock for general system use, and frees power mgmt to set
		 * various cpu clock speeds.
		 */
		if (system_clock_freq == 0)
			cmn_err(CE_PANIC, "invalid system_clock_freq 0x%lx",
			    system_clock_freq);
		sys_tick_freq = system_clock_freq;
#else /* SPITFIRE */
		sys_tick_freq = cpunodes[CPU->cpu_id].clock_freq;
#endif
	}
}


void shipit(int upaid);
extern uint64_t xc_tick_limit;
extern uint64_t xc_tick_jump_limit;

#ifdef SEND_MONDO_STATS
uint64_t x_early[NCPU][64];
#endif

/*
 * Note: A version of this function is used by the debugger via the KDI,
 * and must be kept in sync with this version.  Any changes made to this
 * function to support new chips or to accomodate errata must also be included
 * in the KDI-specific version.  See spitfire_kdi.c.
 */
void
send_one_mondo(int cpuid)
{
	uint64_t idsr, starttick, endtick;
	int upaid, busy, nack;
	uint64_t tick, tick_prev;
	ulong_t ticks;

	CPU_STATS_ADDQ(CPU, sys, xcalls, 1);
	upaid = CPUID_TO_UPAID(cpuid);
	tick = starttick = gettick();
	shipit(upaid);
	endtick = starttick + xc_tick_limit;
	busy = nack = 0;
	for (;;) {
		idsr = getidsr();
		if (idsr == 0)
			break;
		/*
		 * When we detect an irregular tick jump, we adjust
		 * the timer window to the current tick value.
		 */
		tick_prev = tick;
		tick = gettick();
		ticks = tick - tick_prev;
		if (ticks > xc_tick_jump_limit) {
			endtick = tick + xc_tick_limit;
		} else if (tick > endtick) {
			if (panic_quiesce)
				return;
			cmn_err(CE_PANIC,
			    "send mondo timeout (target 0x%x) [%d NACK %d "
			    "BUSY]", upaid, nack, busy);
		}
		if (idsr & IDSR_BUSY) {
			busy++;
			continue;
		}
		drv_usecwait(1);
		shipit(upaid);
		nack++;
		busy = 0;
	}
#ifdef SEND_MONDO_STATS
	x_early[getprocessorid()][highbit(gettick() - starttick) - 1]++;
#endif
}

void
send_mondo_set(cpuset_t set)
{
	int i;

	for (i = 0; i < NCPU; i++)
		if (CPU_IN_SET(set, i)) {
			send_one_mondo(i);
			CPUSET_DEL(set, i);
			if (CPUSET_ISNULL(set))
				break;
		}
}

void
syncfpu(void)
{
}

/*
 * Determine the size of the CPU module's error structure in bytes.  This is
 * called once during boot to initialize the error queues.
 */
int
cpu_aflt_size(void)
{
	/*
	 * We need to determine whether this is a sabre, Hummingbird or a
	 * Spitfire/Blackbird impl and set the appropriate state variables for
	 * ecache tag manipulation.  We can't do this in cpu_setup() as it is
	 * too early in the boot flow and the cpunodes are not initialized.
	 * This routine will be called once after cpunodes[] is ready, so do
	 * it here.
	 */
	if (cpunodes[CPU->cpu_id].implementation == SABRE_IMPL) {
		isus2i = 1;
		cpu_ec_tag_mask = SB_ECTAG_MASK;
		cpu_ec_state_mask = SB_ECSTATE_MASK;
		cpu_ec_par_mask = SB_ECPAR_MASK;
		cpu_ec_par_shift = SB_ECPAR_SHIFT;
		cpu_ec_tag_shift = SB_ECTAG_SHIFT;
		cpu_ec_state_shift = SB_ECSTATE_SHIFT;
		cpu_ec_state_exl = SB_ECSTATE_EXL;
		cpu_ec_state_mod = SB_ECSTATE_MOD;

		/* These states do not exist in sabre - set to 0xFF */
		cpu_ec_state_shr = 0xFF;
		cpu_ec_state_own = 0xFF;

		cpu_ec_state_valid = SB_ECSTATE_VALID;
		cpu_ec_state_dirty = SB_ECSTATE_DIRTY;
		cpu_ec_state_parity = SB_ECSTATE_PARITY;
		cpu_ec_parity = SB_EC_PARITY;
	} else if (cpunodes[CPU->cpu_id].implementation == HUMMBRD_IMPL) {
		isus2e = 1;
		cpu_ec_tag_mask = HB_ECTAG_MASK;
		cpu_ec_state_mask = HB_ECSTATE_MASK;
		cpu_ec_par_mask = HB_ECPAR_MASK;
		cpu_ec_par_shift = HB_ECPAR_SHIFT;
		cpu_ec_tag_shift = HB_ECTAG_SHIFT;
		cpu_ec_state_shift = HB_ECSTATE_SHIFT;
		cpu_ec_state_exl = HB_ECSTATE_EXL;
		cpu_ec_state_mod = HB_ECSTATE_MOD;

		/* These states do not exist in hummingbird - set to 0xFF */
		cpu_ec_state_shr = 0xFF;
		cpu_ec_state_own = 0xFF;

		cpu_ec_state_valid = HB_ECSTATE_VALID;
		cpu_ec_state_dirty = HB_ECSTATE_DIRTY;
		cpu_ec_state_parity = HB_ECSTATE_PARITY;
		cpu_ec_parity = HB_EC_PARITY;
	}

	return (sizeof (spitf_async_flt));
}


/*
 * Correctable ecc error trap handler
 */
/*ARGSUSED*/
void
cpu_ce_error(struct regs *rp, ulong_t p_afar, ulong_t p_afsr,
	uint_t p_afsr_high, uint_t p_afar_high)
{
	ushort_t sdbh, sdbl;
	ushort_t e_syndh, e_syndl;
	spitf_async_flt spf_flt;
	struct async_flt *ecc;
	int queue = 1;

	uint64_t t_afar = p_afar;
	uint64_t t_afsr = p_afsr;

	/*
	 * Note: the Spitfire data buffer error registers
	 * (upper and lower halves) are or'ed into the upper
	 * word of the afsr by ce_err().
	 */
	sdbh = (ushort_t)((t_afsr >> 33) & 0x3FF);
	sdbl = (ushort_t)((t_afsr >> 43) & 0x3FF);

	e_syndh = (uchar_t)(sdbh & (uint_t)P_DER_E_SYND);
	e_syndl = (uchar_t)(sdbl & (uint_t)P_DER_E_SYND);

	t_afsr &= S_AFSR_MASK;
	t_afar &= SABRE_AFAR_PA;	/* must use Sabre AFAR mask */

	/* Setup the async fault structure */
	bzero(&spf_flt, sizeof (spitf_async_flt));
	ecc = (struct async_flt *)&spf_flt;
	ecc->flt_id = gethrtime_waitfree();
	ecc->flt_stat = t_afsr;
	ecc->flt_addr = t_afar;
	ecc->flt_status = ECC_C_TRAP;
	ecc->flt_bus_id = getprocessorid();
	ecc->flt_inst = CPU->cpu_id;
	ecc->flt_pc = (caddr_t)rp->r_pc;
	ecc->flt_func = log_ce_err;
	ecc->flt_in_memory =
	    (pf_is_memory(ecc->flt_addr >> MMU_PAGESHIFT)) ? 1: 0;
	spf_flt.flt_sdbh = sdbh;
	spf_flt.flt_sdbl = sdbl;

	/*
	 * Check for fatal conditions.
	 */
	check_misc_err(&spf_flt);

	/*
	 * Pananoid checks for valid AFSR and UDBs
	 */
	if ((t_afsr & P_AFSR_CE) == 0) {
		cpu_aflt_log(CE_PANIC, 1, &spf_flt, CMN_LFLAGS,
		    "** Panic due to CE bit not set in the AFSR",
		    "  Corrected Memory Error on");
	}

	/*
	 * We want to skip logging only if ALL the following
	 * conditions are true:
	 *
	 *	1. There is only one error
	 *	2. That error is a correctable memory error
	 *	3. The error is caused by the memory scrubber (in which case
	 *	    the error will have occurred under on_trap protection)
	 *	4. The error is on a retired page
	 *
	 * Note: OT_DATA_EC is used places other than the memory scrubber.
	 * However, none of those errors should occur on a retired page.
	 */
	if ((ecc->flt_stat & (S_AFSR_ALL_ERRS & ~P_AFSR_ME)) == P_AFSR_CE &&
	    curthread->t_ontrap != NULL) {

		if (curthread->t_ontrap->ot_prot & OT_DATA_EC) {
			if (page_retire_check(ecc->flt_addr, NULL) == 0) {
				queue = 0;
			}
		}
	}

	if (((sdbh & P_DER_CE) == 0) && ((sdbl & P_DER_CE) == 0)) {
		cpu_aflt_log(CE_PANIC, 1, &spf_flt, CMN_LFLAGS,
		    "** Panic due to CE bits not set in the UDBs",
		    " Corrected Memory Error on");
	}

	if ((sdbh >> 8) & 1) {
		ecc->flt_synd = e_syndh;
		ce_scrub(ecc);
		if (queue) {
			cpu_errorq_dispatch(FM_EREPORT_CPU_USII_CE, ecc,
			    sizeof (*ecc), ce_queue, ERRORQ_ASYNC);
		}
	}

	if ((sdbl >> 8) & 1) {
		ecc->flt_addr = t_afar | 0x8;	/* Sabres do not have a UDBL */
		ecc->flt_synd = e_syndl | UDBL_REG;
		ce_scrub(ecc);
		if (queue) {
			cpu_errorq_dispatch(FM_EREPORT_CPU_USII_CE, ecc,
			    sizeof (*ecc), ce_queue, ERRORQ_ASYNC);
		}
	}

	/*
	 * Re-enable all error trapping (CEEN currently cleared).
	 */
	clr_datapath();
	set_asyncflt(P_AFSR_CE);
	set_error_enable(EER_ENABLE);
}

/*
 * Cpu specific CE logging routine
 */
static void
log_ce_err(struct async_flt *aflt, char *unum)
{
	spitf_async_flt spf_flt;

	if ((aflt->flt_stat & P_AFSR_CE) && (ce_verbose_memory == 0)) {
		return;
	}

	spf_flt.cmn_asyncflt = *aflt;
	cpu_aflt_log(CE_CONT, 0, &spf_flt, CE_LFLAGS, unum,
	    " Corrected Memory Error detected by");
}

/*
 * Spitfire does not perform any further CE classification refinement
 */
/*ARGSUSED*/
int
ce_scrub_xdiag_recirc(struct async_flt *ecc, errorq_t *eqp, errorq_elem_t *eqep,
    size_t afltoffset)
{
	return (0);
}

char *
flt_to_error_type(struct async_flt *aflt)
{
	if (aflt->flt_status & ECC_INTERMITTENT)
		return (ERR_TYPE_DESC_INTERMITTENT);
	if (aflt->flt_status & ECC_PERSISTENT)
		return (ERR_TYPE_DESC_PERSISTENT);
	if (aflt->flt_status & ECC_STICKY)
		return (ERR_TYPE_DESC_STICKY);
	return (ERR_TYPE_DESC_UNKNOWN);
}

/*
 * Called by correctable ecc error logging code to print out
 * the stick/persistent/intermittent status of the error.
 */
static void
cpu_ce_log_status(spitf_async_flt *spf_flt, char *unum)
{
	ushort_t status;
	char *status1_str = "Memory";
	char *status2_str = "Intermittent";
	struct async_flt *aflt = (struct async_flt *)spf_flt;

	status = aflt->flt_status;

	if (status & ECC_ECACHE)
		status1_str = "Ecache";

	if (status & ECC_STICKY)
		status2_str = "Sticky";
	else if (status & ECC_PERSISTENT)
		status2_str = "Persistent";

	cpu_aflt_log(CE_CONT, 0, spf_flt, CPU_ERRID_FIRST,
	    NULL, " Corrected %s Error on %s is %s",
	    status1_str, unum, status2_str);
}

/*
 * check for a valid ce syndrome, then call the
 * displacement flush scrubbing code, and then check the afsr to see if
 * the error was persistent or intermittent. Reread the afar/afsr to see
 * if the error was not scrubbed successfully, and is therefore sticky.
 */
/*ARGSUSED1*/
void
cpu_ce_scrub_mem_err(struct async_flt *ecc, boolean_t triedcpulogout)
{
	uint64_t eer, afsr;
	ushort_t status;

	ASSERT(getpil() > LOCK_LEVEL);

	/*
	 * It is possible that the flt_addr is not a valid
	 * physical address. To deal with this, we disable
	 * NCEEN while we scrub that address. If this causes
	 * a TIMEOUT/BERR, we know this is an invalid
	 * memory location.
	 */
	kpreempt_disable();
	eer = get_error_enable();
	if (eer & (EER_CEEN | EER_NCEEN))
		set_error_enable(eer & ~(EER_CEEN | EER_NCEEN));

	/*
	 * To check if the error detected by IO is persistent, sticky or
	 * intermittent.
	 */
	if (ecc->flt_status & ECC_IOBUS) {
		ecc->flt_stat = P_AFSR_CE;
	}

	scrubphys(P2ALIGN(ecc->flt_addr, 64),
	    cpunodes[CPU->cpu_id].ecache_size);

	get_asyncflt(&afsr);
	if (afsr & (P_AFSR_TO | P_AFSR_BERR)) {
		/*
		 * Must ensure that we don't get the TIMEOUT/BERR
		 * when we reenable NCEEN, so we clear the AFSR.
		 */
		set_asyncflt(afsr & (P_AFSR_TO | P_AFSR_BERR));
		if (eer & (EER_CEEN | EER_NCEEN))
			set_error_enable(eer);
		kpreempt_enable();
		return;
	}

	if (eer & EER_NCEEN)
		set_error_enable(eer & ~EER_CEEN);

	/*
	 * Check and clear any ECC errors from the scrub.  If the scrub did
	 * not trip over the error, mark it intermittent.  If the scrub did
	 * trip the error again and it did not scrub away, mark it sticky.
	 * Otherwise mark it persistent.
	 */
	if (check_ecc(ecc) != 0) {
		cpu_read_paddr(ecc, 0, 1);

		if (check_ecc(ecc) != 0)
			status = ECC_STICKY;
		else
			status = ECC_PERSISTENT;
	} else
		status = ECC_INTERMITTENT;

	if (eer & (EER_CEEN | EER_NCEEN))
		set_error_enable(eer);
	kpreempt_enable();

	ecc->flt_status &= ~(ECC_INTERMITTENT | ECC_PERSISTENT | ECC_STICKY);
	ecc->flt_status |= status;
}

/*
 * get the syndrome and unum, and then call the routines
 * to check the other cpus and iobuses, and then do the error logging.
 */
/*ARGSUSED1*/
void
cpu_ce_log_err(struct async_flt *ecc, errorq_elem_t *eqep)
{
	char unum[UNUM_NAMLEN];
	int len = 0;
	int ce_verbose = 0;
	int err;

	ASSERT(ecc->flt_func != NULL);

	/* Get the unum string for logging purposes */
	(void) cpu_get_mem_unum_aflt(AFLT_STAT_VALID, ecc, unum,
	    UNUM_NAMLEN, &len);

	/* Call specific error logging routine */
	(void) (*ecc->flt_func)(ecc, unum);

	/*
	 * Count errors per unum.
	 * Non-memory errors are all counted via a special unum string.
	 */
	if ((err = ce_count_unum(ecc->flt_status, len, unum)) != PR_OK &&
	    automatic_page_removal) {
		(void) page_retire(ecc->flt_addr, err);
	}

	if (ecc->flt_panic) {
		ce_verbose = 1;
	} else if ((ecc->flt_class == BUS_FAULT) ||
	    (ecc->flt_stat & P_AFSR_CE)) {
		ce_verbose = (ce_verbose_memory > 0);
	} else {
		ce_verbose = 1;
	}

	if (ce_verbose) {
		spitf_async_flt sflt;
		int synd_code;

		sflt.cmn_asyncflt = *ecc;	/* for cpu_aflt_log() */

		cpu_ce_log_status(&sflt, unum);

		synd_code = synd_to_synd_code(AFLT_STAT_VALID,
		    SYND(ecc->flt_synd));

		if (SYND_IS_SINGLE_BIT_DATA(synd_code)) {
			cpu_aflt_log(CE_CONT, 0, &sflt, CPU_ERRID_FIRST,
			    NULL, " ECC Data Bit %2d was in error "
			    "and corrected", synd_code);
		} else if (SYND_IS_SINGLE_BIT_CHK(synd_code)) {
			cpu_aflt_log(CE_CONT, 0, &sflt, CPU_ERRID_FIRST,
			    NULL, " ECC Check Bit %2d was in error "
			    "and corrected", synd_code - C0);
		} else {
			/*
			 * These are UE errors - we shouldn't be getting CE
			 * traps for these; handle them in case of bad h/w.
			 */
			switch (synd_code) {
			case M2:
				cpu_aflt_log(CE_CONT, 0, &sflt,
				    CPU_ERRID_FIRST, NULL,
				    " Two ECC Bits were in error");
				break;
			case M3:
				cpu_aflt_log(CE_CONT, 0, &sflt,
				    CPU_ERRID_FIRST, NULL,
				    " Three ECC Bits were in error");
				break;
			case M4:
				cpu_aflt_log(CE_CONT, 0, &sflt,
				    CPU_ERRID_FIRST, NULL,
				    " Four ECC Bits were in error");
				break;
			case MX:
				cpu_aflt_log(CE_CONT, 0, &sflt,
				    CPU_ERRID_FIRST, NULL,
				    " More than Four ECC bits were "
				    "in error");
				break;
			default:
				cpu_aflt_log(CE_CONT, 0, &sflt,
				    CPU_ERRID_FIRST, NULL,
				    " Unknown fault syndrome %d",
				    synd_code);
				break;
			}
		}
	}

	/* Display entire cache line, if valid address */
	if (ce_show_data && ecc->flt_addr != AFLT_INV_ADDR)
		read_ecc_data(ecc, 1, 1);
}

/*
 * We route all errors through a single switch statement.
 */
void
cpu_ue_log_err(struct async_flt *aflt)
{

	switch (aflt->flt_class) {
	case CPU_FAULT:
		cpu_async_log_err(aflt);
		break;

	case BUS_FAULT:
		bus_async_log_err(aflt);
		break;

	default:
		cmn_err(CE_WARN, "discarding async error 0x%p with invalid "
		    "fault class (0x%x)", (void *)aflt, aflt->flt_class);
		break;
	}
}

/* Values for action variable in cpu_async_error() */
#define	ACTION_NONE		0
#define	ACTION_TRAMPOLINE	1
#define	ACTION_AST_FLAGS	2

/*
 * Access error trap handler for asynchronous cpu errors.  This routine is
 * called to handle a data or instruction access error.  All fatal errors are
 * completely handled by this routine (by panicking).  Non fatal error logging
 * is queued for later processing either via AST or softint at a lower PIL.
 * In case of panic, the error log queue will also be processed as part of the
 * panic flow to ensure all errors are logged.  This routine is called with all
 * errors disabled at PIL15.  The AFSR bits are cleared and the UDBL and UDBH
 * error bits are also cleared.  The hardware has also disabled the I and
 * D-caches for us, so we must re-enable them before returning.
 *
 * A summary of the handling of tl=0 UE/LDP/EDP/TO/BERR/WP/CP:
 *
 *		_______________________________________________________________
 *		|        Privileged tl0		|         Unprivileged	      |
 *		| Protected	| Unprotected	| Protected	| Unprotected |
 *		|on_trap|lofault|		|		|	      |
 * -------------|-------|-------+---------------+---------------+-------------|
 *		|	|	|		|		|	      |
 * UE/LDP/EDP	| L,T,p	| L,R,p	| L,P		| n/a		| L,R,p	      |
 *		|	|	|		|		|	      |
 * TO/BERR	| T	| S	| L,P		| n/a		| S	      |
 *		|	|	|		|		|	      |
 * WP		| L,M,p | L,M,p	| L,M,p		| n/a		| L,M,p       |
 *		|	|	|		|		|	      |
 * CP (IIi/IIe)	| L,P	| L,P	| L,P		| n/a		| L,P	      |
 * ____________________________________________________________________________
 *
 *
 * Action codes:
 *
 * L - log
 * M - kick off memscrubber if flt_in_memory
 * P - panic
 * p - panic if US-IIi or US-IIe (Sabre); overrides R and M
 * R - i)  if aft_panic is set, panic
 *     ii) otherwise, send hwerr event to contract and SIGKILL to process
 * S - send SIGBUS to process
 * T - trampoline
 *
 * Special cases:
 *
 * 1) if aft_testfatal is set, all faults result in a panic regardless
 *    of type (even WP), protection (even on_trap), or privilege.
 */
/*ARGSUSED*/
void
cpu_async_error(struct regs *rp, ulong_t p_afar, ulong_t p_afsr,
	uint_t p_afsr_high, uint_t p_afar_high)
{
	ushort_t sdbh, sdbl, ttype, tl;
	spitf_async_flt spf_flt;
	struct async_flt *aflt;
	char pr_reason[28];
	uint64_t oafsr;
	uint64_t acc_afsr = 0;			/* accumulated afsr */
	int action = ACTION_NONE;
	uint64_t t_afar = p_afar;
	uint64_t t_afsr = p_afsr;
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
	 * Note: the Spitfire data buffer error registers
	 * (upper and lower halves) are or'ed into the upper
	 * word of the afsr by async_err() if P_AFSR_UE is set.
	 */
	sdbh = (ushort_t)((t_afsr >> 33) & 0x3FF);
	sdbl = (ushort_t)((t_afsr >> 43) & 0x3FF);

	/*
	 * Grab the ttype encoded in <63:53> of the saved
	 * afsr passed from async_err()
	 */
	ttype = (ushort_t)((t_afsr >> 53) & 0x1FF);
	tl = (ushort_t)(t_afsr >> 62);

	t_afsr &= S_AFSR_MASK;
	t_afar &= SABRE_AFAR_PA;	/* must use Sabre AFAR mask */

	/*
	 * Initialize most of the common and CPU-specific structure.  We derive
	 * aflt->flt_priv from %tstate, instead of from the AFSR.PRIV bit.  The
	 * initial setting of aflt->flt_panic is based on TL: we must panic if
	 * the error occurred at TL > 0.  We also set flt_panic if the test/demo
	 * tuneable aft_testfatal is set (not the default).
	 */
	bzero(&spf_flt, sizeof (spitf_async_flt));
	aflt = (struct async_flt *)&spf_flt;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_stat = t_afsr;
	aflt->flt_addr = t_afar;
	aflt->flt_bus_id = getprocessorid();
	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_pc = (caddr_t)rp->r_pc;
	aflt->flt_prot = AFLT_PROT_NONE;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_priv = (rp->r_tstate & TSTATE_PRIV) ? 1 : 0;
	aflt->flt_tl = (uchar_t)tl;
	aflt->flt_panic = (tl != 0 || aft_testfatal != 0);
	aflt->flt_core = (pflag & SDOCORE) ? 1 : 0;

	/*
	 * Set flt_status based on the trap type.  If we end up here as the
	 * result of a UE detected by the CE handling code, leave status 0.
	 */
	switch (ttype) {
	case T_DATA_ERROR:
		aflt->flt_status = ECC_D_TRAP;
		break;
	case T_INSTR_ERROR:
		aflt->flt_status = ECC_I_TRAP;
		break;
	}

	spf_flt.flt_sdbh = sdbh;
	spf_flt.flt_sdbl = sdbl;

	/*
	 * Check for fatal async errors.
	 */
	check_misc_err(&spf_flt);

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
				action = ACTION_TRAMPOLINE;
			}

			if ((t_afsr & (P_AFSR_TO | P_AFSR_BERR)) &&
			    (otp->ot_prot & OT_DATA_ACCESS)) {
				aflt->flt_prot = AFLT_PROT_ACCESS;
				otp->ot_trap |= OT_DATA_ACCESS;
				rp->r_pc = otp->ot_trampoline;
				rp->r_npc = rp->r_pc + 4;
				action = ACTION_TRAMPOLINE;
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
			action = ACTION_TRAMPOLINE;
		}
	}

	/*
	 * Determine if this error needs to be treated as fatal.  Note that
	 * multiple errors detected upon entry to this trap handler does not
	 * necessarily warrant a panic.  We only want to panic if the trap
	 * happened in privileged mode and not under t_ontrap or t_lofault
	 * protection.  The exception is WP: if we *only* get WP, it is not
	 * fatal even if the trap occurred in privileged mode, except on Sabre.
	 *
	 * aft_panic, if set, effectively makes us treat usermode
	 * UE/EDP/LDP faults as if they were privileged - so we we will
	 * panic instead of sending a contract event.  A lofault-protected
	 * fault will normally follow the contract event; if aft_panic is
	 * set this will be changed to a panic.
	 *
	 * For usermode BERR/BTO errors, eg from processes performing device
	 * control through mapped device memory, we need only deliver
	 * a SIGBUS to the offending process.
	 *
	 * Some additional flt_panic reasons (eg, WP on Sabre) will be
	 * checked later; for now we implement the common reasons.
	 */
	if (aflt->flt_prot == AFLT_PROT_NONE) {
		/*
		 * Beware - multiple bits may be set in AFSR
		 */
		if (t_afsr & (P_AFSR_UE | P_AFSR_LDP | P_AFSR_EDP)) {
			if (aflt->flt_priv || aft_panic)
				aflt->flt_panic = 1;
		}

		if (t_afsr & (P_AFSR_TO | P_AFSR_BERR)) {
			if (aflt->flt_priv)
				aflt->flt_panic = 1;
		}
	} else if (aflt->flt_prot == AFLT_PROT_COPY && aft_panic) {
		aflt->flt_panic = 1;
	}

	/*
	 * UE/BERR/TO: Call our bus nexus friends to check for
	 * IO errors that may have resulted in this trap.
	 */
	if (t_afsr & (P_AFSR_TO | P_AFSR_BERR | P_AFSR_UE)) {
		cpu_run_bus_error_handlers(aflt, expected);
	}

	/*
	 * Handle UE: If the UE is in memory, we need to flush the bad line from
	 * the E-cache.  We also need to query the bus nexus for fatal errors.
	 * For sabre, we will panic on UEs. Attempts to do diagnostic read on
	 * caches may introduce more parity errors (especially when the module
	 * is bad) and in sabre there is no guarantee that such errors
	 * (if introduced) are written back as poisoned data.
	 */
	if (t_afsr & P_AFSR_UE) {
		int i;

		(void) strcat(pr_reason, "UE ");

		spf_flt.flt_type = CPU_UE_ERR;
		aflt->flt_in_memory = (pf_is_memory(aflt->flt_addr >>
		    MMU_PAGESHIFT)) ? 1: 0;

		/*
		 * With UE, we have the PA of the fault.
		 * Let do a diagnostic read to get the ecache
		 * data and tag info of the bad line for logging.
		 */
		if (aflt->flt_in_memory) {
			uint32_t ec_set_size;
			uchar_t state;
			uint32_t ecache_idx;
			uint64_t faultpa = P2ALIGN(aflt->flt_addr, 64);

			/* touch the line to put it in ecache */
			acc_afsr |= read_and_clear_afsr();
			(void) lddphys(faultpa);
			acc_afsr |= (read_and_clear_afsr() &
			    ~(P_AFSR_EDP | P_AFSR_UE));

			ec_set_size = cpunodes[CPU->cpu_id].ecache_size /
			    ecache_associativity;

			for (i = 0; i < ecache_associativity; i++) {
				ecache_idx = i * ec_set_size +
				    (aflt->flt_addr % ec_set_size);
				get_ecache_dtag(P2ALIGN(ecache_idx, 64),
				    (uint64_t *)&spf_flt.flt_ec_data[0],
				    &spf_flt.flt_ec_tag, &oafsr, &acc_afsr);
				acc_afsr |= oafsr;

				state = (uchar_t)((spf_flt.flt_ec_tag &
				    cpu_ec_state_mask) >> cpu_ec_state_shift);

				if ((state & cpu_ec_state_valid) &&
				    ((spf_flt.flt_ec_tag & cpu_ec_tag_mask) ==
				    ((uint64_t)aflt->flt_addr >>
				    cpu_ec_tag_shift)))
					break;
			}

			/*
			 * Check to see if the ecache tag is valid for the
			 * fault PA. In the very unlikely event where the
			 * line could be victimized, no ecache info will be
			 * available. If this is the case, capture the line
			 * from memory instead.
			 */
			if ((state & cpu_ec_state_valid) == 0 ||
			    (spf_flt.flt_ec_tag & cpu_ec_tag_mask) !=
			    ((uint64_t)aflt->flt_addr >> cpu_ec_tag_shift)) {
				for (i = 0; i < 8; i++, faultpa += 8) {
					ec_data_t *ecdptr;

					ecdptr = &spf_flt.flt_ec_data[i];
					acc_afsr |= read_and_clear_afsr();
					ecdptr->ec_d8 = lddphys(faultpa);
					acc_afsr |= (read_and_clear_afsr() &
					    ~(P_AFSR_EDP | P_AFSR_UE));
					ecdptr->ec_afsr = 0;
							/* null afsr value */
				}

				/*
				 * Mark tag invalid to indicate mem dump
				 * when we print out the info.
				 */
				spf_flt.flt_ec_tag = AFLT_INV_ADDR;
			}
			spf_flt.flt_ec_lcnt = 1;

			/*
			 * Flush out the bad line
			 */
			flushecacheline(P2ALIGN(aflt->flt_addr, 64),
			    cpunodes[CPU->cpu_id].ecache_size);

			acc_afsr |= clear_errors(NULL, NULL);
		}

		/*
		 * Ask our bus nexus friends if they have any fatal errors. If
		 * so, they will log appropriate error messages and panic as a
		 * result. We then queue an event for each UDB that reports a
		 * UE. Each UE reported in a UDB will have its own log message.
		 *
		 * Note from kbn: In the case where there are multiple UEs
		 * (ME bit is set) - the AFAR address is only accurate to
		 * the 16-byte granularity. One cannot tell whether the AFAR
		 * belongs to the UDBH or UDBL syndromes. In this case, we
		 * always report the AFAR address to be 16-byte aligned.
		 *
		 * If we're on a Sabre, there is no SDBL, but it will always
		 * read as zero, so the sdbl test below will safely fail.
		 */
		if (bus_func_invoke(BF_TYPE_UE) == BF_FATAL || isus2i || isus2e)
			aflt->flt_panic = 1;

		if (sdbh & P_DER_UE) {
			aflt->flt_synd = sdbh & P_DER_E_SYND;
			cpu_errorq_dispatch(FM_EREPORT_CPU_USII_UE,
			    (void *)&spf_flt, sizeof (spf_flt), ue_queue,
			    aflt->flt_panic);
		}
		if (sdbl & P_DER_UE) {
			aflt->flt_synd = sdbl & P_DER_E_SYND;
			aflt->flt_synd |= UDBL_REG;	/* indicates UDBL */
			if (!(aflt->flt_stat & P_AFSR_ME))
				aflt->flt_addr |= 0x8;
			cpu_errorq_dispatch(FM_EREPORT_CPU_USII_UE,
			    (void *)&spf_flt, sizeof (spf_flt), ue_queue,
			    aflt->flt_panic);
		}

		/*
		 * We got a UE and are panicking, save the fault PA in a known
		 * location so that the platform specific panic code can check
		 * for copyback errors.
		 */
		if (aflt->flt_panic && aflt->flt_in_memory) {
			panic_aflt = *aflt;
		}
	}

	/*
	 * Handle EDP and LDP: Locate the line with bad parity and enqueue an
	 * async error for logging. For Sabre, we panic on EDP or LDP.
	 */
	if (t_afsr & (P_AFSR_EDP | P_AFSR_LDP)) {
		spf_flt.flt_type = CPU_EDP_LDP_ERR;

		if (t_afsr & P_AFSR_EDP)
			(void) strcat(pr_reason, "EDP ");

		if (t_afsr & P_AFSR_LDP)
			(void) strcat(pr_reason, "LDP ");

		/*
		 * Here we have no PA to work with.
		 * Scan each line in the ecache to look for
		 * the one with bad parity.
		 */
		aflt->flt_addr = AFLT_INV_ADDR;
		scan_ecache(&aflt->flt_addr, &spf_flt.flt_ec_data[0],
		    &spf_flt.flt_ec_tag, &spf_flt.flt_ec_lcnt, &oafsr);
		acc_afsr |= (oafsr & ~P_AFSR_WP);

		/*
		 * If we found a bad PA, update the state to indicate if it is
		 * memory or I/O space.  This code will be important if we ever
		 * support cacheable frame buffers.
		 */
		if (aflt->flt_addr != AFLT_INV_ADDR) {
			aflt->flt_in_memory = (pf_is_memory(aflt->flt_addr >>
			    MMU_PAGESHIFT)) ? 1 : 0;
		}

		if (isus2i || isus2e)
			aflt->flt_panic = 1;

		cpu_errorq_dispatch((t_afsr & P_AFSR_EDP) ?
		    FM_EREPORT_CPU_USII_EDP : FM_EREPORT_CPU_USII_LDP,
		    (void *)&spf_flt, sizeof (spf_flt), ue_queue,
		    aflt->flt_panic);
	}

	/*
	 * Timeout and bus error handling.  There are two cases to consider:
	 *
	 * (1) If we are in the kernel protected by ddi_peek or ddi_poke,we
	 * have already modified the saved registers so that we will return
	 * from the trap to the appropriate trampoline routine; otherwise panic.
	 *
	 * (2) In user mode, we can simply use our AST mechanism to deliver
	 * a SIGBUS.  We do not log the occurence - processes performing
	 * device control would generate lots of uninteresting messages.
	 */
	if (t_afsr & (P_AFSR_TO | P_AFSR_BERR)) {
		if (t_afsr & P_AFSR_TO)
			(void) strcat(pr_reason, "BTO ");

		if (t_afsr & P_AFSR_BERR)
			(void) strcat(pr_reason, "BERR ");

		spf_flt.flt_type = CPU_BTO_BERR_ERR;
		if (aflt->flt_priv && aflt->flt_prot == AFLT_PROT_NONE) {
			cpu_errorq_dispatch((t_afsr & P_AFSR_TO) ?
			    FM_EREPORT_CPU_USII_TO : FM_EREPORT_CPU_USII_BERR,
			    (void *)&spf_flt, sizeof (spf_flt), ue_queue,
			    aflt->flt_panic);
		}
	}

	/*
	 * Handle WP: WP happens when the ecache is victimized and a parity
	 * error was detected on a writeback.  The data in question will be
	 * poisoned as a UE will be written back.  The PA is not logged and
	 * it is possible that it doesn't belong to the trapped thread.  The
	 * WP trap is not fatal, but it could be fatal to someone that
	 * subsequently accesses the toxic page.  We set read_all_memscrub
	 * to force the memscrubber to read all of memory when it awakens.
	 * For Sabre/Hummingbird, WP is fatal because the HW doesn't write a
	 * UE back to poison the data.
	 */
	if (t_afsr & P_AFSR_WP) {
		(void) strcat(pr_reason, "WP ");
		if (isus2i || isus2e) {
			aflt->flt_panic = 1;
		} else {
			read_all_memscrub = 1;
		}
		spf_flt.flt_type = CPU_WP_ERR;
		cpu_errorq_dispatch(FM_EREPORT_CPU_USII_WP,
		    (void *)&spf_flt, sizeof (spf_flt), ue_queue,
		    aflt->flt_panic);
	}

	/*
	 * Handle trapping CP error: In Sabre/Hummingbird, parity error in
	 * the ecache on a copyout due to a PCI DMA read is signaled as a CP.
	 * This is fatal.
	 */

	if (t_afsr & P_AFSR_CP) {
		if (isus2i || isus2e) {
			(void) strcat(pr_reason, "CP ");
			aflt->flt_panic = 1;
			spf_flt.flt_type = CPU_TRAPPING_CP_ERR;
			cpu_errorq_dispatch(FM_EREPORT_CPU_USII_CP,
			    (void *)&spf_flt, sizeof (spf_flt), ue_queue,
			    aflt->flt_panic);
		} else {
			/*
			 * Orphan CP: Happens due to signal integrity problem
			 * on a CPU, where a CP is reported, without reporting
			 * its associated UE. This is handled by locating the
			 * bad parity line and would kick off the memscrubber
			 * to find the UE if in memory or in another's cache.
			 */
			spf_flt.flt_type = CPU_ORPHAN_CP_ERR;
			(void) strcat(pr_reason, "ORPHAN_CP ");

			/*
			 * Here we have no PA to work with.
			 * Scan each line in the ecache to look for
			 * the one with bad parity.
			 */
			aflt->flt_addr = AFLT_INV_ADDR;
			scan_ecache(&aflt->flt_addr, &spf_flt.flt_ec_data[0],
			    &spf_flt.flt_ec_tag, &spf_flt.flt_ec_lcnt,
			    &oafsr);
			acc_afsr |= oafsr;

			/*
			 * If we found a bad PA, update the state to indicate
			 * if it is memory or I/O space.
			 */
			if (aflt->flt_addr != AFLT_INV_ADDR) {
				aflt->flt_in_memory =
				    (pf_is_memory(aflt->flt_addr >>
				    MMU_PAGESHIFT)) ? 1 : 0;
			}
			read_all_memscrub = 1;
			cpu_errorq_dispatch(FM_EREPORT_CPU_USII_CP,
			    (void *)&spf_flt, sizeof (spf_flt), ue_queue,
			    aflt->flt_panic);

		}
	}

	/*
	 * If we queued an error other than WP or CP and we are going to return
	 * from the trap and the error was in user mode or inside of a
	 * copy routine, set AST flag so the queue will be drained before
	 * returning to user mode.
	 *
	 * For UE/LDP/EDP, the AST processing will SIGKILL the process
	 * and send an event to its process contract.
	 *
	 * For BERR/BTO, the AST processing will SIGBUS the process.  There
	 * will have been no error queued in this case.
	 */
	if ((t_afsr &
	    (P_AFSR_UE | P_AFSR_LDP | P_AFSR_EDP | P_AFSR_BERR | P_AFSR_TO)) &&
	    (!aflt->flt_priv || aflt->flt_prot == AFLT_PROT_COPY)) {
			int pcb_flag = 0;

			if (t_afsr & (P_AFSR_UE | P_AFSR_LDP | P_AFSR_EDP))
				pcb_flag |= ASYNC_HWERR;

			if (t_afsr & P_AFSR_BERR)
				pcb_flag |= ASYNC_BERR;

			if (t_afsr & P_AFSR_TO)
				pcb_flag |= ASYNC_BTO;

			ttolwp(curthread)->lwp_pcb.pcb_flags |= pcb_flag;
			aston(curthread);
			action = ACTION_AST_FLAGS;
	}

	/*
	 * In response to a deferred error, we must do one of three things:
	 * (1) set the AST flags, (2) trampoline, or (3) panic.  action is
	 * set in cases (1) and (2) - check that either action is set or
	 * (3) is true.
	 *
	 * On II, the WP writes poisoned data back to memory, which will
	 * cause a UE and a panic or reboot when read.  In this case, we
	 * don't need to panic at this time.  On IIi and IIe,
	 * aflt->flt_panic is already set above.
	 */
	ASSERT((aflt->flt_panic != 0) || (action != ACTION_NONE) ||
	    (t_afsr & P_AFSR_WP));

	/*
	 * Make a final sanity check to make sure we did not get any more async
	 * errors and accumulate the afsr.
	 */
	flush_ecache(ecache_flushaddr, cpunodes[CPU->cpu_id].ecache_size * 2,
	    cpunodes[CPU->cpu_id].ecache_linesize);
	(void) clear_errors(&spf_flt, NULL);

	/*
	 * Take care of a special case: If there is a UE in the ecache flush
	 * area, we'll see it in flush_ecache().  This will trigger the
	 * CPU_ADDITIONAL_ERRORS case below.
	 *
	 * This could occur if the original error was a UE in the flush area,
	 * or if the original error was an E$ error that was flushed out of
	 * the E$ in scan_ecache().
	 *
	 * If it's at the same address that we're already logging, then it's
	 * probably one of these cases.  Clear the bit so we don't trip over
	 * it on the additional errors case, which could cause an unnecessary
	 * panic.
	 */
	if ((aflt->flt_stat & P_AFSR_UE) && aflt->flt_addr == t_afar)
		acc_afsr |= aflt->flt_stat & ~P_AFSR_UE;
	else
		acc_afsr |= aflt->flt_stat;

	/*
	 * Check the acumulated afsr for the important bits.
	 * Make sure the spf_flt.flt_type value is set, and
	 * enque an error.
	 */
	if (acc_afsr &
	    (P_AFSR_LEVEL1 | P_AFSR_IVUE | P_AFSR_ETP | P_AFSR_ISAP)) {
		if (acc_afsr & (P_AFSR_UE | P_AFSR_EDP | P_AFSR_LDP |
		    P_AFSR_BERR | P_AFSR_TO | P_AFSR_IVUE | P_AFSR_ETP |
		    P_AFSR_ISAP))
			aflt->flt_panic = 1;

		spf_flt.flt_type = CPU_ADDITIONAL_ERR;
		aflt->flt_stat = acc_afsr;
		cpu_errorq_dispatch(FM_EREPORT_CPU_USII_UNKNOWN,
		    (void *)&spf_flt, sizeof (spf_flt), ue_queue,
		    aflt->flt_panic);
	}

	/*
	 * If aflt->flt_panic is set at this point, we need to panic as the
	 * result of a trap at TL > 0, or an error we determined to be fatal.
	 * We've already enqueued the error in one of the if-clauses above,
	 * and it will be dequeued and logged as part of the panic flow.
	 */
	if (aflt->flt_panic) {
		cpu_aflt_log(CE_PANIC, 1, &spf_flt, CPU_ERRID_FIRST,
		    "See previous message(s) for details", " %sError(s)",
		    pr_reason);
	}

	/*
	 * Before returning, we must re-enable errors, and
	 * reset the caches to their boot-up state.
	 */
	set_lsu(get_lsu() | cache_boot_state);
	set_error_enable(EER_ENABLE);
}

/*
 * Check for miscellaneous fatal errors and call CE_PANIC if any are seen.
 * This routine is shared by the CE and UE handling code.
 */
static void
check_misc_err(spitf_async_flt *spf_flt)
{
	struct async_flt *aflt = (struct async_flt *)spf_flt;
	char *fatal_str = NULL;

	/*
	 * The ISAP and ETP errors are supposed to cause a POR
	 * from the system, so in theory we never, ever see these messages.
	 * ISAP, ETP and IVUE are considered to be fatal.
	 */
	if (aflt->flt_stat & P_AFSR_ISAP)
		fatal_str = " System Address Parity Error on";
	else if (aflt->flt_stat & P_AFSR_ETP)
		fatal_str = " Ecache Tag Parity Error on";
	else if (aflt->flt_stat & P_AFSR_IVUE)
		fatal_str = " Interrupt Vector Uncorrectable Error on";
	if (fatal_str != NULL) {
		cpu_aflt_log(CE_PANIC, 1, spf_flt, CMN_LFLAGS,
		    NULL, fatal_str);
	}
}

/*
 * Routine to convert a syndrome into a syndrome code.
 */
static int
synd_to_synd_code(int synd_status, ushort_t synd)
{
	if (synd_status != AFLT_STAT_VALID)
		return (-1);

	/*
	 * Use the 8-bit syndrome to index the ecc_syndrome_tab
	 * to get the code indicating which bit(s) is(are) bad.
	 */
	if ((synd == 0) || (synd >= SYND_TBL_SIZE))
		return (-1);
	else
		return (ecc_syndrome_tab[synd]);
}

/* ARGSUSED */
int
cpu_get_mem_sid(char *unum, char *buf, int buflen, int *lenp)
{
	return (ENOTSUP);
}

/* ARGSUSED */
int
cpu_get_mem_offset(uint64_t flt_addr, uint64_t *offp)
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
 * Routine to return a string identifying the physical name
 * associated with a memory/cache error.
 */
/* ARGSUSED */
int
cpu_get_mem_unum(int synd_status, ushort_t synd, uint64_t afsr,
    uint64_t afar, int cpuid, int flt_in_memory, ushort_t flt_status,
    char *buf, int buflen, int *lenp)
{
	short synd_code;
	int ret;

	if (flt_in_memory) {
		synd_code = synd_to_synd_code(synd_status, synd);
		if (synd_code == -1) {
			ret = EINVAL;
		} else if (prom_get_unum(synd_code, P2ALIGN(afar, 8),
		    buf, buflen, lenp) != 0) {
			ret = EIO;
		} else if (*lenp <= 1) {
			ret = EINVAL;
		} else {
			ret = 0;
		}
	} else {
		ret = ENOTSUP;
	}

	if (ret != 0) {
		buf[0] = '\0';
		*lenp = 0;
	}

	return (ret);
}

/*
 * Wrapper for cpu_get_mem_unum() routine that takes an
 * async_flt struct rather than explicit arguments.
 */
int
cpu_get_mem_unum_aflt(int synd_status, struct async_flt *aflt,
    char *buf, int buflen, int *lenp)
{
	return (cpu_get_mem_unum(synd_status, SYND(aflt->flt_synd),
	    aflt->flt_stat, aflt->flt_addr, aflt->flt_bus_id,
	    aflt->flt_in_memory, aflt->flt_status, buf, buflen, lenp));
}

/*
 * This routine is a more generic interface to cpu_get_mem_unum(),
 * that may be used by other modules (e.g. mm).
 */
int
cpu_get_mem_name(uint64_t synd, uint64_t *afsr, uint64_t afar,
		char *buf, int buflen, int *lenp)
{
	int synd_status, flt_in_memory, ret;
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

	flt_in_memory = (pf_is_memory(afar >> MMU_PAGESHIFT)) ? 1 : 0;

	if ((ret = cpu_get_mem_unum(synd_status, (ushort_t)synd, *afsr, afar,
	    CPU->cpu_id, flt_in_memory, 0, unum, UNUM_NAMLEN, lenp))
	    != 0)
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
/* ARGSUSED */
int
cpu_get_mem_info(uint64_t synd, uint64_t afar,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp)
{
	return (ENOTSUP);
}

/*
 * Routine to return a string identifying the physical
 * name associated with a cpuid.
 */
/* ARGSUSED */
int
cpu_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
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
 * Cpu specific log func for UEs.
 */
static void
log_ue_err(struct async_flt *aflt, char *unum)
{
	spitf_async_flt *spf_flt = (spitf_async_flt *)aflt;
	int len = 0;

#ifdef DEBUG
	int afsr_priv = (aflt->flt_stat & P_AFSR_PRIV) ? 1 : 0;

	/*
	 * Paranoid Check for priv mismatch
	 * Only applicable for UEs
	 */
	if (afsr_priv != aflt->flt_priv) {
		/*
		 * The priv bits in %tstate and %afsr did not match; we expect
		 * this to be very rare, so flag it with a message.
		 */
		cpu_aflt_log(CE_WARN, 2, spf_flt, CPU_ERRID_FIRST, NULL,
		    ": PRIV bit in TSTATE and AFSR mismatched; "
		    "TSTATE.PRIV=%d used", (aflt->flt_priv) ? 1 : 0);

		/* update saved afsr to reflect the correct priv */
		aflt->flt_stat &= ~P_AFSR_PRIV;
		if (aflt->flt_priv)
			aflt->flt_stat |= P_AFSR_PRIV;
	}
#endif /* DEBUG */

	(void) cpu_get_mem_unum_aflt(AFLT_STAT_VALID, aflt, unum,
	    UNUM_NAMLEN, &len);

	cpu_aflt_log(CE_WARN, 1, spf_flt, UE_LFLAGS, unum,
	    " Uncorrectable Memory Error on");

	if (SYND(aflt->flt_synd) == 0x3) {
		cpu_aflt_log(CE_WARN, 1, spf_flt, CPU_ERRID_FIRST, NULL,
		    " Syndrome 0x3 indicates that this may not be a "
		    "memory module problem");
	}

	if (aflt->flt_in_memory)
		cpu_log_ecmem_info(spf_flt);
}


/*
 * The cpu_async_log_err() function is called via the ue_drain() function to
 * handle logging for CPU events that are dequeued.  As such, it can be invoked
 * from softint context, from AST processing in the trap() flow, or from the
 * panic flow.  We decode the CPU-specific data, and log appropriate messages.
 */
static void
cpu_async_log_err(void *flt)
{
	spitf_async_flt *spf_flt = (spitf_async_flt *)flt;
	struct async_flt *aflt = (struct async_flt *)flt;
	char unum[UNUM_NAMLEN];
	char *space;
	char *ecache_scrub_logstr = NULL;

	switch (spf_flt->flt_type) {
	case CPU_UE_ERR:
		/*
		 * We want to skip logging only if ALL the following
		 * conditions are true:
		 *
		 *	1. We are not panicking
		 *	2. There is only one error
		 *	3. That error is a memory error
		 *	4. The error is caused by the memory scrubber (in
		 *	   which case the error will have occurred under
		 *	   on_trap protection)
		 *	5. The error is on a retired page
		 *
		 * Note 1: AFLT_PROT_EC is used places other than the memory
		 * scrubber.  However, none of those errors should occur
		 * on a retired page.
		 *
		 * Note 2: In the CE case, these errors are discarded before
		 * the errorq.  In the UE case, we must wait until now --
		 * softcall() grabs a mutex, which we can't do at a high PIL.
		 */
		if (!panicstr &&
		    (aflt->flt_stat & S_AFSR_ALL_ERRS) == P_AFSR_UE &&
		    aflt->flt_prot == AFLT_PROT_EC) {
			if (page_retire_check(aflt->flt_addr, NULL) == 0) {
				/* Zero the address to clear the error */
				softcall(ecc_page_zero, (void *)aflt->flt_addr);
				return;
			}
		}

		/*
		 * Log the UE and check for causes of this UE error that
		 * don't cause a trap (Copyback error).  cpu_async_error()
		 * has already checked the i/o buses for us.
		 */
		log_ue_err(aflt, unum);
		if (aflt->flt_in_memory)
			cpu_check_allcpus(aflt);
		break;

	case CPU_EDP_LDP_ERR:
		if (aflt->flt_stat & P_AFSR_EDP)
			cpu_aflt_log(CE_WARN, 1, spf_flt, PARERR_LFLAGS,
			    NULL, " EDP event on");

		if (aflt->flt_stat & P_AFSR_LDP)
			cpu_aflt_log(CE_WARN, 1, spf_flt, PARERR_LFLAGS,
			    NULL, " LDP event on");

		/* Log ecache info if exist */
		if (spf_flt->flt_ec_lcnt > 0) {
			cpu_log_ecmem_info(spf_flt);

			cpu_aflt_log(CE_CONT, 2, spf_flt, CPU_ERRID_FIRST,
			    NULL, " AFAR was derived from E$Tag");
		} else {
			cpu_aflt_log(CE_CONT, 2, spf_flt, CPU_ERRID_FIRST,
			    NULL, " No error found in ecache (No fault "
			    "PA available)");
		}
		break;

	case CPU_WP_ERR:
		/*
		 * If the memscrub thread hasn't yet read
		 * all of memory, as we requested in the
		 * trap handler, then give it a kick to
		 * make sure it does.
		 */
		if (!isus2i && !isus2e && read_all_memscrub)
			memscrub_run();

		cpu_aflt_log(CE_WARN, 1, spf_flt, WP_LFLAGS, NULL,
		    " WP event on");
		return;

	case CPU_BTO_BERR_ERR:
		/*
		 * A bus timeout or error occurred that was in user mode or not
		 * in a protected kernel code region.
		 */
		if (aflt->flt_stat & P_AFSR_BERR) {
			cpu_aflt_log(CE_WARN, aflt->flt_panic ? 1 : 2,
			    spf_flt, BERRTO_LFLAGS, NULL,
			    " Bus Error on System Bus in %s mode from",
			    aflt->flt_priv ? "privileged" : "user");
		}

		if (aflt->flt_stat & P_AFSR_TO) {
			cpu_aflt_log(CE_WARN, aflt->flt_panic ? 1 : 2,
			    spf_flt, BERRTO_LFLAGS, NULL,
			    " Timeout on System Bus in %s mode from",
			    aflt->flt_priv ? "privileged" : "user");
		}

		return;

	case CPU_PANIC_CP_ERR:
		/*
		 * Process the Copyback (CP) error info (if any) obtained from
		 * polling all the cpus in the panic flow. This case is only
		 * entered if we are panicking.
		 */
		ASSERT(panicstr != NULL);
		ASSERT(aflt->flt_id == panic_aflt.flt_id);

		/* See which space - this info may not exist */
		if (panic_aflt.flt_status & ECC_D_TRAP)
			space = "Data ";
		else if (panic_aflt.flt_status & ECC_I_TRAP)
			space = "Instruction ";
		else
			space = "";

		cpu_aflt_log(CE_WARN, 1, spf_flt, CP_LFLAGS, NULL,
		    " AFAR was derived from UE report,"
		    " CP event on CPU%d (caused %saccess error on %s%d)",
		    aflt->flt_inst, space, (panic_aflt.flt_status & ECC_IOBUS) ?
		    "IOBUS" : "CPU", panic_aflt.flt_bus_id);

		if (spf_flt->flt_ec_lcnt > 0)
			cpu_log_ecmem_info(spf_flt);
		else
			cpu_aflt_log(CE_WARN, 2, spf_flt, CPU_ERRID_FIRST,
			    NULL, " No cache dump available");

		return;

	case CPU_TRAPPING_CP_ERR:
		/*
		 * For sabre only.  This is a copyback ecache parity error due
		 * to a PCI DMA read.  We should be panicking if we get here.
		 */
		ASSERT(panicstr != NULL);
		cpu_aflt_log(CE_WARN, 1, spf_flt, CP_LFLAGS, NULL,
		    " AFAR was derived from UE report,"
		    " CP event on CPU%d (caused Data access error "
		    "on PCIBus)", aflt->flt_inst);
		return;

		/*
		 * We log the ecache lines of the following states,
		 * clean_bad_idle, clean_bad_busy, dirty_bad_idle and
		 * dirty_bad_busy if ecache_scrub_verbose is set and panic
		 * in addition to logging if ecache_scrub_panic is set.
		 */
	case CPU_BADLINE_CI_ERR:
		ecache_scrub_logstr = "CBI";
		/* FALLTHRU */

	case CPU_BADLINE_CB_ERR:
		if (ecache_scrub_logstr == NULL)
			ecache_scrub_logstr = "CBB";
		/* FALLTHRU */

	case CPU_BADLINE_DI_ERR:
		if (ecache_scrub_logstr == NULL)
			ecache_scrub_logstr = "DBI";
		/* FALLTHRU */

	case CPU_BADLINE_DB_ERR:
		if (ecache_scrub_logstr == NULL)
			ecache_scrub_logstr = "DBB";

		cpu_aflt_log(CE_NOTE, 2, spf_flt,
		    (CPU_ERRID_FIRST | CPU_FLTCPU), NULL,
		    " %s event on", ecache_scrub_logstr);
		cpu_log_ecmem_info(spf_flt);

		return;

	case CPU_ORPHAN_CP_ERR:
		/*
		 * Orphan CPs, where the CP bit is set, but when a CPU
		 * doesn't report a UE.
		 */
		if (read_all_memscrub)
			memscrub_run();

		cpu_aflt_log(CE_NOTE, 2, spf_flt, (CP_LFLAGS | CPU_FLTCPU),
		    NULL, " Orphan CP event on");

		/* Log ecache info if exist */
		if (spf_flt->flt_ec_lcnt > 0)
			cpu_log_ecmem_info(spf_flt);
		else
			cpu_aflt_log(CE_NOTE, 2, spf_flt,
			    (CP_LFLAGS | CPU_FLTCPU), NULL,
			    " No error found in ecache (No fault "
			    "PA available");
		return;

	case CPU_ECACHE_ADDR_PAR_ERR:
		cpu_aflt_log(CE_WARN, 1, spf_flt, PARERR_LFLAGS, NULL,
		    " E$ Tag Address Parity error on");
		cpu_log_ecmem_info(spf_flt);
		return;

	case CPU_ECACHE_STATE_ERR:
		cpu_aflt_log(CE_WARN, 1, spf_flt, PARERR_LFLAGS, NULL,
		    " E$ Tag State Parity error on");
		cpu_log_ecmem_info(spf_flt);
		return;

	case CPU_ECACHE_TAG_ERR:
		cpu_aflt_log(CE_WARN, 1, spf_flt, PARERR_LFLAGS, NULL,
		    " E$ Tag scrub event on");
		cpu_log_ecmem_info(spf_flt);
		return;

	case CPU_ECACHE_ETP_ETS_ERR:
		cpu_aflt_log(CE_WARN, 1, spf_flt, PARERR_LFLAGS, NULL,
		    " AFSR.ETP is set and AFSR.ETS is zero on");
		cpu_log_ecmem_info(spf_flt);
		return;


	case CPU_ADDITIONAL_ERR:
		cpu_aflt_log(CE_WARN, 1, spf_flt, CMN_LFLAGS & ~CPU_SPACE, NULL,
		    " Additional errors detected during error processing on");
		return;

	default:
		cmn_err(CE_WARN, "cpu_async_log_err: fault %p has unknown "
		    "fault type %x", (void *)spf_flt, spf_flt->flt_type);
		return;
	}

	/* ... fall through from the UE, EDP, or LDP cases */

	if (aflt->flt_addr != AFLT_INV_ADDR && aflt->flt_in_memory) {
		if (!panicstr) {
			(void) page_retire(aflt->flt_addr, PR_UE);
		} else {
			/*
			 * Clear UEs on panic so that we don't
			 * get haunted by them during panic or
			 * after reboot
			 */
			clearphys(P2ALIGN(aflt->flt_addr, 64),
			    cpunodes[CPU->cpu_id].ecache_size,
			    cpunodes[CPU->cpu_id].ecache_linesize);

			(void) clear_errors(NULL, NULL);
		}
	}

	/*
	 * Log final recover message
	 */
	if (!panicstr) {
		if (!aflt->flt_priv) {
			cpu_aflt_log(CE_CONT, 3, spf_flt, CPU_ERRID_FIRST,
			    NULL, " Above Error is in User Mode"
			    "\n    and is fatal: "
			    "will SIGKILL process and notify contract");
		} else if (aflt->flt_prot == AFLT_PROT_COPY && aflt->flt_core) {
			cpu_aflt_log(CE_CONT, 3, spf_flt, CPU_ERRID_FIRST,
			    NULL, " Above Error detected while dumping core;"
			    "\n    core file will be truncated");
		} else if (aflt->flt_prot == AFLT_PROT_COPY) {
			cpu_aflt_log(CE_CONT, 3, spf_flt, CPU_ERRID_FIRST,
			    NULL, " Above Error is due to Kernel access"
			    "\n    to User space and is fatal: "
			    "will SIGKILL process and notify contract");
		} else if (aflt->flt_prot == AFLT_PROT_EC) {
			cpu_aflt_log(CE_CONT, 3, spf_flt, CPU_ERRID_FIRST, NULL,
			    " Above Error detected by protected Kernel code"
			    "\n    that will try to clear error from system");
		}
	}
}


/*
 * Check all cpus for non-trapping UE-causing errors
 * In Ultra I/II, we look for copyback errors (CPs)
 */
void
cpu_check_allcpus(struct async_flt *aflt)
{
	spitf_async_flt cp;
	spitf_async_flt *spf_cpflt = &cp;
	struct async_flt *cpflt = (struct async_flt *)&cp;
	int pix;

	cpflt->flt_id = aflt->flt_id;
	cpflt->flt_addr = aflt->flt_addr;

	for (pix = 0; pix < NCPU; pix++) {
		if (CPU_XCALL_READY(pix)) {
			xc_one(pix, (xcfunc_t *)get_cpu_status,
			    (uint64_t)cpflt, 0);

			if (cpflt->flt_stat & P_AFSR_CP) {
				char *space;

				/* See which space - this info may not exist */
				if (aflt->flt_status & ECC_D_TRAP)
					space = "Data ";
				else if (aflt->flt_status & ECC_I_TRAP)
					space = "Instruction ";
				else
					space = "";

				cpu_aflt_log(CE_WARN, 1, spf_cpflt, CP_LFLAGS,
				    NULL, " AFAR was derived from UE report,"
				    " CP event on CPU%d (caused %saccess "
				    "error on %s%d)", pix, space,
				    (aflt->flt_status & ECC_IOBUS) ?
				    "IOBUS" : "CPU", aflt->flt_bus_id);

				if (spf_cpflt->flt_ec_lcnt > 0)
					cpu_log_ecmem_info(spf_cpflt);
				else
					cpu_aflt_log(CE_WARN, 2, spf_cpflt,
					    CPU_ERRID_FIRST, NULL,
					    " No cache dump available");
			}
		}
	}
}

#ifdef DEBUG
int test_mp_cp = 0;
#endif

/*
 * Cross-call callback routine to tell a CPU to read its own %afsr to check
 * for copyback errors and capture relevant information.
 */
static uint_t
get_cpu_status(uint64_t arg)
{
	struct async_flt *aflt = (struct async_flt *)arg;
	spitf_async_flt *spf_flt = (spitf_async_flt *)arg;
	uint64_t afsr;
	uint32_t ec_idx;
	uint64_t sdbh, sdbl;
	int i;
	uint32_t ec_set_size;
	uchar_t valid;
	ec_data_t ec_data[8];
	uint64_t ec_tag, flt_addr_tag, oafsr;
	uint64_t *acc_afsr = NULL;

	get_asyncflt(&afsr);
	if (CPU_PRIVATE(CPU) != NULL) {
		acc_afsr = CPU_PRIVATE_PTR(CPU, sfpr_scrub_afsr);
		afsr |= *acc_afsr;
		*acc_afsr = 0;
	}

#ifdef DEBUG
	if (test_mp_cp)
		afsr |= P_AFSR_CP;
#endif
	aflt->flt_stat = afsr;

	if (afsr & P_AFSR_CP) {
		/*
		 * Capture the UDBs
		 */
		get_udb_errors(&sdbh, &sdbl);
		spf_flt->flt_sdbh = (ushort_t)(sdbh & 0x3FF);
		spf_flt->flt_sdbl = (ushort_t)(sdbl & 0x3FF);

		/*
		 * Clear CP bit before capturing ecache data
		 * and AFSR info.
		 */
		set_asyncflt(P_AFSR_CP);

		/*
		 * See if we can capture the ecache line for the
		 * fault PA.
		 *
		 * Return a valid matching ecache line, if any.
		 * Otherwise, return the first matching ecache
		 * line marked invalid.
		 */
		flt_addr_tag = aflt->flt_addr >> cpu_ec_tag_shift;
		ec_set_size = cpunodes[CPU->cpu_id].ecache_size /
		    ecache_associativity;
		spf_flt->flt_ec_lcnt = 0;

		for (i = 0, ec_idx = (aflt->flt_addr % ec_set_size);
		    i < ecache_associativity; i++, ec_idx += ec_set_size) {
			get_ecache_dtag(P2ALIGN(ec_idx, 64),
			    (uint64_t *)&ec_data[0], &ec_tag, &oafsr,
			    acc_afsr);

			if ((ec_tag & cpu_ec_tag_mask) != flt_addr_tag)
				continue;

			valid = cpu_ec_state_valid &
			    (uchar_t)((ec_tag & cpu_ec_state_mask) >>
			    cpu_ec_state_shift);

			if (valid || spf_flt->flt_ec_lcnt == 0) {
				spf_flt->flt_ec_tag = ec_tag;
				bcopy(&ec_data, &spf_flt->flt_ec_data,
				    sizeof (ec_data));
				spf_flt->flt_ec_lcnt = 1;

				if (valid)
					break;
			}
		}
	}
	return (0);
}

/*
 * CPU-module callback for the non-panicking CPUs.  This routine is invoked
 * from panic_idle() as part of the other CPUs stopping themselves when a
 * panic occurs.  We need to be VERY careful what we do here, since panicstr
 * is NOT set yet and we cannot blow through locks.  If panic_aflt is set
 * (panic_aflt.flt_id is non-zero), we need to read our %afsr to look for
 * CP error information.
 */
void
cpu_async_panic_callb(void)
{
	spitf_async_flt cp;
	struct async_flt *aflt = (struct async_flt *)&cp;
	uint64_t *scrub_afsr;

	if (panic_aflt.flt_id != 0) {
		aflt->flt_addr = panic_aflt.flt_addr;
		(void) get_cpu_status((uint64_t)aflt);

		if (CPU_PRIVATE(CPU) != NULL) {
			scrub_afsr = CPU_PRIVATE_PTR(CPU, sfpr_scrub_afsr);
			if (*scrub_afsr & P_AFSR_CP) {
				aflt->flt_stat |= *scrub_afsr;
				*scrub_afsr = 0;
			}
		}
		if (aflt->flt_stat & P_AFSR_CP) {
			aflt->flt_id = panic_aflt.flt_id;
			aflt->flt_panic = 1;
			aflt->flt_inst = CPU->cpu_id;
			aflt->flt_class = CPU_FAULT;
			cp.flt_type = CPU_PANIC_CP_ERR;
			cpu_errorq_dispatch(FM_EREPORT_CPU_USII_CP,
			    (void *)&cp, sizeof (cp), ue_queue,
			    aflt->flt_panic);
		}
	}
}

/*
 * Turn off all cpu error detection, normally only used for panics.
 */
void
cpu_disable_errors(void)
{
	xt_all(set_error_enable_tl1, EER_DISABLE, EER_SET_ABSOLUTE);
}

/*
 * Enable errors.
 */
void
cpu_enable_errors(void)
{
	xt_all(set_error_enable_tl1, EER_ENABLE, EER_SET_ABSOLUTE);
}

static void
cpu_read_paddr(struct async_flt *ecc, short verbose, short ce_err)
{
	uint64_t aligned_addr = P2ALIGN(ecc->flt_addr, 8);
	int i, loop = 1;
	ushort_t ecc_0;
	uint64_t paddr;
	uint64_t data;

	if (verbose)
		loop = 8;
	for (i = 0; i < loop; i++) {
		paddr = aligned_addr + (i * 8);
		data = lddphys(paddr);
		if (verbose) {
			if (ce_err) {
				ecc_0 = ecc_gen((uint32_t)(data>>32),
				    (uint32_t)data);
				cpu_aflt_log(CE_CONT, 0, NULL, NO_LFLAGS,
				    NULL, "    Paddr 0x%" PRIx64 ", "
				    "Data 0x%08x.%08x, ECC 0x%x", paddr,
				    (uint32_t)(data>>32), (uint32_t)data,
				    ecc_0);
			} else {
				cpu_aflt_log(CE_CONT, 0, NULL, NO_LFLAGS,
				    NULL, "    Paddr 0x%" PRIx64 ", "
				    "Data 0x%08x.%08x", paddr,
				    (uint32_t)(data>>32), (uint32_t)data);
			}
		}
	}
}

static struct {		/* sec-ded-s4ed ecc code */
	uint_t hi, lo;
} ecc_code[8] = {
	{ 0xee55de23U, 0x16161161U },
	{ 0x55eede93U, 0x61612212U },
	{ 0xbb557b8cU, 0x49494494U },
	{ 0x55bb7b6cU, 0x94948848U },
	{ 0x16161161U, 0xee55de23U },
	{ 0x61612212U, 0x55eede93U },
	{ 0x49494494U, 0xbb557b8cU },
	{ 0x94948848U, 0x55bb7b6cU }
};

static ushort_t
ecc_gen(uint_t high_bytes, uint_t low_bytes)
{
	int i, j;
	uchar_t checker, bit_mask;
	struct {
		uint_t hi, lo;
	} hex_data, masked_data[8];

	hex_data.hi = high_bytes;
	hex_data.lo = low_bytes;

	/* mask out bits according to sec-ded-s4ed ecc code */
	for (i = 0; i < 8; i++) {
		masked_data[i].hi = hex_data.hi & ecc_code[i].hi;
		masked_data[i].lo = hex_data.lo & ecc_code[i].lo;
	}

	/*
	 * xor all bits in masked_data[i] to get bit_i of checker,
	 * where i = 0 to 7
	 */
	checker = 0;
	for (i = 0; i < 8; i++) {
		bit_mask = 1 << i;
		for (j = 0; j < 32; j++) {
			if (masked_data[i].lo & 1) checker ^= bit_mask;
			if (masked_data[i].hi & 1) checker ^= bit_mask;
			masked_data[i].hi >>= 1;
			masked_data[i].lo >>= 1;
		}
	}
	return (checker);
}

/*
 * Flush the entire ecache using displacement flush by reading through a
 * physical address range as large as the ecache.
 */
void
cpu_flush_ecache(void)
{
	flush_ecache(ecache_flushaddr, cpunodes[CPU->cpu_id].ecache_size * 2,
	    cpunodes[CPU->cpu_id].ecache_linesize);
}

/*
 * read and display the data in the cache line where the
 * original ce error occurred.
 * This routine is mainly used for debugging new hardware.
 */
void
read_ecc_data(struct async_flt *ecc, short verbose, short ce_err)
{
	kpreempt_disable();
	/* disable ECC error traps */
	set_error_enable(EER_ECC_DISABLE);

	/*
	 * flush the ecache
	 * read the data
	 * check to see if an ECC error occured
	 */
	flush_ecache(ecache_flushaddr, cpunodes[CPU->cpu_id].ecache_size * 2,
	    cpunodes[CPU->cpu_id].ecache_linesize);
	set_lsu(get_lsu() | cache_boot_state);
	cpu_read_paddr(ecc, verbose, ce_err);
	(void) check_ecc(ecc);

	/* enable ECC error traps */
	set_error_enable(EER_ENABLE);
	kpreempt_enable();
}

/*
 * Check the AFSR bits for UE/CE persistence.
 * If UE or CE errors are detected, the routine will
 * clears all the AFSR sticky bits (except CP for
 * spitfire/blackbird) and the UDBs.
 * if ce_debug or ue_debug is set, log any ue/ce errors detected.
 */
static int
check_ecc(struct async_flt *ecc)
{
	uint64_t t_afsr;
	uint64_t t_afar;
	uint64_t udbh;
	uint64_t udbl;
	ushort_t udb;
	int persistent = 0;

	/*
	 * Capture the AFSR, AFAR and UDBs info
	 */
	get_asyncflt(&t_afsr);
	get_asyncaddr(&t_afar);
	t_afar &= SABRE_AFAR_PA;
	get_udb_errors(&udbh, &udbl);

	if ((t_afsr & P_AFSR_UE) || (t_afsr & P_AFSR_CE)) {
		/*
		 * Clear the errors
		 */
		clr_datapath();

		if (isus2i || isus2e)
			set_asyncflt(t_afsr);
		else
			set_asyncflt(t_afsr & ~P_AFSR_CP);

		/*
		 * determine whether to check UDBH or UDBL for persistence
		 */
		if (ecc->flt_synd & UDBL_REG) {
			udb = (ushort_t)udbl;
			t_afar |= 0x8;
		} else {
			udb = (ushort_t)udbh;
		}

		if (ce_debug || ue_debug) {
			spitf_async_flt spf_flt; /* for logging */
			struct async_flt *aflt =
			    (struct async_flt *)&spf_flt;

			/* Package the info nicely in the spf_flt struct */
			bzero(&spf_flt, sizeof (spitf_async_flt));
			aflt->flt_stat = t_afsr;
			aflt->flt_addr = t_afar;
			spf_flt.flt_sdbh = (ushort_t)(udbh & 0x3FF);
			spf_flt.flt_sdbl = (ushort_t)(udbl & 0x3FF);

			cpu_aflt_log(CE_CONT, 0, &spf_flt, (CPU_AFSR |
			    CPU_AFAR | CPU_UDBH | CPU_UDBL), NULL,
			    " check_ecc: Dumping captured error states ...");
		}

		/*
		 * if the fault addresses don't match, not persistent
		 */
		if (t_afar != ecc->flt_addr) {
			return (persistent);
		}

		/*
		 * check for UE persistence
		 * since all DIMMs in the bank are identified for a UE,
		 * there's no reason to check the syndrome
		 */
		if ((ecc->flt_stat & P_AFSR_UE) && (t_afsr & P_AFSR_UE)) {
			persistent = 1;
		}

		/*
		 * check for CE persistence
		 */
		if ((ecc->flt_stat & P_AFSR_CE) && (t_afsr & P_AFSR_CE)) {
			if ((udb & P_DER_E_SYND) ==
			    (ecc->flt_synd & P_DER_E_SYND)) {
				persistent = 1;
			}
		}
	}
	return (persistent);
}

#ifdef HUMMINGBIRD
#define	HB_FULL_DIV		1
#define	HB_HALF_DIV		2
#define	HB_LOWEST_DIV		8
#define	HB_ECLK_INVALID		0xdeadbad
static uint64_t hb_eclk[HB_LOWEST_DIV + 1] = {
	HB_ECLK_INVALID, HB_ECLK_1, HB_ECLK_2, HB_ECLK_INVALID,
	HB_ECLK_4, HB_ECLK_INVALID, HB_ECLK_6, HB_ECLK_INVALID,
	HB_ECLK_8 };

#define	HB_SLOW_DOWN		0
#define	HB_SPEED_UP		1

#define	SET_ESTAR_MODE(mode)					\
	stdphysio(HB_ESTAR_MODE, (mode));			\
	/*							\
	 * PLL logic requires minimum of 16 clock		\
	 * cycles to lock to the new clock speed.		\
	 * Wait 1 usec to satisfy this requirement.		\
	 */							\
	drv_usecwait(1);

#define	CHANGE_REFRESH_COUNT(direction, cur_div, new_div)	\
{								\
	volatile uint64_t data;					\
	uint64_t count, new_count;				\
	clock_t delay;						\
	data = lddphysio(HB_MEM_CNTRL0);			\
	count = (data & HB_REFRESH_COUNT_MASK) >> 		\
	    HB_REFRESH_COUNT_SHIFT;				\
	new_count = (HB_REFRESH_INTERVAL *			\
	    cpunodes[CPU->cpu_id].clock_freq) /			\
	    (HB_REFRESH_CLOCKS_PER_COUNT * (new_div) * NANOSEC);\
	data = (data & ~HB_REFRESH_COUNT_MASK) |		\
	    (new_count << HB_REFRESH_COUNT_SHIFT);		\
	stdphysio(HB_MEM_CNTRL0, data);				\
	data = lddphysio(HB_MEM_CNTRL0);        		\
	/*							\
	 * If we are slowing down the cpu and Memory		\
	 * Self Refresh is not enabled, it is required		\
	 * to wait for old refresh count to count-down and	\
	 * new refresh count to go into effect (let new value	\
	 * counts down once).					\
	 */							\
	if ((direction) == HB_SLOW_DOWN &&			\
	    (data & HB_SELF_REFRESH_MASK) == 0) {		\
		/*						\
		 * Each count takes 64 cpu clock cycles		\
		 * to decrement.  Wait for current refresh	\
		 * count plus new refresh count at current	\
		 * cpu speed to count down to zero.  Round	\
		 * up the delay time.				\
		 */						\
		delay = ((HB_REFRESH_CLOCKS_PER_COUNT *		\
		    (count + new_count) * MICROSEC * (cur_div)) /\
		    cpunodes[CPU->cpu_id].clock_freq) + 1;	\
		drv_usecwait(delay);				\
	}							\
}

#define	SET_SELF_REFRESH(bit)					\
{								\
	volatile uint64_t data;					\
	data = lddphysio(HB_MEM_CNTRL0);			\
	data = (data & ~HB_SELF_REFRESH_MASK) |			\
	    ((bit) << HB_SELF_REFRESH_SHIFT);			\
	stdphysio(HB_MEM_CNTRL0, data);				\
	data = lddphysio(HB_MEM_CNTRL0);			\
}
#endif	/* HUMMINGBIRD */

/* ARGSUSED */
void
cpu_change_speed(uint64_t new_divisor, uint64_t arg2)
{
#ifdef HUMMINGBIRD
	uint64_t cur_mask, cur_divisor = 0;
	volatile uint64_t reg;
	processor_info_t *pi = &(CPU->cpu_type_info);
	int index;

	if ((new_divisor < HB_FULL_DIV || new_divisor > HB_LOWEST_DIV) ||
	    (hb_eclk[new_divisor] == HB_ECLK_INVALID)) {
		cmn_err(CE_WARN, "cpu_change_speed: bad divisor 0x%lx",
		    new_divisor);
		return;
	}

	reg = lddphysio(HB_ESTAR_MODE);
	cur_mask = reg & HB_ECLK_MASK;
	for (index = HB_FULL_DIV; index <= HB_LOWEST_DIV; index++) {
		if (hb_eclk[index] == cur_mask) {
			cur_divisor = index;
			break;
		}
	}

	if (cur_divisor == 0)
		cmn_err(CE_PANIC, "cpu_change_speed: current divisor "
		    "can't be determined!");

	/*
	 * If we are already at the requested divisor speed, just
	 * return.
	 */
	if (cur_divisor == new_divisor)
		return;

	if (cur_divisor == HB_FULL_DIV && new_divisor == HB_HALF_DIV) {
		CHANGE_REFRESH_COUNT(HB_SLOW_DOWN, cur_divisor, new_divisor);
		SET_ESTAR_MODE(hb_eclk[new_divisor]);
		SET_SELF_REFRESH(HB_SELF_REFRESH_ENABLE);

	} else if (cur_divisor == HB_HALF_DIV && new_divisor == HB_FULL_DIV) {
		SET_SELF_REFRESH(HB_SELF_REFRESH_DISABLE);
		SET_ESTAR_MODE(hb_eclk[new_divisor]);
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		CHANGE_REFRESH_COUNT(HB_SPEED_UP, cur_divisor, new_divisor);

	} else if (cur_divisor == HB_FULL_DIV && new_divisor > HB_HALF_DIV) {
		/*
		 * Transition to 1/2 speed first, then to
		 * lower speed.
		 */
		CHANGE_REFRESH_COUNT(HB_SLOW_DOWN, cur_divisor, HB_HALF_DIV);
		SET_ESTAR_MODE(hb_eclk[HB_HALF_DIV]);
		SET_SELF_REFRESH(HB_SELF_REFRESH_ENABLE);

		CHANGE_REFRESH_COUNT(HB_SLOW_DOWN, HB_HALF_DIV, new_divisor);
		SET_ESTAR_MODE(hb_eclk[new_divisor]);

	} else if (cur_divisor > HB_HALF_DIV && new_divisor == HB_FULL_DIV) {
		/*
		 * Transition to 1/2 speed first, then to
		 * full speed.
		 */
		SET_ESTAR_MODE(hb_eclk[HB_HALF_DIV]);
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		CHANGE_REFRESH_COUNT(HB_SPEED_UP, cur_divisor, HB_HALF_DIV);

		SET_SELF_REFRESH(HB_SELF_REFRESH_DISABLE);
		SET_ESTAR_MODE(hb_eclk[new_divisor]);
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		CHANGE_REFRESH_COUNT(HB_SPEED_UP, HB_HALF_DIV, new_divisor);

	} else if (cur_divisor < new_divisor) {
		CHANGE_REFRESH_COUNT(HB_SLOW_DOWN, cur_divisor, new_divisor);
		SET_ESTAR_MODE(hb_eclk[new_divisor]);

	} else if (cur_divisor > new_divisor) {
		SET_ESTAR_MODE(hb_eclk[new_divisor]);
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		CHANGE_REFRESH_COUNT(HB_SPEED_UP, cur_divisor, new_divisor);
	}
	CPU->cpu_m.divisor = (uchar_t)new_divisor;
	cpu_set_curr_clock(((uint64_t)pi->pi_clock * 1000000) / new_divisor);
#endif
}

/*
 * Clear the AFSR sticky bits and the UDBs. For Sabre/Spitfire/Blackbird,
 * we clear all the sticky bits. If a non-null pointer to a async fault
 * structure argument is passed in, the captured error state (AFSR, AFAR, UDBs)
 * info will be returned in the structure.  If a non-null pointer to a
 * uint64_t is passed in, this will be updated if the CP bit is set in the
 * AFSR.  The afsr will be returned.
 */
static uint64_t
clear_errors(spitf_async_flt *spf_flt, uint64_t *acc_afsr)
{
	struct async_flt *aflt = (struct async_flt *)spf_flt;
	uint64_t afsr;
	uint64_t udbh, udbl;

	get_asyncflt(&afsr);

	if ((acc_afsr != NULL) && (afsr & P_AFSR_CP))
		*acc_afsr |= afsr;

	if (spf_flt != NULL) {
		aflt->flt_stat = afsr;
		get_asyncaddr(&aflt->flt_addr);
		aflt->flt_addr &= SABRE_AFAR_PA;

		get_udb_errors(&udbh, &udbl);
		spf_flt->flt_sdbh = (ushort_t)(udbh & 0x3FF);
		spf_flt->flt_sdbl = (ushort_t)(udbl & 0x3FF);
	}

	set_asyncflt(afsr);		/* clear afsr */
	clr_datapath();			/* clear udbs */
	return (afsr);
}

/*
 * Scan the ecache to look for bad lines.  If found, the afsr, afar, e$ data
 * tag of the first bad line will be returned. We also return the old-afsr
 * (before clearing the sticky bits). The linecnt data will be updated to
 * indicate the number of bad lines detected.
 */
static void
scan_ecache(uint64_t *t_afar, ec_data_t *ecache_data,
	uint64_t *ecache_tag, int *linecnt, uint64_t *t_afsr)
{
	ec_data_t t_ecdata[8];
	uint64_t t_etag, oafsr;
	uint64_t pa = AFLT_INV_ADDR;
	uint32_t i, j, ecache_sz;
	uint64_t acc_afsr = 0;
	uint64_t *cpu_afsr = NULL;

	if (CPU_PRIVATE(CPU) != NULL)
		cpu_afsr = CPU_PRIVATE_PTR(CPU, sfpr_scrub_afsr);

	*linecnt = 0;
	ecache_sz = cpunodes[CPU->cpu_id].ecache_size;

	for (i = 0; i < ecache_sz; i += 64) {
		get_ecache_dtag(i, (uint64_t *)&t_ecdata[0], &t_etag, &oafsr,
		    cpu_afsr);
		acc_afsr |= oafsr;

		/*
		 * Scan through the whole 64 bytes line in 8 8-byte chunks
		 * looking for the first occurrence of an EDP error.  The AFSR
		 * info is captured for each 8-byte chunk.  Note that for
		 * Spitfire/Blackbird, the AFSR.PSYND is captured by h/w in
		 * 16-byte chunk granularity (i.e. the AFSR will be the same
		 * for the high and low 8-byte words within the 16-byte chunk).
		 * For Sabre/Hummingbird, the AFSR.PSYND is captured in 8-byte
		 * granularity and only PSYND bits [7:0] are used.
		 */
		for (j = 0; j < 8; j++) {
			ec_data_t *ecdptr = &t_ecdata[j];

			if (ecdptr->ec_afsr & P_AFSR_EDP) {
				uint64_t errpa;
				ushort_t psynd;
				uint32_t ec_set_size = ecache_sz /
				    ecache_associativity;

				/*
				 * For Spitfire/Blackbird, we need to look at
				 * the PSYND to make sure that this 8-byte chunk
				 * is the right one.  PSYND bits [15:8] belong
				 * to the upper 8-byte (even) chunk.  Bits
				 * [7:0] belong to the lower 8-byte chunk (odd).
				 */
				psynd = ecdptr->ec_afsr & P_AFSR_P_SYND;
				if (!isus2i && !isus2e) {
					if (j & 0x1)
						psynd = psynd & 0xFF;
					else
						psynd = psynd >> 8;

					if (!psynd)
						continue; /* wrong chunk */
				}

				/* Construct the PA */
				errpa = ((t_etag & cpu_ec_tag_mask) <<
				    cpu_ec_tag_shift) | ((i | (j << 3)) %
				    ec_set_size);

				/* clean up the cache line */
				flushecacheline(P2ALIGN(errpa, 64),
				    cpunodes[CPU->cpu_id].ecache_size);

				oafsr = clear_errors(NULL, cpu_afsr);
				acc_afsr |= oafsr;

				(*linecnt)++;

				/*
				 * Capture the PA for the first bad line found.
				 * Return the ecache dump and tag info.
				 */
				if (pa == AFLT_INV_ADDR) {
					int k;

					pa = errpa;
					for (k = 0; k < 8; k++)
						ecache_data[k] = t_ecdata[k];
					*ecache_tag = t_etag;
				}
				break;
			}
		}
	}
	*t_afar = pa;
	*t_afsr = acc_afsr;
}

static void
cpu_log_ecmem_info(spitf_async_flt *spf_flt)
{
	struct async_flt *aflt = (struct async_flt *)spf_flt;
	uint64_t ecache_tag = spf_flt->flt_ec_tag;
	char linestr[30];
	char *state_str;
	int i;

	/*
	 * Check the ecache tag to make sure it
	 * is valid. If invalid, a memory dump was
	 * captured instead of a ecache dump.
	 */
	if (spf_flt->flt_ec_tag != AFLT_INV_ADDR) {
		uchar_t eparity = (uchar_t)
		    ((ecache_tag & cpu_ec_par_mask) >> cpu_ec_par_shift);

		uchar_t estate = (uchar_t)
		    ((ecache_tag & cpu_ec_state_mask) >> cpu_ec_state_shift);

		if (estate == cpu_ec_state_shr)
			state_str = "Shared";
		else if (estate == cpu_ec_state_exl)
			state_str = "Exclusive";
		else if (estate == cpu_ec_state_own)
			state_str = "Owner";
		else if (estate == cpu_ec_state_mod)
			state_str = "Modified";
		else
			state_str = "Invalid";

		if (spf_flt->flt_ec_lcnt > 1) {
			(void) snprintf(linestr, sizeof (linestr),
			    "Badlines found=%d", spf_flt->flt_ec_lcnt);
		} else {
			linestr[0] = '\0';
		}

		cpu_aflt_log(CE_CONT, 2, spf_flt, CPU_ERRID_FIRST, NULL,
		    " PA=0x%08x.%08x\n    E$tag 0x%08x.%08x E$State: %s "
		    "E$parity 0x%02x %s", (uint32_t)(aflt->flt_addr >> 32),
		    (uint32_t)aflt->flt_addr, (uint32_t)(ecache_tag >> 32),
		    (uint32_t)ecache_tag, state_str,
		    (uint32_t)eparity, linestr);
	} else {
		cpu_aflt_log(CE_CONT, 2, spf_flt, CPU_ERRID_FIRST, NULL,
		    " E$tag != PA from AFAR; E$line was victimized"
		    "\n    dumping memory from PA 0x%08x.%08x instead",
		    (uint32_t)(P2ALIGN(aflt->flt_addr, 64) >> 32),
		    (uint32_t)P2ALIGN(aflt->flt_addr, 64));
	}

	/*
	 * Dump out all 8 8-byte ecache data captured
	 * For each 8-byte data captured, we check the
	 * captured afsr's parity syndrome to find out
	 * which 8-byte chunk is bad. For memory dump, the
	 * AFSR values were initialized to 0.
	 */
	for (i = 0; i < 8; i++) {
		ec_data_t *ecdptr;
		uint_t offset;
		ushort_t psynd;
		ushort_t bad;
		uint64_t edp;

		offset = i << 3;	/* multiply by 8 */
		ecdptr = &spf_flt->flt_ec_data[i];
		psynd = ecdptr->ec_afsr & P_AFSR_P_SYND;
		edp = ecdptr->ec_afsr & P_AFSR_EDP;

		/*
		 * For Sabre/Hummingbird, parity synd is captured only
		 * in [7:0] of AFSR.PSYND for each 8-byte chunk.
		 * For spitfire/blackbird, AFSR.PSYND is captured
		 * in 16-byte granularity. [15:8] represent
		 * the upper 8 byte and [7:0] the lower 8 byte.
		 */
		if (isus2i || isus2e || (i & 0x1))
			bad = (psynd & 0xFF);		/* check bits [7:0] */
		else
			bad = (psynd & 0xFF00);		/* check bits [15:8] */

		if (bad && edp) {
			cpu_aflt_log(CE_CONT, 2, spf_flt, NO_LFLAGS, NULL,
			    " E$Data (0x%02x): 0x%08x.%08x "
			    "*Bad* PSYND=0x%04x", offset,
			    (uint32_t)(ecdptr->ec_d8 >> 32),
			    (uint32_t)ecdptr->ec_d8, psynd);
		} else {
			cpu_aflt_log(CE_CONT, 2, spf_flt, NO_LFLAGS, NULL,
			    " E$Data (0x%02x): 0x%08x.%08x", offset,
			    (uint32_t)(ecdptr->ec_d8 >> 32),
			    (uint32_t)ecdptr->ec_d8);
		}
	}
}

/*
 * Common logging function for all cpu async errors.  This function allows the
 * caller to generate a single cmn_err() call that logs the appropriate items
 * from the fault structure, and implements our rules for AFT logging levels.
 *
 *	ce_code: cmn_err() code (e.g. CE_PANIC, CE_WARN, CE_CONT)
 *	tagnum: 0, 1, 2, .. generate the [AFT#] tag
 *	spflt: pointer to spitfire async fault structure
 *	logflags: bitflags indicating what to output
 *	endstr: a end string to appear at the end of this log
 *	fmt: a format string to appear at the beginning of the log
 *
 * The logflags allows the construction of predetermined output from the spflt
 * structure.  The individual data items always appear in a consistent order.
 * Note that either or both of the spflt structure pointer and logflags may be
 * NULL or zero respectively, indicating that the predetermined output
 * substrings are not requested in this log.  The output looks like this:
 *
 *	[AFT#] <CPU_ERRID_FIRST><fmt string><CPU_FLTCPU>
 *	<CPU_SPACE><CPU_ERRID>
 *	newline+4spaces<CPU_AFSR><CPU_AFAR>
 *	newline+4spaces<CPU_AF_PSYND><CPU_AF_ETS><CPU_FAULTPC>
 *	newline+4spaces<CPU_UDBH><CPU_UDBL>
 *	newline+4spaces<CPU_SYND>
 *	newline+4spaces<endstr>
 *
 * Note that <endstr> may not start on a newline if we are logging <CPU_PSYND>;
 * it is assumed that <endstr> will be the unum string in this case.  The size
 * of our intermediate formatting buf[] is based on the worst case of all flags
 * being enabled.  We pass the caller's varargs directly to vcmn_err() for
 * formatting so we don't need additional stack space to format them here.
 */
/*PRINTFLIKE6*/
static void
cpu_aflt_log(int ce_code, int tagnum, spitf_async_flt *spflt, uint_t logflags,
	const char *endstr, const char *fmt, ...)
{
	struct async_flt *aflt = (struct async_flt *)spflt;
	char buf[400], *p, *q; /* see comments about buf[] size above */
	va_list ap;
	int console_log_flag;

	if ((aflt == NULL) || ((aflt->flt_class == CPU_FAULT) &&
	    (aflt->flt_stat & P_AFSR_LEVEL1)) ||
	    (aflt->flt_panic)) {
		console_log_flag = (tagnum < 2) || aft_verbose;
	} else {
		int verbose = ((aflt->flt_class == BUS_FAULT) ||
		    (aflt->flt_stat & P_AFSR_CE)) ?
		    ce_verbose_memory : ce_verbose_other;

		if (!verbose)
			return;

		console_log_flag = (verbose > 1);
	}

	if (console_log_flag)
		(void) sprintf(buf, "[AFT%d]", tagnum);
	else
		(void) sprintf(buf, "![AFT%d]", tagnum);

	p = buf + strlen(buf);	/* current buffer position */
	q = buf + sizeof (buf);	/* pointer past end of buffer */

	if (spflt != NULL && (logflags & CPU_ERRID_FIRST)) {
		(void) snprintf(p, (size_t)(q - p), " errID 0x%08x.%08x",
		    (uint32_t)(aflt->flt_id >> 32), (uint32_t)aflt->flt_id);
		p += strlen(p);
	}

	/*
	 * Copy the caller's format string verbatim into buf[].  It will be
	 * formatted by the call to vcmn_err() at the end of this function.
	 */
	if (fmt != NULL && p < q) {
		(void) strncpy(p, fmt, (size_t)(q - p - 1));
		buf[sizeof (buf) - 1] = '\0';
		p += strlen(p);
	}

	if (spflt != NULL) {
		if (logflags & CPU_FLTCPU) {
			(void) snprintf(p, (size_t)(q - p), " CPU%d",
			    aflt->flt_inst);
			p += strlen(p);
		}

		if (logflags & CPU_SPACE) {
			if (aflt->flt_status & ECC_D_TRAP)
				(void) snprintf(p, (size_t)(q - p),
				    " Data access");
			else if (aflt->flt_status & ECC_I_TRAP)
				(void) snprintf(p, (size_t)(q - p),
				    " Instruction access");
			p += strlen(p);
		}

		if (logflags & CPU_TL) {
			(void) snprintf(p, (size_t)(q - p), " at TL%s",
			    aflt->flt_tl ? ">0" : "=0");
			p += strlen(p);
		}

		if (logflags & CPU_ERRID) {
			(void) snprintf(p, (size_t)(q - p),
			    ", errID 0x%08x.%08x",
			    (uint32_t)(aflt->flt_id >> 32),
			    (uint32_t)aflt->flt_id);
			p += strlen(p);
		}

		if (logflags & CPU_AFSR) {
			(void) snprintf(p, (size_t)(q - p),
			    "\n    AFSR 0x%08b.%08b",
			    (uint32_t)(aflt->flt_stat >> 32), AFSR_FMTSTR0,
			    (uint32_t)aflt->flt_stat, AFSR_FMTSTR1);
			p += strlen(p);
		}

		if (logflags & CPU_AFAR) {
			(void) snprintf(p, (size_t)(q - p), " AFAR 0x%08x.%08x",
			    (uint32_t)(aflt->flt_addr >> 32),
			    (uint32_t)aflt->flt_addr);
			p += strlen(p);
		}

		if (logflags & CPU_AF_PSYND) {
			ushort_t psynd = (ushort_t)
			    (aflt->flt_stat & P_AFSR_P_SYND);

			(void) snprintf(p, (size_t)(q - p),
			    "\n    AFSR.PSYND 0x%04x(Score %02d)",
			    psynd, ecc_psynd_score(psynd));
			p += strlen(p);
		}

		if (logflags & CPU_AF_ETS) {
			(void) snprintf(p, (size_t)(q - p), " AFSR.ETS 0x%02x",
			    (uchar_t)((aflt->flt_stat & P_AFSR_ETS) >> 16));
			p += strlen(p);
		}

		if (logflags & CPU_FAULTPC) {
			(void) snprintf(p, (size_t)(q - p), " Fault_PC 0x%p",
			    (void *)aflt->flt_pc);
			p += strlen(p);
		}

		if (logflags & CPU_UDBH) {
			(void) snprintf(p, (size_t)(q - p),
			    "\n    UDBH 0x%04b UDBH.ESYND 0x%02x",
			    spflt->flt_sdbh, UDB_FMTSTR,
			    spflt->flt_sdbh & 0xFF);
			p += strlen(p);
		}

		if (logflags & CPU_UDBL) {
			(void) snprintf(p, (size_t)(q - p),
			    " UDBL 0x%04b UDBL.ESYND 0x%02x",
			    spflt->flt_sdbl, UDB_FMTSTR,
			    spflt->flt_sdbl & 0xFF);
			p += strlen(p);
		}

		if (logflags & CPU_SYND) {
			ushort_t synd = SYND(aflt->flt_synd);

			(void) snprintf(p, (size_t)(q - p),
			    "\n    %s Syndrome 0x%x Memory Module ",
			    UDBL(aflt->flt_synd) ? "UDBL" : "UDBH", synd);
			p += strlen(p);
		}
	}

	if (endstr != NULL) {
		if (!(logflags & CPU_SYND))
			(void) snprintf(p, (size_t)(q - p), "\n    %s", endstr);
		else
			(void) snprintf(p, (size_t)(q - p), "%s", endstr);
		p += strlen(p);
	}

	if (ce_code == CE_CONT && (p < q - 1))
		(void) strcpy(p, "\n"); /* add final \n if needed */

	va_start(ap, fmt);
	vcmn_err(ce_code, buf, ap);
	va_end(ap);
}

/*
 * Ecache Scrubbing
 *
 * The basic idea is to prevent lines from sitting in the ecache long enough
 * to build up soft errors which can lead to ecache parity errors.
 *
 * The following rules are observed when flushing the ecache:
 *
 * 1. When the system is busy, flush bad clean lines
 * 2. When the system is idle, flush all clean lines
 * 3. When the system is idle, flush good dirty lines
 * 4. Never flush bad dirty lines.
 *
 *	modify	parity	busy   idle
 *	----------------------------
 *	clean	good		X
 * 	clean	bad	X	X
 * 	dirty	good		X
 *	dirty	bad
 *
 * Bad or good refers to whether a line has an E$ parity error or not.
 * Clean or dirty refers to the state of the modified bit.  We currently
 * default the scan rate to 100 (scan 10% of the cache per second).
 *
 * The following are E$ states and actions.
 *
 * We encode our state as a 3-bit number, consisting of:
 *	ECACHE_STATE_MODIFIED	(0=clean, 1=dirty)
 *	ECACHE_STATE_PARITY	(0=good,  1=bad)
 *	ECACHE_STATE_BUSY	(0=idle,  1=busy)
 *
 * We associate a flushing and a logging action with each state.
 *
 * E$ actions are different for Spitfire and Sabre/Hummingbird modules.
 * MIRROR_FLUSH indicates that an E$ line will be flushed for the mirrored
 * E$ only, in addition to value being set by ec_flush.
 */

#define	ALWAYS_FLUSH		0x1	/* flush E$ line on all E$ types */
#define	NEVER_FLUSH		0x0	/* never the flush the E$ line */
#define	MIRROR_FLUSH		0xF	/* flush E$ line on mirrored E$ only */

struct {
	char	ec_flush;		/* whether to flush or not */
	char	ec_log;			/* ecache logging */
	char	ec_log_type;		/* log type info */
} ec_action[] = {	/* states of the E$ line in M P B */
	{ ALWAYS_FLUSH, 0, 0 },			 /* 0 0 0 clean_good_idle */
	{ MIRROR_FLUSH, 0, 0 },			 /* 0 0 1 clean_good_busy */
	{ ALWAYS_FLUSH, 1, CPU_BADLINE_CI_ERR }, /* 0 1 0 clean_bad_idle */
	{ ALWAYS_FLUSH, 1, CPU_BADLINE_CB_ERR }, /* 0 1 1 clean_bad_busy */
	{ ALWAYS_FLUSH, 0, 0 },			 /* 1 0 0 dirty_good_idle */
	{ MIRROR_FLUSH, 0, 0 },			 /* 1 0 1 dirty_good_busy */
	{ NEVER_FLUSH, 1, CPU_BADLINE_DI_ERR },	 /* 1 1 0 dirty_bad_idle */
	{ NEVER_FLUSH, 1, CPU_BADLINE_DB_ERR }	 /* 1 1 1 dirty_bad_busy */
};

/*
 * Offsets into the ec_action[] that determines clean_good_busy and
 * dirty_good_busy lines.
 */
#define	ECACHE_CGB_LINE		1	/* E$ clean_good_busy line */
#define	ECACHE_DGB_LINE		5	/* E$ dirty_good_busy line */

/*
 * We are flushing lines which are Clean_Good_Busy and also the lines
 * Dirty_Good_Busy. And we only follow it for non-mirrored E$.
 */
#define	CGB(x, m)	(((x) == ECACHE_CGB_LINE) && (m != ECACHE_CPU_MIRROR))
#define	DGB(x, m)	(((x) == ECACHE_DGB_LINE) && (m != ECACHE_CPU_MIRROR))

#define	ECACHE_STATE_MODIFIED	0x4
#define	ECACHE_STATE_PARITY	0x2
#define	ECACHE_STATE_BUSY	0x1

/*
 * If ecache is mirrored ecache_calls_a_sec and ecache_scan_rate are reduced.
 */
int ecache_calls_a_sec_mirrored = 1;
int ecache_lines_per_call_mirrored = 1;

int ecache_scrub_enable = 1;	/* ecache scrubbing is on by default */
int ecache_scrub_verbose = 1;		/* prints clean and dirty lines */
int ecache_scrub_panic = 0;		/* panics on a clean and dirty line */
int ecache_calls_a_sec = 100;		/* scrubber calls per sec */
int ecache_scan_rate = 100;		/* scan rate (in tenths of a percent) */
int ecache_idle_factor = 1;		/* increase the scan rate when idle */
int ecache_flush_clean_good_busy = 50;	/* flush rate (in percent) */
int ecache_flush_dirty_good_busy = 100;	/* flush rate (in percent) */

volatile int ec_timeout_calls = 1;	/* timeout calls */

/*
 * Interrupt number and pil for ecache scrubber cross-trap calls.
 */
static uint64_t ecache_scrub_inum;
uint_t ecache_scrub_pil = PIL_9;

/*
 * Kstats for the E$ scrubber.
 */
typedef struct ecache_kstat {
	kstat_named_t clean_good_idle;		/* # of lines scrubbed */
	kstat_named_t clean_good_busy;		/* # of lines skipped */
	kstat_named_t clean_bad_idle;		/* # of lines scrubbed */
	kstat_named_t clean_bad_busy;		/* # of lines scrubbed */
	kstat_named_t dirty_good_idle;		/* # of lines scrubbed */
	kstat_named_t dirty_good_busy;		/* # of lines skipped */
	kstat_named_t dirty_bad_idle;		/* # of lines skipped */
	kstat_named_t dirty_bad_busy;		/* # of lines skipped */
	kstat_named_t invalid_lines;		/* # of invalid lines */
	kstat_named_t clean_good_busy_flush;    /* # of lines scrubbed */
	kstat_named_t dirty_good_busy_flush;    /* # of lines scrubbed */
	kstat_named_t tags_cleared;		/* # of E$ tags cleared */
} ecache_kstat_t;

static ecache_kstat_t ec_kstat_template = {
	{ "clean_good_idle", KSTAT_DATA_ULONG },
	{ "clean_good_busy", KSTAT_DATA_ULONG },
	{ "clean_bad_idle", KSTAT_DATA_ULONG },
	{ "clean_bad_busy", KSTAT_DATA_ULONG },
	{ "dirty_good_idle", KSTAT_DATA_ULONG },
	{ "dirty_good_busy", KSTAT_DATA_ULONG },
	{ "dirty_bad_idle", KSTAT_DATA_ULONG },
	{ "dirty_bad_busy", KSTAT_DATA_ULONG },
	{ "invalid_lines", KSTAT_DATA_ULONG },
	{ "clean_good_busy_flush", KSTAT_DATA_ULONG },
	{ "dirty_good_busy_flush", KSTAT_DATA_ULONG },
	{ "ecache_tags_cleared", KSTAT_DATA_ULONG }
};

struct kmem_cache *sf_private_cache;

/*
 * Called periodically on each CPU to scan the ecache once a sec.
 * adjusting the ecache line index appropriately
 */
void
scrub_ecache_line()
{
	spitfire_scrub_misc_t *ssmp = CPU_PRIVATE_PTR(CPU, sfpr_scrub_misc);
	int cpuid = CPU->cpu_id;
	uint32_t index = ssmp->ecache_flush_index;
	uint64_t ec_size = cpunodes[cpuid].ecache_size;
	size_t ec_linesize = cpunodes[cpuid].ecache_linesize;
	int nlines = ssmp->ecache_nlines;
	uint32_t ec_set_size = ec_size / ecache_associativity;
	int ec_mirror = ssmp->ecache_mirror;
	ecache_kstat_t *ec_ksp = (ecache_kstat_t *)ssmp->ecache_ksp->ks_data;

	int line, scan_lines, flush_clean_busy = 0, flush_dirty_busy = 0;
	int mpb;		/* encode Modified, Parity, Busy for action */
	uchar_t state;
	uint64_t ec_tag, paddr, oafsr, tafsr, nafsr;
	uint64_t *acc_afsr = CPU_PRIVATE_PTR(CPU, sfpr_scrub_afsr);
	ec_data_t ec_data[8];
	kstat_named_t *ec_knp;

	switch (ec_mirror) {
		default:
		case ECACHE_CPU_NON_MIRROR:
			/*
			 * The E$ scan rate is expressed in units of tenths of
			 * a percent.  ecache_scan_rate = 1000 (100%) means the
			 * whole cache is scanned every second.
			 */
			scan_lines = (nlines * ecache_scan_rate) /
			    (1000 * ecache_calls_a_sec);
			if (!(ssmp->ecache_busy)) {
				if (ecache_idle_factor > 0) {
					scan_lines *= ecache_idle_factor;
				}
			} else {
				flush_clean_busy = (scan_lines *
				    ecache_flush_clean_good_busy) / 100;
				flush_dirty_busy = (scan_lines *
				    ecache_flush_dirty_good_busy) / 100;
			}

			ec_timeout_calls = (ecache_calls_a_sec ?
			    ecache_calls_a_sec : 1);
			break;

		case ECACHE_CPU_MIRROR:
			scan_lines = ecache_lines_per_call_mirrored;
			ec_timeout_calls = (ecache_calls_a_sec_mirrored ?
			    ecache_calls_a_sec_mirrored : 1);
			break;
	}

	/*
	 * The ecache scrubber algorithm operates by reading and
	 * decoding the E$ tag to determine whether the corresponding E$ line
	 * can be scrubbed. There is a implicit assumption in the scrubber
	 * logic that the E$ tag is valid. Unfortunately, this assertion is
	 * flawed since the E$ tag may also be corrupted and have parity errors
	 * The scrubber logic is enhanced to check the validity of the E$ tag
	 * before scrubbing. When a parity error is detected in the E$ tag,
	 * it is possible to recover and scrub the tag under certain conditions
	 * so that a ETP error condition can be avoided.
	 */

	for (mpb = line = 0; line < scan_lines; line++, mpb = 0) {
		/*
		 * We get the old-AFSR before clearing the AFSR sticky bits
		 * in {get_ecache_tag, check_ecache_line, get_ecache_dtag}
		 * If CP bit is set in the old-AFSR, we log an Orphan CP event.
		 */
		ec_tag = get_ecache_tag(index, &nafsr, acc_afsr);
		state = (uchar_t)((ec_tag & cpu_ec_state_mask) >>
		    cpu_ec_state_shift);

		/*
		 * ETP is set try to scrub the ecache tag.
		 */
		if (nafsr & P_AFSR_ETP) {
			ecache_scrub_tag_err(nafsr, state, index);
		} else if (state & cpu_ec_state_valid) {
			/*
			 * ETP is not set, E$ tag is valid.
			 * Proceed with the E$ scrubbing.
			 */
			if (state & cpu_ec_state_dirty)
				mpb |= ECACHE_STATE_MODIFIED;

			tafsr = check_ecache_line(index, acc_afsr);

			if (tafsr & P_AFSR_EDP) {
				mpb |= ECACHE_STATE_PARITY;

				if (ecache_scrub_verbose ||
				    ecache_scrub_panic) {
					get_ecache_dtag(P2ALIGN(index, 64),
					    (uint64_t *)&ec_data[0],
					    &ec_tag, &oafsr, acc_afsr);
				}
			}

			if (ssmp->ecache_busy)
				mpb |= ECACHE_STATE_BUSY;

			ec_knp = (kstat_named_t *)ec_ksp + mpb;
			ec_knp->value.ul++;

			paddr = ((ec_tag & cpu_ec_tag_mask) <<
			    cpu_ec_tag_shift) | (index % ec_set_size);

			/*
			 * We flush the E$ lines depending on the ec_flush,
			 * we additionally flush clean_good_busy and
			 * dirty_good_busy lines for mirrored E$.
			 */
			if (ec_action[mpb].ec_flush == ALWAYS_FLUSH) {
				flushecacheline(paddr, ec_size);
			} else if ((ec_mirror == ECACHE_CPU_MIRROR) &&
			    (ec_action[mpb].ec_flush == MIRROR_FLUSH)) {
				flushecacheline(paddr, ec_size);
			} else if (ec_action[mpb].ec_flush == NEVER_FLUSH) {
				softcall(ecache_page_retire, (void *)paddr);
			}

			/*
			 * Conditionally flush both the clean_good and
			 * dirty_good lines when busy.
			 */
			if (CGB(mpb, ec_mirror) && (flush_clean_busy > 0)) {
				flush_clean_busy--;
				flushecacheline(paddr, ec_size);
				ec_ksp->clean_good_busy_flush.value.ul++;
			} else if (DGB(mpb, ec_mirror) &&
			    (flush_dirty_busy > 0)) {
				flush_dirty_busy--;
				flushecacheline(paddr, ec_size);
				ec_ksp->dirty_good_busy_flush.value.ul++;
			}

			if (ec_action[mpb].ec_log && (ecache_scrub_verbose ||
			    ecache_scrub_panic)) {
				ecache_scrub_log(ec_data, ec_tag, paddr, mpb,
				    tafsr);
			}

		} else {
			ec_ksp->invalid_lines.value.ul++;
		}

		if ((index += ec_linesize) >= ec_size)
			index = 0;

	}

	/*
	 * set the ecache scrub index for the next time around
	 */
	ssmp->ecache_flush_index = index;

	if (*acc_afsr & P_AFSR_CP) {
		uint64_t ret_afsr;

		ret_afsr = ecache_scrub_misc_err(CPU_ORPHAN_CP_ERR, *acc_afsr);
		if ((ret_afsr & P_AFSR_CP) == 0)
			*acc_afsr = 0;
	}
}

/*
 * Handler for ecache_scrub_inum softint.  Call scrub_ecache_line until
 * we decrement the outstanding request count to zero.
 */

/*ARGSUSED*/
uint_t
scrub_ecache_line_intr(caddr_t arg1, caddr_t arg2)
{
	int i;
	int outstanding;
	spitfire_scrub_misc_t *ssmp = CPU_PRIVATE_PTR(CPU, sfpr_scrub_misc);
	uint32_t *countp = &ssmp->ec_scrub_outstanding;

	do {
		outstanding = *countp;
		ASSERT(outstanding > 0);
		for (i = 0; i < outstanding; i++)
			scrub_ecache_line();
	} while (atomic_add_32_nv(countp, -outstanding));

	return (DDI_INTR_CLAIMED);
}

/*
 * force each cpu to perform an ecache scrub, called from a timeout
 */
extern xcfunc_t ecache_scrubreq_tl1;

void
do_scrub_ecache_line(void)
{
	long delta;

	if (ecache_calls_a_sec > hz)
		ecache_calls_a_sec = hz;
	else if (ecache_calls_a_sec <= 0)
		ecache_calls_a_sec = 1;

	if (ecache_calls_a_sec_mirrored > hz)
		ecache_calls_a_sec_mirrored = hz;
	else if (ecache_calls_a_sec_mirrored <= 0)
		ecache_calls_a_sec_mirrored = 1;

	if (ecache_scrub_enable) {
		xt_all(ecache_scrubreq_tl1, ecache_scrub_inum, 0);
		delta = hz / ec_timeout_calls;
	} else {
		delta = hz;
	}

	(void) realtime_timeout((void(*)(void *))do_scrub_ecache_line, 0,
	    delta);
}

/*
 * initialization for ecache scrubbing
 * This routine is called AFTER all cpus have had cpu_init_private called
 * to initialize their private data areas.
 */
void
cpu_init_cache_scrub(void)
{
	if (ecache_calls_a_sec > hz) {
		cmn_err(CE_NOTE, "ecache_calls_a_sec set too high (%d); "
		    "resetting to hz (%d)", ecache_calls_a_sec, hz);
		ecache_calls_a_sec = hz;
	}

	/*
	 * Register softint for ecache scrubbing.
	 */
	ecache_scrub_inum = add_softintr(ecache_scrub_pil,
	    scrub_ecache_line_intr, NULL, SOFTINT_MT);

	/*
	 * kick off the scrubbing using realtime timeout
	 */
	(void) realtime_timeout((void(*)(void *))do_scrub_ecache_line, 0,
	    hz / ecache_calls_a_sec);
}

/*
 * Unset the busy flag for this cpu.
 */
void
cpu_idle_ecache_scrub(struct cpu *cp)
{
	if (CPU_PRIVATE(cp) != NULL) {
		spitfire_scrub_misc_t *ssmp = CPU_PRIVATE_PTR(cp,
		    sfpr_scrub_misc);
		ssmp->ecache_busy = ECACHE_CPU_IDLE;
	}
}

/*
 * Set the busy flag for this cpu.
 */
void
cpu_busy_ecache_scrub(struct cpu *cp)
{
	if (CPU_PRIVATE(cp) != NULL) {
		spitfire_scrub_misc_t *ssmp = CPU_PRIVATE_PTR(cp,
		    sfpr_scrub_misc);
		ssmp->ecache_busy = ECACHE_CPU_BUSY;
	}
}

/*
 * initialize the ecache scrubber data structures
 * The global entry point cpu_init_private replaces this entry point.
 *
 */
static void
cpu_init_ecache_scrub_dr(struct cpu *cp)
{
	spitfire_scrub_misc_t *ssmp = CPU_PRIVATE_PTR(cp, sfpr_scrub_misc);
	int cpuid = cp->cpu_id;

	/*
	 * intialize bookkeeping for cache scrubbing
	 */
	bzero(ssmp, sizeof (spitfire_scrub_misc_t));

	ssmp->ecache_flush_index = 0;

	ssmp->ecache_nlines =
	    cpunodes[cpuid].ecache_size / cpunodes[cpuid].ecache_linesize;

	/*
	 * Determine whether we are running on mirrored SRAM
	 */

	if (cpunodes[cpuid].msram == ECACHE_CPU_MIRROR)
		ssmp->ecache_mirror = ECACHE_CPU_MIRROR;
	else
		ssmp->ecache_mirror = ECACHE_CPU_NON_MIRROR;

	cpu_busy_ecache_scrub(cp);

	/*
	 * initialize the kstats
	 */
	ecache_kstat_init(cp);
}

/*
 * uninitialize the ecache scrubber data structures
 * The global entry point cpu_uninit_private replaces this entry point.
 */
static void
cpu_uninit_ecache_scrub_dr(struct cpu *cp)
{
	spitfire_scrub_misc_t *ssmp = CPU_PRIVATE_PTR(cp, sfpr_scrub_misc);

	if (ssmp->ecache_ksp != NULL) {
		kstat_delete(ssmp->ecache_ksp);
		ssmp->ecache_ksp = NULL;
	}

	/*
	 * un-initialize bookkeeping for cache scrubbing
	 */
	bzero(ssmp, sizeof (spitfire_scrub_misc_t));

	cpu_idle_ecache_scrub(cp);
}

struct kmem_cache *sf_private_cache;

/*
 * Cpu private initialization.  This includes allocating the cpu_private
 * data structure, initializing it, and initializing the scrubber for this
 * cpu.  This is called once for EVERY cpu, including CPU 0. This function
 * calls cpu_init_ecache_scrub_dr to init the scrubber.
 * We use kmem_cache_create for the spitfire private data structure because it
 * needs to be allocated on a S_ECACHE_MAX_LSIZE (64) byte boundary.
 */
void
cpu_init_private(struct cpu *cp)
{
	spitfire_private_t *sfprp;

	ASSERT(CPU_PRIVATE(cp) == NULL);

	/*
	 * If the sf_private_cache has not been created, create it.
	 */
	if (sf_private_cache == NULL) {
		sf_private_cache = kmem_cache_create("sf_private_cache",
		    sizeof (spitfire_private_t), S_ECACHE_MAX_LSIZE, NULL,
		    NULL, NULL, NULL, NULL, 0);
		ASSERT(sf_private_cache);
	}

	sfprp = CPU_PRIVATE(cp) = kmem_cache_alloc(sf_private_cache, KM_SLEEP);

	bzero(sfprp, sizeof (spitfire_private_t));

	cpu_init_ecache_scrub_dr(cp);
}

/*
 * Cpu private unitialization.  Uninitialize the Ecache scrubber and
 * deallocate the scrubber data structures and cpu_private data structure.
 * For now, this function just calls cpu_unint_ecache_scrub_dr to uninit
 * the scrubber for the specified cpu.
 */
void
cpu_uninit_private(struct cpu *cp)
{
	ASSERT(CPU_PRIVATE(cp));

	cpu_uninit_ecache_scrub_dr(cp);
	kmem_cache_free(sf_private_cache, CPU_PRIVATE(cp));
	CPU_PRIVATE(cp) = NULL;
}

/*
 * initialize the ecache kstats for each cpu
 */
static void
ecache_kstat_init(struct cpu *cp)
{
	struct kstat *ksp;
	spitfire_scrub_misc_t *ssmp = CPU_PRIVATE_PTR(cp, sfpr_scrub_misc);

	ASSERT(ssmp != NULL);

	if ((ksp = kstat_create("unix", cp->cpu_id, "ecache_kstat", "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (ecache_kstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE)) == NULL) {
		ssmp->ecache_ksp = NULL;
		cmn_err(CE_NOTE, "!ecache_kstat_init(%d) failed\n", cp->cpu_id);
		return;
	}

	ssmp->ecache_ksp = ksp;
	bcopy(&ec_kstat_template, ksp->ks_data, sizeof (ecache_kstat_t));
	kstat_install(ksp);
}

/*
 * log the bad ecache information
 */
static void
ecache_scrub_log(ec_data_t *ec_data, uint64_t ec_tag, uint64_t paddr, int mpb,
		uint64_t afsr)
{
	spitf_async_flt spf_flt;
	struct async_flt *aflt;
	int i;
	char *class;

	bzero(&spf_flt, sizeof (spitf_async_flt));
	aflt = &spf_flt.cmn_asyncflt;

	for (i = 0; i < 8; i++) {
		spf_flt.flt_ec_data[i] = ec_data[i];
	}

	spf_flt.flt_ec_tag = ec_tag;

	if (mpb < (sizeof (ec_action) / sizeof (ec_action[0]))) {
		spf_flt.flt_type = ec_action[mpb].ec_log_type;
	} else spf_flt.flt_type = (ushort_t)mpb;

	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_addr = paddr;
	aflt->flt_stat = afsr;
	aflt->flt_panic = (uchar_t)ecache_scrub_panic;

	switch (mpb) {
	case CPU_ECACHE_TAG_ERR:
	case CPU_ECACHE_ADDR_PAR_ERR:
	case CPU_ECACHE_ETP_ETS_ERR:
	case CPU_ECACHE_STATE_ERR:
		class = FM_EREPORT_CPU_USII_ESCRUB_TAG;
		break;
	default:
		class = FM_EREPORT_CPU_USII_ESCRUB_DATA;
		break;
	}

	cpu_errorq_dispatch(class, (void *)&spf_flt, sizeof (spf_flt),
	    ue_queue, aflt->flt_panic);

	if (aflt->flt_panic)
		cmn_err(CE_PANIC, "ecache_scrub_panic set and bad E$"
		    "line detected");
}

/*
 * Process an ecache error that occured during the E$ scrubbing.
 * We do the ecache scan to find the bad line, flush the bad line
 * and start the memscrubber to find any UE (in memory or in another cache)
 */
static uint64_t
ecache_scrub_misc_err(int type, uint64_t afsr)
{
	spitf_async_flt spf_flt;
	struct async_flt *aflt;
	uint64_t oafsr;

	bzero(&spf_flt, sizeof (spitf_async_flt));
	aflt = &spf_flt.cmn_asyncflt;

	/*
	 * Scan each line in the cache to look for the one
	 * with bad parity
	 */
	aflt->flt_addr = AFLT_INV_ADDR;
	scan_ecache(&aflt->flt_addr, &spf_flt.flt_ec_data[0],
	    &spf_flt.flt_ec_tag, &spf_flt.flt_ec_lcnt, &oafsr);

	if (oafsr & P_AFSR_CP) {
		uint64_t *cp_afsr = CPU_PRIVATE_PTR(CPU, sfpr_scrub_afsr);
		*cp_afsr |= oafsr;
	}

	/*
	 * If we found a bad PA, update the state to indicate if it is
	 * memory or I/O space.
	 */
	if (aflt->flt_addr != AFLT_INV_ADDR) {
		aflt->flt_in_memory = (pf_is_memory(aflt->flt_addr >>
		    MMU_PAGESHIFT)) ? 1 : 0;
	}

	spf_flt.flt_type = (ushort_t)type;

	aflt->flt_inst = CPU->cpu_id;
	aflt->flt_class = CPU_FAULT;
	aflt->flt_id = gethrtime_waitfree();
	aflt->flt_status = afsr;
	aflt->flt_panic = (uchar_t)ecache_scrub_panic;

	/*
	 * We have the bad line, flush that line and start
	 * the memscrubber.
	 */
	if (spf_flt.flt_ec_lcnt > 0) {
		flushecacheline(P2ALIGN(aflt->flt_addr, 64),
		    cpunodes[CPU->cpu_id].ecache_size);
		read_all_memscrub = 1;
		memscrub_run();
	}

	cpu_errorq_dispatch((type == CPU_ORPHAN_CP_ERR) ?
	    FM_EREPORT_CPU_USII_CP : FM_EREPORT_CPU_USII_UNKNOWN,
	    (void *)&spf_flt, sizeof (spf_flt), ue_queue, aflt->flt_panic);

	return (oafsr);
}

static void
ecache_scrub_tag_err(uint64_t afsr, uchar_t state, uint32_t index)
{
	ushort_t afsr_ets = (afsr & P_AFSR_ETS) >> P_AFSR_ETS_SHIFT;
	spitfire_scrub_misc_t *ssmp = CPU_PRIVATE_PTR(CPU, sfpr_scrub_misc);
	ecache_kstat_t *ec_ksp = (ecache_kstat_t *)ssmp->ecache_ksp->ks_data;
	uint64_t ec_tag, paddr, oafsr;
	ec_data_t ec_data[8];
	int cpuid = CPU->cpu_id;
	uint32_t ec_set_size = cpunodes[cpuid].ecache_size /
	    ecache_associativity;
	uint64_t *cpu_afsr = CPU_PRIVATE_PTR(CPU, sfpr_scrub_afsr);

	get_ecache_dtag(P2ALIGN(index, 64), (uint64_t *)&ec_data[0], &ec_tag,
	    &oafsr, cpu_afsr);
	paddr = ((ec_tag & cpu_ec_tag_mask) << cpu_ec_tag_shift) |
	    (index % ec_set_size);

	/*
	 * E$ tag state has good parity
	 */
	if ((afsr_ets & cpu_ec_state_parity) == 0) {
		if (afsr_ets & cpu_ec_parity) {
			/*
			 * E$ tag state bits indicate the line is clean,
			 * invalidate the E$ tag and continue.
			 */
			if (!(state & cpu_ec_state_dirty)) {
				/*
				 * Zero the tag and mark the state invalid
				 * with good parity for the tag.
				 */
				if (isus2i || isus2e)
					write_hb_ec_tag_parity(index);
				else
					write_ec_tag_parity(index);

				/* Sync with the dual tag */
				flushecacheline(0,
				    cpunodes[CPU->cpu_id].ecache_size);
				ec_ksp->tags_cleared.value.ul++;
				ecache_scrub_log(ec_data, ec_tag, paddr,
				    CPU_ECACHE_TAG_ERR, afsr);
				return;
			} else {
				ecache_scrub_log(ec_data, ec_tag, paddr,
				    CPU_ECACHE_ADDR_PAR_ERR, afsr);
				cmn_err(CE_PANIC, " E$ tag address has bad"
				    " parity");
			}
		} else if ((afsr_ets & cpu_ec_parity) == 0) {
			/*
			 * ETS is zero but ETP is set
			 */
			ecache_scrub_log(ec_data, ec_tag, paddr,
			    CPU_ECACHE_ETP_ETS_ERR, afsr);
			cmn_err(CE_PANIC, "AFSR.ETP is set and"
			    " AFSR.ETS is zero");
		}
	} else {
		/*
		 * E$ tag state bit has a bad parity
		 */
		ecache_scrub_log(ec_data, ec_tag, paddr,
		    CPU_ECACHE_STATE_ERR, afsr);
		cmn_err(CE_PANIC, "E$ tag state has bad parity");
	}
}

static void
ecache_page_retire(void *arg)
{
	uint64_t paddr = (uint64_t)arg;
	(void) page_retire(paddr, PR_UE);
}

void
sticksync_slave(void)
{}

void
sticksync_master(void)
{}

/*ARGSUSED*/
void
cpu_check_ce(int flag, uint64_t pa, caddr_t va, uint_t bpp)
{}

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

/*ARGSUSED*/
void
cpu_errorq_dispatch(char *error_class, void *payload, size_t payload_sz,
    errorq_t *eqp, uint_t flag)
{
	struct async_flt *aflt = (struct async_flt *)payload;

	aflt->flt_erpt_class = error_class;
	errorq_dispatch(eqp, payload, payload_sz, flag);
}

#define	MAX_SIMM	8

struct ce_info {
	char    name[UNUM_NAMLEN];
	uint64_t intermittent_total;
	uint64_t persistent_total;
	uint64_t sticky_total;
	unsigned short leaky_bucket_cnt;
};

/*
 * Separately-defined structure for use in reporting the ce_info
 * to SunVTS without exposing the internal layout and implementation
 * of struct ce_info.
 */
static struct ecc_error_info ecc_error_info_data = {
	{ "version", KSTAT_DATA_UINT32 },
	{ "maxcount", KSTAT_DATA_UINT32 },
	{ "count", KSTAT_DATA_UINT32 }
};
static const size_t ecc_error_info_ndata = sizeof (ecc_error_info_data) /
    sizeof (struct kstat_named);

#if KSTAT_CE_UNUM_NAMLEN < UNUM_NAMLEN
#error "Need to rev ecc_error_info version and update KSTAT_CE_UNUM_NAMLEN"
#endif

struct ce_info  *mem_ce_simm = NULL;
size_t mem_ce_simm_size = 0;

/*
 * Default values for the number of CE's allowed per interval.
 * Interval is defined in minutes
 * SOFTERR_MIN_TIMEOUT is defined in microseconds
 */
#define	SOFTERR_LIMIT_DEFAULT		2
#define	SOFTERR_INTERVAL_DEFAULT	1440		/* This is 24 hours */
#define	SOFTERR_MIN_TIMEOUT		(60 * MICROSEC)	/* This is 1 minute */
#define	TIMEOUT_NONE			((timeout_id_t)0)
#define	TIMEOUT_SET			((timeout_id_t)1)

/*
 * timeout identifer for leaky_bucket
 */
static timeout_id_t leaky_bucket_timeout_id = TIMEOUT_NONE;

/*
 * Tunables for maximum number of allowed CE's in a given time
 */
int ecc_softerr_limit = SOFTERR_LIMIT_DEFAULT;
int ecc_softerr_interval = SOFTERR_INTERVAL_DEFAULT;

void
cpu_mp_init(void)
{
	size_t size = cpu_aflt_size();
	size_t i;
	kstat_t *ksp;

	/*
	 * Initialize the CE error handling buffers.
	 */
	mem_ce_simm_size = MAX_SIMM * max_ncpus;
	size = sizeof (struct ce_info) * mem_ce_simm_size;
	mem_ce_simm = kmem_zalloc(size, KM_SLEEP);

	ksp = kstat_create("unix", 0, "ecc-info", "misc",
	    KSTAT_TYPE_NAMED, ecc_error_info_ndata, KSTAT_FLAG_VIRTUAL);
	if (ksp != NULL) {
		ksp->ks_data = (struct kstat_named *)&ecc_error_info_data;
		ecc_error_info_data.version.value.ui32 = KSTAT_CE_INFO_VER;
		ecc_error_info_data.maxcount.value.ui32 = mem_ce_simm_size;
		ecc_error_info_data.count.value.ui32 = 0;
		kstat_install(ksp);
	}

	for (i = 0; i < mem_ce_simm_size; i++) {
		struct kstat_ecc_mm_info *kceip;

		kceip = kmem_zalloc(sizeof (struct kstat_ecc_mm_info),
		    KM_SLEEP);
		ksp = kstat_create("mm", i, "ecc-info", "misc",
		    KSTAT_TYPE_NAMED,
		    sizeof (struct kstat_ecc_mm_info) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL);
		if (ksp != NULL) {
			/*
			 * Re-declare ks_data_size to include room for the
			 * UNUM name since we don't have KSTAT_FLAG_VAR_SIZE
			 * set.
			 */
			ksp->ks_data_size = sizeof (struct kstat_ecc_mm_info) +
			    KSTAT_CE_UNUM_NAMLEN;
			ksp->ks_data = kceip;
			kstat_named_init(&kceip->name,
			    "name", KSTAT_DATA_STRING);
			kstat_named_init(&kceip->intermittent_total,
			    "intermittent_total", KSTAT_DATA_UINT64);
			kstat_named_init(&kceip->persistent_total,
			    "persistent_total", KSTAT_DATA_UINT64);
			kstat_named_init(&kceip->sticky_total,
			    "sticky_total", KSTAT_DATA_UINT64);
			/*
			 * Use the default snapshot routine as it knows how to
			 * deal with named kstats with long strings.
			 */
			ksp->ks_update = ecc_kstat_update;
			kstat_install(ksp);
		} else {
			kmem_free(kceip, sizeof (struct kstat_ecc_mm_info));
		}
	}
}

/*ARGSUSED*/
static void
leaky_bucket_timeout(void *arg)
{
	int i;
	struct ce_info *psimm = mem_ce_simm;

	for (i = 0; i < mem_ce_simm_size; i++) {
		if (psimm[i].leaky_bucket_cnt > 0)
			atomic_dec_16(&psimm[i].leaky_bucket_cnt);
	}
	add_leaky_bucket_timeout();
}

static void
add_leaky_bucket_timeout(void)
{
	long timeout_in_microsecs;

	/*
	 * create timeout for next leak.
	 *
	 * The timeout interval is calculated as follows
	 *
	 * (ecc_softerr_interval * 60 * MICROSEC) / ecc_softerr_limit
	 *
	 * ecc_softerr_interval is in minutes, so multiply this by 60 (seconds
	 * in a minute), then multiply this by MICROSEC to get the interval
	 * in microseconds.  Divide this total by ecc_softerr_limit so that
	 * the timeout interval is accurate to within a few microseconds.
	 */

	if (ecc_softerr_limit <= 0)
		ecc_softerr_limit = SOFTERR_LIMIT_DEFAULT;
	if (ecc_softerr_interval <= 0)
		ecc_softerr_interval = SOFTERR_INTERVAL_DEFAULT;

	timeout_in_microsecs = ((int64_t)ecc_softerr_interval * 60 * MICROSEC) /
	    ecc_softerr_limit;

	if (timeout_in_microsecs < SOFTERR_MIN_TIMEOUT)
		timeout_in_microsecs = SOFTERR_MIN_TIMEOUT;

	leaky_bucket_timeout_id = timeout(leaky_bucket_timeout,
	    (void *)NULL, drv_usectohz((clock_t)timeout_in_microsecs));
}

/*
 * Legacy Correctable ECC Error Hash
 *
 * All of the code below this comment is used to implement a legacy array
 * which counted intermittent, persistent, and sticky CE errors by unum,
 * and then was later extended to publish the data as a kstat for SunVTS.
 * All of this code is replaced by FMA, and remains here until such time
 * that the UltraSPARC-I/II CPU code is converted to FMA, or is EOLed.
 *
 * Errors are saved in three buckets per-unum:
 * (1) sticky - scrub was unsuccessful, cannot be scrubbed
 *     This could represent a problem, and is immediately printed out.
 * (2) persistent - was successfully scrubbed
 *     These errors use the leaky bucket algorithm to determine
 *     if there is a serious problem.
 * (3) intermittent - may have originated from the cpu or upa/safari bus,
 *     and does not necessarily indicate any problem with the dimm itself,
 *     is critical information for debugging new hardware.
 *     Because we do not know if it came from the dimm, it would be
 *     inappropriate to include these in the leaky bucket counts.
 *
 * If the E$ line was modified before the scrub operation began, then the
 * displacement flush at the beginning of scrubphys() will cause the modified
 * line to be written out, which will clean up the CE.  Then, any subsequent
 * read will not cause an error, which will cause persistent errors to be
 * identified as intermittent.
 *
 * If a DIMM is going bad, it will produce true persistents as well as
 * false intermittents, so these intermittents can be safely ignored.
 *
 * If the error count is excessive for a DIMM, this function will return
 * PR_MCE, and the CPU module may then decide to remove that page from use.
 */
static int
ce_count_unum(int status, int len, char *unum)
{
	int i;
	struct ce_info *psimm = mem_ce_simm;
	int page_status = PR_OK;

	ASSERT(psimm != NULL);

	if (len <= 0 ||
	    (status & (ECC_STICKY | ECC_PERSISTENT | ECC_INTERMITTENT)) == 0)
		return (page_status);

	/*
	 * Initialize the leaky_bucket timeout
	 */
	if (atomic_cas_ptr(&leaky_bucket_timeout_id,
	    TIMEOUT_NONE, TIMEOUT_SET) == TIMEOUT_NONE)
		add_leaky_bucket_timeout();

	for (i = 0; i < mem_ce_simm_size; i++) {
		if (psimm[i].name[0] == '\0') {
			/*
			 * Hit the end of the valid entries, add
			 * a new one.
			 */
			(void) strncpy(psimm[i].name, unum, len);
			if (status & ECC_STICKY) {
				/*
				 * Sticky - the leaky bucket is used to track
				 * soft errors.  Since a sticky error is a
				 * hard error and likely to be retired soon,
				 * we do not count it in the leaky bucket.
				 */
				psimm[i].leaky_bucket_cnt = 0;
				psimm[i].intermittent_total = 0;
				psimm[i].persistent_total = 0;
				psimm[i].sticky_total = 1;
				cmn_err(CE_NOTE,
				    "[AFT0] Sticky Softerror encountered "
				    "on Memory Module %s\n", unum);
				page_status = PR_MCE;
			} else if (status & ECC_PERSISTENT) {
				psimm[i].leaky_bucket_cnt = 1;
				psimm[i].intermittent_total = 0;
				psimm[i].persistent_total = 1;
				psimm[i].sticky_total = 0;
			} else {
				/*
				 * Intermittent - Because the scrub operation
				 * cannot find the error in the DIMM, we will
				 * not count these in the leaky bucket
				 */
				psimm[i].leaky_bucket_cnt = 0;
				psimm[i].intermittent_total = 1;
				psimm[i].persistent_total = 0;
				psimm[i].sticky_total = 0;
			}
			ecc_error_info_data.count.value.ui32++;
			break;
		} else if (strncmp(unum, psimm[i].name, len) == 0) {
			/*
			 * Found an existing entry for the current
			 * memory module, adjust the counts.
			 */
			if (status & ECC_STICKY) {
				psimm[i].sticky_total++;
				cmn_err(CE_NOTE,
				    "[AFT0] Sticky Softerror encountered "
				    "on Memory Module %s\n", unum);
				page_status = PR_MCE;
			} else if (status & ECC_PERSISTENT) {
				int new_value;

				new_value = atomic_inc_16_nv(
				    &psimm[i].leaky_bucket_cnt);
				psimm[i].persistent_total++;
				if (new_value > ecc_softerr_limit) {
					cmn_err(CE_NOTE, "[AFT0] Most recent %d"
					    " soft errors from Memory Module"
					    " %s exceed threshold (N=%d,"
					    " T=%dh:%02dm) triggering page"
					    " retire", new_value, unum,
					    ecc_softerr_limit,
					    ecc_softerr_interval / 60,
					    ecc_softerr_interval % 60);
					atomic_dec_16(
					    &psimm[i].leaky_bucket_cnt);
					page_status = PR_MCE;
				}
			} else { /* Intermittent */
				psimm[i].intermittent_total++;
			}
			break;
		}
	}

	if (i >= mem_ce_simm_size)
		cmn_err(CE_CONT, "[AFT0] Softerror: mem_ce_simm[] out of "
		    "space.\n");

	return (page_status);
}

/*
 * Function to support counting of IO detected CEs.
 */
void
cpu_ce_count_unum(struct async_flt *ecc, int len, char *unum)
{
	int err;

	err = ce_count_unum(ecc->flt_status, len, unum);
	if (err != PR_OK && automatic_page_removal) {
		(void) page_retire(ecc->flt_addr, err);
	}
}

static int
ecc_kstat_update(kstat_t *ksp, int rw)
{
	struct kstat_ecc_mm_info *kceip = ksp->ks_data;
	struct ce_info *ceip = mem_ce_simm;
	int i = ksp->ks_instance;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ASSERT(ksp->ks_data != NULL);
	ASSERT(i < mem_ce_simm_size && i >= 0);

	/*
	 * Since we're not using locks, make sure that we don't get partial
	 * data. The name is always copied before the counters are incremented
	 * so only do this update routine if at least one of the counters is
	 * non-zero, which ensures that ce_count_unum() is done, and the
	 * string is fully copied.
	 */
	if (ceip[i].intermittent_total == 0 &&
	    ceip[i].persistent_total == 0 &&
	    ceip[i].sticky_total == 0) {
		/*
		 * Uninitialized or partially initialized. Ignore.
		 * The ks_data buffer was allocated via kmem_zalloc,
		 * so no need to bzero it.
		 */
		return (0);
	}

	kstat_named_setstr(&kceip->name, ceip[i].name);
	kceip->intermittent_total.value.ui64 = ceip[i].intermittent_total;
	kceip->persistent_total.value.ui64 = ceip[i].persistent_total;
	kceip->sticky_total.value.ui64 = ceip[i].sticky_total;

	return (0);
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

/*ARGSUSED*/
void
mmu_init_kernel_pgsz(struct hat *hat)
{
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
