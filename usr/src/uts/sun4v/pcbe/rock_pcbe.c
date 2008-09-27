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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Rock Performance Counter Back End
 */

#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/modctl.h>
#include <sys/machsystm.h>
#include <sys/sdt.h>
#include <sys/hypervisor_api.h>
#include <sys/rock_hypervisor_api.h>
#include <sys/hsvc.h>

#define	NT_END			0xFF

#define	CPC_COUNT_HPRIV		0x8

/* Counter Types */
#define	NUM_PCBE_COUNTERS	7
#define	RK_PERF_CYC		0x0100
#define	RK_PERF_INSTR		0x0200
#define	RK_PERF_L2		0x0400
#define	RK_PERF_MMU		0x0800
#define	RK_PERF_YANK		0x2000
#define	RK_PERF_SIBLK		0x4000
#define	RK_PERF_LVLK		0x8000
#define	RK_PERF_SPEC		0x1000	/* Reserved */

#define	NORMAL_COUNTER		0x1
#define	SYNTHETIC_COUNTER	0x2

/* ASI_PERF_MMU_CNT_FILTER TXN bits */
#define	ASI_PERF_MMU_CNT_FILTER_UTLB_HITS	0x1
#define	ASI_PERF_MMU_CNT_FILTER_UTLB_MISS	0x2
#define	ASI_PERF_MMU_CNT_FILTER_DATA_ACCESS	0x8
#define	ASI_PERF_MMU_CNT_FILTER_INSTR_ACCESS	0x10
#define	ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL	0x20
#define	ASI_PERF_MMU_CNT_FILTER_EA_REAL		0x40

#define	MMU_ALL_TXNS		(ASI_PERF_MMU_CNT_FILTER_UTLB_HITS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_MISS | \
				ASI_PERF_MMU_CNT_FILTER_DATA_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_INSTR_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_REAL)

#define	MMU_ITLB_MISS		(ASI_PERF_MMU_CNT_FILTER_EA_REAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_INSTR_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_MISS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_HITS)

#define	MMU_DTLB_MISS		(ASI_PERF_MMU_CNT_FILTER_EA_REAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_DATA_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_MISS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_HITS)

#define	MMU_UTLB_MISS		(ASI_PERF_MMU_CNT_FILTER_EA_REAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_INSTR_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_DATA_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_MISS)

#define	MMU_UTLB_HIT		(ASI_PERF_MMU_CNT_FILTER_EA_REAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_INSTR_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_DATA_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_HITS)

#define	MMU_ITLB_MISS_UTLB_HIT	(ASI_PERF_MMU_CNT_FILTER_EA_REAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_INSTR_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_HITS)

#define	MMU_ITLB_MISS_UTLB_MISS	(ASI_PERF_MMU_CNT_FILTER_EA_REAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_INSTR_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_MISS)

#define	MMU_DTLB_MISS_UTLB_HIT	(ASI_PERF_MMU_CNT_FILTER_EA_REAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_DATA_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_HITS)

#define	MMU_DTLB_MISS_UTLB_MISS	(ASI_PERF_MMU_CNT_FILTER_EA_REAL | \
				ASI_PERF_MMU_CNT_FILTER_EA_VIRTUAL | \
				ASI_PERF_MMU_CNT_FILTER_DATA_ACCESS | \
				ASI_PERF_MMU_CNT_FILTER_UTLB_MISS)

/*
 * These values will be loaded to nametable.bits which is a 32 bit number.
 * Please see the description of bits in nametable struct. If the counters
 * are a part of different pic, then we can re-use GROUP and TYPE.
 */
#define	SYN_BIT			((uint32_t)1 << 31)	/* Set bit 32 */
#define	GROUP_MASK		0xFFF000		/* Bits 12-23 */
#define	ID_TO_GROUP(GROUP_ID)	((GROUP_ID)<<12)
#define	GROUP(SYN_COUNTER)	((SYN_COUNTER) & GROUP_MASK)
#define	TYPE(SYN_COUNTER)   ((SYN_COUNTER) & 0x000FFF)	/* Bits 0-12 */

/* Synthetic counter types */
#define	L2_GROUP_DS		ID_TO_GROUP(0)
#define	DS_DRAM		0x0
#define	DS_L3		0x1
#define	DS_OTHER_L2	0x2
#define	DS_LOCAL_L2	0x3
#define	DS_MISS		0x4

#define	L2_DS_DRAM		(SYN_BIT | L2_GROUP_DS | DS_DRAM)
#define	L2_DS_L3		(SYN_BIT | L2_GROUP_DS | DS_L3)
#define	L2_DS_OTHER_L2		(SYN_BIT | L2_GROUP_DS | DS_OTHER_L2)
#define	L2_DS_LOCAL_L2		(SYN_BIT | L2_GROUP_DS | DS_LOCAL_L2)
#define	L2_DS_MISS		(SYN_BIT | L2_GROUP_DS | DS_MISS)

#define	TXN_LD			0x3
#define	TXN_ST			0x18
#define	L2_GROUP_TXN_MISS	ID_TO_GROUP(1)
#define	L2_TXN_LD_MISS		(SYN_BIT | L2_GROUP_TXN_MISS | TXN_LD)
#define	L2_TXN_ST_MISS		(SYN_BIT | L2_GROUP_TXN_MISS | TXN_ST)

#define	L2_GROUP_TXN_HIT	ID_TO_GROUP(2)
#define	L2_TXN_LD_HIT		(SYN_BIT | L2_GROUP_TXN_HIT | TXN_LD)
#define	L2_TXN_ST_HIT		(SYN_BIT | L2_GROUP_TXN_HIT | TXN_ST)

#define	L2_GROUP_EVT		ID_TO_GROUP(3)
#define	EVT_L2_NOEVENTS		0
#define	EVT_L2_PEND_ST		2
#define	EVT_L2_HIT		0
#define	L2_EVT_HIT		(SYN_BIT | L2_GROUP_EVT | EVT_L2_HIT)

/* Instruction types. Corresponds to ASI_PERF_IS_INFO.TYP */
#define	I_GROUP_TYPE		ID_TO_GROUP(0)
#define	TYPE_HELPER		(1<<0)
#define	TYPE_LD			(1<<1)
#define	TYPE_ST			(1<<2)
#define	TYPE_CTI		(1<<3)
#define	TYPE_FP			(1<<4)
#define	TYPE_INT_ALU		(1<<5)
#define	TYPE_CMPLX_ALU		(1<<6)

#define	INSTR_TYPE_LD		(SYN_BIT | I_GROUP_TYPE | TYPE_LD)
#define	INSTR_TYPE_ST		(SYN_BIT | I_GROUP_TYPE | TYPE_ST)
#define	INSTR_TYPE_CTI		(SYN_BIT | I_GROUP_TYPE | TYPE_CTI)
#define	INSTR_TYPE_FP		(SYN_BIT | I_GROUP_TYPE | TYPE_FP)

/* Execution modes. Corresponds to ASI_PERF_IS_INFO.MODE */
#define	I_GROUP_MODE		ID_TO_GROUP(1)
#define	MODE_NOR		0x0	/* From PRM */
#define	MODE_OOO		0x1	/*   ditto  */
#define	MODE_EXE		0x2	/*   ditto  */
#define	MODE_DLY		0x3	/*   ditto  */
#define	MODE_DEF		0x4	/*   ditto  */
#define	MODE_HWS		0x5	/*   ditto  */

#define	INSTR_MODE_NOR		(SYN_BIT | I_GROUP_MODE | MODE_NOR)
#define	INSTR_MODE_OOO		(SYN_BIT | I_GROUP_MODE | MODE_OOO)
#define	INSTR_MODE_EXE		(SYN_BIT | I_GROUP_MODE | MODE_EXE)
#define	INSTR_MODE_DLY		(SYN_BIT | I_GROUP_MODE | MODE_DLY)
#define	INSTR_MODE_DEF		(SYN_BIT | I_GROUP_MODE | MODE_DEF)
#define	INSTR_MODE_HWS		(SYN_BIT | I_GROUP_MODE | MODE_HWS)

/* Instruction events. Corresponds to ASI_PERF_IS_INFO.EVT */
#define	I_GROUP_EVT		ID_TO_GROUP(2)

/* Bit numbers from PRM  */
#define	EVT_DC_MISS		(1<<0)
#define	EVT_PRIOR_MISS		(1<<1)
#define	EVT_DTLB_MISS		(1<<2)
#define	EVT_LDB_FULL		(1<<3)
#define	EVT_STB_FULL		(1<<4)
#define	EVT_FE_STALL		(1<<5)
#define	EVT_FROM_DQ		(1<<6)
#define	EVT_CORRECT_BP		(1<<7)
#define	EVT_BYPASS_RAW		(1<<8)
#define	EVT_NONBYPASS_RAW	(1<<9)
#define	EVT_CTI_TAKEN		(1<<10)
#define	EVT_FAILED_SPEC		(1<<11)

#define	INSTR_EVT_DC_MISS	(SYN_BIT | I_GROUP_EVT | EVT_DC_MISS)
#define	INSTR_EVT_PRIOR_MISS	(SYN_BIT | I_GROUP_EVT | EVT_PRIOR_MISS)
#define	INSTR_EVT_DTLB_MISS	(SYN_BIT | I_GROUP_EVT | EVT_DTLB_MISS)
#define	INSTR_EVT_LDB_FULL	(SYN_BIT | I_GROUP_EVT | EVT_LDB_FULL)
#define	INSTR_EVT_STB_FULL	(SYN_BIT | I_GROUP_EVT | EVT_STB_FULL)
#define	INSTR_EVT_FE_STALL	(SYN_BIT | I_GROUP_EVT | EVT_FE_STALL)
#define	INSTR_EVT_FROM_DQ	(SYN_BIT | I_GROUP_EVT | EVT_FROM_DQ)
#define	INSTR_EVT_CORRECT_BP	(SYN_BIT | I_GROUP_EVT | EVT_CORRECT_BP)
#define	INSTR_EVT_BYPASS_RAW	(SYN_BIT | I_GROUP_EVT | EVT_BYPASS_RAW)
#define	INSTR_EVT_NONBYPASS_RAW	(SYN_BIT | I_GROUP_EVT | EVT_NONBYPASS_RAW)
#define	INSTR_EVT_CTI_TAKEN	(SYN_BIT | I_GROUP_EVT | EVT_CTI_TAKEN)
#define	INSTR_EVT_FAILED_SPEC	(SYN_BIT | I_GROUP_EVT | EVT_FAILED_SPEC)

/*
 * Synthetic counters to count MCCDESR error events
 * All the events are mutually exclusive therefore can be counted
 * simultaneously. Hence each one is a different pic. Therefore
 * there is no need to have GROUP or TYPE for these counters.
 */
#define	MCCDESR_YANK		(SYN_BIT)
#define	MCCDESR_SIBLK		(SYN_BIT)
#define	MCCDESR_LVLK		(SYN_BIT)

/* Number of samples to be taken before Performance Event Trap is generated */
/* Maximum frequencies that can be configured */
#define	INSTR_SAM_MAX_FREQ	0x3FF	/* 10 bits */
#define	L2_SAM_MAX_FREQ		0xFFFF	/* 16 bits */
#define	MMU_SAM_MAX_FREQ	0xFFFF	/* 16 bits */

/* Minimum frequencies that should be configured to prevent DOS */
#define	INSTR_SAM_MIN_FREQ	50
#define	L2_SAM_MIN_FREQ		250
#define	MMU_SAM_MIN_FREQ	250

/* Default frequencies that are configured */
#define	INSTR_MODE_FREQ		100
#define	L2_DS_FREQ		10000
#define	L2_LOAD_FRM_OTH_L2_FREQ	1000
#define	L2_MISS_FREQ		1000
#define	L2_HIT_FREQ		5000

/* Number of bits in the hardware for the counter */
#define	CYC_COUNTER_BITS	39
#define	INSTR_COUNTER_BITS	39
#define	L2_COUNTER_BITS		48
#define	MMU_COUNTER_BITS	48
#define	YANK_COUNTER_BITS	64
#define	SIBLK_COUNTER_BITS	64
#define	LVLK_COUNTER_BITS	64

#define	RK_PERF_COUNT_TOE_SHIFT	(63)

#define	STATE_CONFIGURED	0x1
#define	STATE_PROGRAMMED	0x2
#define	STATE_STOPPED		0x4
#define	STATE_RELEASED		0x8
#define	UNINITIALIZED		2 /* should be other than 0/1 */
#define	TLZ			1 /* Do not make it zero */
#define	TLNZ			2

#define	CPU_REF_URL " Documentation for Sun processors can be found at: " \
			"http://www.sun.com/processors/manuals"

#define	MIN_RINGBUF_ENTRIES	100

#define	RINGBUF_GET_HEAD(RB)		\
	(RB->head == RB->tail) ? NULL : \
	(uint64_t *)((uint64_t)(&RB->va_values) + RB->head);

#define	RINGBUF_SET_HEAD(RB)			\
	RB->hwm = RB->tail + (RB->size >> 1);	\
	if (RB->hwm >= RB->size)		\
		RB->hwm -= RB->size;		\
	RB->head = RB->tail;

#define	RINGBUF_MOVE_HEAD(RB, PTR, SAMPLE_SZ)				\
	PTR = (uint64_t *)((uint64_t)PTR + SAMPLE_SZ);			\
	if (PTR >= (uint64_t *)((uint64_t)(&RB->va_values) + RB->size))	\
		PTR = (uint64_t *)&RB->va_values;			\
	if (PTR == (uint64_t *)((uint64_t)(&RB->va_values) + RB->tail))	\
		PTR = NULL;

#define	MAKE_MASK(NBITS, SHIFT)	(((unsigned long)(1<<(NBITS))-1)<<SHIFT)

/* Global Structures and typedefs */
struct	_rk_pcbe_ringbuf {	/*	  INIT-ER	WRITTER	  READER */
	uint32_t	head;	/* offset  guest	guest	  guest	 */
	uint32_t	tail;	/* offset  guest	hv	   both	 */
	uint32_t	size;	/* bytes   guest	n/a	   both	 */
	uint32_t	hwm;	/* bytes   guest	hv	  guest  */
	uint64_t	va_values; /*	   guest	hv	  guest  */
};

typedef	struct _rk_pcbe_ringbuf rk_pcbe_ringbuf_t;

typedef	struct _sampler {
	rk_pcbe_ringbuf_t *ring_buffer;	/* Ring buffer start address */
	uint64_t	synthetic_pic;
	uint32_t	frequency;	/* Sampling Frequency */
	uint32_t	syn_counter;	/* Synthetic Counter Type */
	uint32_t	sample_size;	/* Size of each sample in bytes */
	uint32_t	flags;		/* instr sampler: priv */
	uint8_t		tl;		/* Trap Level Filtering */
	uint8_t		nohws;		/* Filter out HW Scouting samples */
} sampler_t;

typedef struct _rk_pcbe_config {
	uint8_t		pcbe_picno;	/* 0:cyc, 1:instr, 2:l2, 3:mmu */
	uint8_t		counter_bits;	/* Number of counter bits */
	uint8_t		counter_type;	/* Normal or Synthetic */
	uint8_t		toe;		/* Trap on Enable */
	uint32_t	counter;	/* Counter name */
	uint32_t	src_type;	/* Strand, Strands, SIU, MMU */
	uint32_t	flags;		/* cyc,instr counter:priv. l2,mmu:Xn */
	uint64_t	pcbe_pic;	/* PIC counter value */
	uint8_t		inuse;		/* pic in use or not */
	uint8_t		state;		/* Current state of the pic */
	processorid_t	cpu;		/* CPU associated to this pic */
	sampler_t	sampler;
#ifdef	RKPCBE_DBG
	char		name[64];	/* Human readable counter name */
#endif
} rk_pcbe_config_t;

/* Function Prototypes for those that are invoked using rk_pcbe_ops */
static int rk_pcbe_init(void);
static int rk_pcbe_fini(void);
static uint_t rk_pcbe_ncounters(void);
static const char *rk_pcbe_impl_name(void);
static const char *rk_pcbe_cpuref(void);
static char *rk_pcbe_list_events(uint_t picnum);
static char *rk_pcbe_list_attrs(void);
static uint64_t rk_pcbe_event_coverage(char *event);
static uint64_t rk_pcbe_overflow_bitmap(void);
static int rk_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void rk_pcbe_program(void *token);
static void rk_pcbe_allstop(void);
static void rk_pcbe_sample(void *token);
static void rk_pcbe_free(void *config);

pcbe_ops_t rk_pcbe_ops = {
	PCBE_VER_1,
	CPC_CAP_OVERFLOW_INTERRUPT,
	rk_pcbe_ncounters,
	rk_pcbe_impl_name,
	rk_pcbe_cpuref,
	rk_pcbe_list_events,
	rk_pcbe_list_attrs,
	rk_pcbe_event_coverage,
	rk_pcbe_overflow_bitmap,
	rk_pcbe_configure,
	rk_pcbe_program,
	rk_pcbe_allstop,
	rk_pcbe_sample,
	rk_pcbe_free
};

/*
 * bits:
 *
 * |     31     |30        24|23      12|11      0
 * | Syn/Normal |    Rsvd    |  Group   |  Type  |
 */
struct nametable {
	const uint32_t	bits;
	const char	*name;
};

/* Cycle Counter. picno: 0 */
static const struct nametable Rock_names0[] = {
	{0x1, "Cycles"},
	{NT_END, ""}
};

/* Instruction Counter. picno: 1 */
static const struct nametable Rock_names1[] = {
	{0x1, "Instr_All"},
	/* Synthetic counters */
	{INSTR_MODE_NOR, "Instr_Normal"},
	{INSTR_MODE_OOO, "Instr_Out_Of_Order"},
	{INSTR_MODE_EXE, "Instr_Execute_Ahead"},
	{INSTR_MODE_DLY, "Instr_Delay"},
	{INSTR_MODE_DEF, "Instr_Deferred"},
	{INSTR_MODE_HWS, "Instr_Scout"},

	{INSTR_TYPE_LD,  "Instr_Load"},
	{INSTR_TYPE_ST,  "Instr_Store"},
	{INSTR_TYPE_CTI, "Instr_Branch"},
	{INSTR_TYPE_FP,  "Instr_Float"},

	{INSTR_EVT_DC_MISS,	"Instr_Dcache_Miss"},
	{INSTR_EVT_PRIOR_MISS,	"Instr_Prior_Miss"},
	{INSTR_EVT_DTLB_MISS,	"Instr_Dtlb_Miss"},
	{INSTR_EVT_LDB_FULL,	"Instr_Loadbuf_Full"},
	{INSTR_EVT_STB_FULL,	"Instr_Storebuf_Full"},
	{INSTR_EVT_FE_STALL,	"Instr_Stall"},
	{INSTR_EVT_FROM_DQ,	"Instr_DQ"},
	{INSTR_EVT_CORRECT_BP,	"Instr_Correct_Branch_Predict"},
	{INSTR_EVT_BYPASS_RAW,	"Instr_Bypass_Raw"},
	{INSTR_EVT_NONBYPASS_RAW, "Instr_Nonbypass_Raw"},
	{INSTR_EVT_CTI_TAKEN, 	"Instr_Branch_Taken"},
	{INSTR_EVT_FAILED_SPEC,	"Instr_Failed_Spec"},

	{NT_END, ""}
};

/* L2 Counters. picno: 2 */
static const struct nametable Rock_names2[] = {
	{0x1,			"L2_Icache_Load"},
	{0x2,			"L2_Dcache_Load"},
	{0x4,			"L2_Instr_Prefetch"},
	{0x8,			"L2_Store_Prefetch"},
	{0x10,			"L2_Store"},
	{0x20,			"L2_Atomic_Ops"},
	{0x40,			"L2_Flush"},
	/* Synthetic counters */
	{L2_DS_L3,		"L2_Load_From_L3"},
	{L2_DS_DRAM,		"L2_Load_From_Dram"},
	{L2_DS_OTHER_L2,	"L2_Load_From_Other_L2"},
	{L2_DS_MISS,		"L2_Miss"},

	{L2_TXN_LD_MISS,	"L2_Load_Miss"},
	{L2_TXN_ST_MISS,	"L2_Store_Miss"},
	{L2_TXN_LD_HIT,		"L2_Load_Hit"},
	{L2_TXN_ST_HIT,		"L2_Store_Hit"},

	{L2_EVT_HIT,		"L2_Hit"},
	{NT_END, ""}
};

/* MMU Counters. picno: 3 */
static const struct nametable Rock_names3[] = {
	{MMU_ALL_TXNS,			"MMU_All"},
	{MMU_ITLB_MISS,			"MMU_Itlb_Miss"},
	{MMU_DTLB_MISS,			"MMU_Dtlb_Miss"},
	{MMU_UTLB_MISS,			"MMU_Utlb_Miss"},
	{MMU_UTLB_HIT,			"MMU_Utlb_Hit"},
	{MMU_ITLB_MISS_UTLB_MISS,	"MMU_I_Utlb_Miss"},
	{MMU_ITLB_MISS_UTLB_HIT,	"MMU_I_Utlb_Hit"},
	{MMU_DTLB_MISS_UTLB_MISS,	"MMU_D_Utlb_Miss"},
	{MMU_DTLB_MISS_UTLB_HIT,	"MMU_D_Utlb_Hit"},
	{NT_END, ""}
};

/* YANK Counter. picno: 4 */
static const struct nametable Rock_names4[] = {
	{MCCDESR_YANK,			"Yank"},
	{NT_END, ""}
};

/* SIBLK Counter. picno: 5 */
static const struct nametable Rock_names5[] = {
	{MCCDESR_SIBLK,			"Siblk"},
	{NT_END, ""}
};

/* LVLK Counter. picno: 6 */
static const struct nametable Rock_names6[] = {
	{MCCDESR_LVLK,			"Lvlk"},
	{NT_END, ""}
};

static const struct nametable *Rock_names[NUM_PCBE_COUNTERS] = {
	Rock_names0,
	Rock_names1,
	Rock_names2,
	Rock_names3,
	Rock_names4,
	Rock_names5,
	Rock_names6
};

extern	char	cpu_module_name[];
uint32_t num_ringbuf_entries = 256; /* Should be a EVEN # */
static const struct nametable **events;
static char *pic_events[NUM_PCBE_COUNTERS];
static rk_pcbe_config_t *active_pics[NUM_PCBE_COUNTERS][NCPU];
static	boolean_t	rock_pcbe_hsvc_available = B_TRUE;

static	char	*rock_name;
static	char	rock_cpuref[256];
static	char	pcbe_module_name[64] = "pcbe.";

static hsvc_info_t rock_pcbe_hsvc = {
	HSVC_REV_1,		/* HSVC rev num */
	NULL,			/* Private */
	HSVC_GROUP_RKPERF,	/* Requested API Group */
	ROCK_HSVC_MAJOR,	/* Requested Major */
	ROCK_HSVC_MINOR,	/* Requested Minor */
	pcbe_module_name	/* Module name */
};

/* Function Definitions */
static struct modlpcbe modlpcbe = {
	&mod_pcbeops,
	"Perf Counters v1.1",
	&rk_pcbe_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modlpcbe,
};

/* Local Function prototypes */
static void rk_pcbe_stop_synthetic(rk_pcbe_config_t *pic);
static void rk_pcbe_release(rk_pcbe_config_t *pic);
static void rk_pcbe_free_synthetic(rk_pcbe_config_t *pic);

static int rk_pcbe_program_normal(rk_pcbe_config_t *pic);
static int rk_pcbe_program_synthetic(rk_pcbe_config_t *pic);
static int program_l2_sampler(rk_pcbe_config_t *pic);
static int program_instr_sampler(rk_pcbe_config_t *pic);

static int rk_pcbe_sample_synthetic(rk_pcbe_config_t *pic, int64_t *diffp);
static int sample_l2_sampler(rk_pcbe_config_t *pic, int64_t *diffp);
static int sample_instr_sampler(rk_pcbe_config_t *pic, int64_t *diffp);
static int sample_mccdesr(rk_pcbe_config_t *pic, int64_t *diffp);

static void alloc_ringbuffer(rk_pcbe_config_t *pic, uint32_t size,
							uint32_t num_samples);
static void free_ringbuffer(rk_pcbe_config_t *pic);
static void print_hv_error(uint64_t rc, int *cntp, char *funcname,
					rk_pcbe_config_t *pic);
static	void set_string_constants(void);

#ifdef	RKPCBE_DBG
static void print_pic(rk_pcbe_config_t *pic, char *heading);
static void set_pic_name(rk_pcbe_config_t *pic);
/* lock for print clarity */
static kmutex_t print_pic_lock;
#define	PRINT_PIC(pic, heading)	\
	print_pic(pic, heading)
#define	DBG_PRINT(_z) printf _z
#else
#define	PRINT_PIC(pic, heading) (void)0
#define	DBG_PRINT(ignore) (void)0
#endif

int
_init(void)
{
	if (rk_pcbe_init() != 0)
		return (ENOTSUP);
	return (mod_install(&modl));
}

int
_fini(void)
{
	if (rk_pcbe_fini() != 0)
		return (EBUSY);
	return (mod_remove(&modl));
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&modl, mi));
}

static int
rk_pcbe_init(void)
{
	const struct 	nametable	*n;
	int		i, status, j;
	size_t		size;
	uint64_t	rock_pcbe_hsvc_sup_minor;

	set_string_constants();
	/*
	 * Validate API version for Rock pcbe hypervisor services
	 */
	status = hsvc_register(&rock_pcbe_hsvc, &rock_pcbe_hsvc_sup_minor);
	if ((status != 0) || (rock_pcbe_hsvc_sup_minor <
	    (uint64_t)ROCK_HSVC_MINOR)) {
		cmn_err(CE_WARN, "%s cannot negotiate hypervisor services: "
		    "major: 0x%lx minor: 0x%lx group: 0x%x errno: %d",
		    pcbe_module_name, rock_pcbe_hsvc.hsvc_major,
		    rock_pcbe_hsvc.hsvc_minor, HSVC_GROUP_RKPERF, status);
		rock_pcbe_hsvc_available = B_FALSE;
		return (-1);
	}

	events = Rock_names;
	/*
	 * Initialize the list of events for each PIC.
	 * Do two passes: one to compute the size necessary and another
	 * to copy the strings. Need room for event, comma, and NULL terminator.
	 */
	for (i = 0; i < NUM_PCBE_COUNTERS; i++) {
		size = 0;
		for (n = events[i]; n->bits != NT_END; n++)
			size += strlen(n->name) + 1;
		pic_events[i] = kmem_alloc(size + 1, KM_SLEEP);
		*pic_events[i] = '\0';
		for (n = events[i]; n->bits != NT_END; n++) {
			(void) strcat(pic_events[i], n->name);
			(void) strcat(pic_events[i], ",");
		}
		/*
		 * Remove trailing comma.
		 */
		pic_events[i][size - 1] = '\0';

		/* Initialize all active pics as NULL */
		for (j = 0; j < NCPU; j++)
			active_pics[i][j] = NULL;
	}
#ifdef	RKPCBE_DBG
	mutex_init(&print_pic_lock, NULL, MUTEX_DRIVER,
	    (void *)ipltospl(PIL_15));
#endif
	return (0);
}

static	int
rk_pcbe_fini(void)
{
	return (0);
}

static uint_t
rk_pcbe_ncounters(void)
{
	return (NUM_PCBE_COUNTERS);
}

static const char *
rk_pcbe_impl_name(void)
{
	return (rock_name);
}

static const char *
rk_pcbe_cpuref(void)
{
	return (rock_cpuref);
}

static char *
rk_pcbe_list_events(uint_t picnum)
{
	ASSERT(picnum >= (uint_t)0 && picnum < cpc_ncounters);

	return (pic_events[picnum]);
}

static char *
rk_pcbe_list_attrs(void)
{
	/*
	 * If no value is spcified in the command line for the
	 * attributes then, a default value of 1 is passed into
	 * pcbe from cpc. Specifying a value as zero is as good as
	 * not specifying it.
	 * 'source' attribute is equivallent of 'single, shared,
	 * siu, mmu' all put together. 'source' will take precedence
	 * over others.
	 * Valid 'source' values are defined in rock_hypervisor_api.h.
	 * If multiple flags need to be specified then user has to
	 * specify the bitwise OR of the flags he/she is interested in.
	 * populate_pic_config validates the correctness of the flags
	 * specified.
	 * tl is little odd. To consider instructions at
	 * tl == 0, specify tl = TLZ in command line
	 * tl > 0, specify tl = TLNZ in command line
	 * The reason for this oddness: attr = 0 means, neglect
	 * that attr.
	 */
	return ("freq,source,single,shared,siu,mmu,nohws,tl,hpriv");
}

static const struct nametable *
find_event(int picno, char *name)
{
	const struct nametable *n;

	for (n = events[picno]; n->bits != NT_END; n++)
		if (strcmp(name, n->name) == 0)
			return (n);

	return (NULL);
}

static uint64_t
rk_pcbe_event_coverage(char *event)
{
	uint64_t	bitmap = 0;
	int 		i;

	/* There is no intersection of events between different PICs */
	for (i = 0; i <  NUM_PCBE_COUNTERS; i++) {
		if (find_event(i, event) != NULL) {
			bitmap = 1 << i;
			break;
		}
	}
	return (bitmap);
}

static uint64_t
rk_pcbe_overflow_bitmap(void)
{
	int 			i;
	rk_pcbe_config_t	*pic;
	uint64_t		ovf_bitmask = 0, ovf_cnt;

	for (i = 0; i <  NUM_PCBE_COUNTERS; i++) {
		pic = active_pics[i][CPU->cpu_id];

		if (pic == NULL || pic->inuse != B_TRUE)
			continue;

		DBG_PRINT(("CPU-%d: Pic %s (#%d, cntr %X) overflowed\n",
		    CPU->cpu_id, pic->name, pic->pcbe_picno, pic->counter));

		/* Check if any of the active pics overflowed */
		if (pic->counter_type == NORMAL_COUNTER) {
			hv_rk_perf_count_overflow((uint64_t)(pic->counter |
			    pic->src_type), &ovf_cnt);
		} else {
		/*
		 * Synthetic counters don't overflow, so we must have gotten
		 * here because the ringbuffer is getting half-full or
		 * one of the normal counter which is a part of synthetic
		 * counter did overflow. Force cpc to call
		 * rk_pcbe_sample_synthetic by setting ovf_cnt to 1. If
		 * returned 0, then cpc prints a WARNING message:
		 * "WARNING: interrupt 0x80c at level 15 not serviced"
		 */
			ovf_cnt = B_TRUE;
		}

		if (ovf_cnt > 0)
			ovf_bitmask |= (1 << pic->pcbe_picno);
	}
	return (ovf_bitmask);
}

/*
 * populate_pic_config
 *
 * Checks the validity of all the attributes and then updates flags
 * to reflect priv bits for Cycle and Instruction counters and
 * transaction bits for L2 and makes sure that flags is 0 for MMU.
 *
 * Along with validating the inputs, pic is populated with appropriate
 * values.
 *
 * Returns 0 on success and CPC_INVALID_ATTRIBUTE on failure.
 */
static int
populate_pic_config(uint_t picnum, uint_t nattrs, kcpc_attr_t *attrs,
				uint32_t bits, rk_pcbe_config_t *pic)
{
	int 		i;
	uint32_t	freq = 0;
	uint32_t	*flagsp = &(pic->flags);
	uint32_t	source = 0;

	pic->pcbe_picno = (uint8_t)picnum;
	pic->toe = B_TRUE;
	pic->sampler.synthetic_pic = 0;
	pic->sampler.ring_buffer = NULL;
	pic->inuse = UNINITIALIZED;
	pic->counter_type = ((bits & SYN_BIT) == 0) ? NORMAL_COUNTER :
	    SYNTHETIC_COUNTER;

	/*
	 * Initialized to 0. If a valid source attribute is specified, then
	 * src_type field gets populated later, else will be defaulted to
	 * HV_RK_PERF_SRC_STRAND
	 */
	pic->src_type = 0;
	/*
	 * Initialized to zero. In all the fallthrough case, this
	 * is checked to determine if certain fields needs to be
	 * populated or not
	 */
	pic->counter = 0;

	switch (picnum) {
#define	PRIV_BITS_MASK	0x7
#define	PRIV_BIT0_MASK	0x1
#define	PRIV_BIT1_MASK	0x2
#define	PRIV_BIT2_MASK	0x4

		case 0:	/* Cycle counter */
			pic->counter = RK_PERF_CYC;
			pic->counter_bits = CYC_COUNTER_BITS;
			/* FALLTHROUGH */
		case 1:	/* Instruction Counter */
			if (pic->counter == 0) {
				pic->counter = RK_PERF_INSTR;
				pic->counter_bits = INSTR_COUNTER_BITS;
			}

			freq = INSTR_MODE_FREQ;
			for (i = 0; i < nattrs; i++) {
				if ((strcmp(attrs[i].ka_name, "freq") == 0)) {
					if ((bits & SYN_BIT) == 0 &&
					    attrs[i].ka_val) {
						return (CPC_INVALID_ATTRIBUTE);
					}
					freq = attrs[i].ka_val;
				} else if ((strcmp(attrs[i].ka_name,
				    "single") == 0) && attrs[i].ka_val)
					pic->src_type |=
					    HV_RK_PERF_SRC_STRAND;
				else if ((strcmp(attrs[i].ka_name,
				    "shared") == 0) && attrs[i].ka_val)
					pic->src_type |=
					    HV_RK_PERF_SRC_STRAND_M;
				else if ((strcmp(attrs[i].ka_name,
				    "hpriv") == 0) && attrs[i].ka_val)
					*flagsp |= CPC_COUNT_HPRIV;
				else if ((strcmp(attrs[i].ka_name,
				    "source") == 0) && attrs[i].ka_val)
					source = attrs[i].ka_val &
					    HV_RK_PERF_SRC_MASK;
				else if ((strcmp(attrs[i].ka_name,
				    "nohws") == 0) && attrs[i].ka_val) {
					if (bits & SYN_BIT)
						pic->sampler.nohws = B_TRUE;
					else if (attrs[i].ka_val)
						return (CPC_INVALID_ATTRIBUTE);
				} else if ((strcmp(attrs[i].ka_name,
				    "tl") == 0) && attrs[i].ka_val) {
					if (bits & SYN_BIT) {
						pic->sampler.tl =
						    (uint8_t)attrs[i].ka_val;
					} else if (attrs[i].ka_val)
						return (CPC_INVALID_ATTRIBUTE);
				} else {
					if (attrs[i].ka_val)
						return (CPC_INVALID_ATTRIBUTE);
				}
			}

			if (source) {
				if (source & (HV_RK_PERF_SRC_SIU |
				    HV_RK_PERF_SRC_MMU))
					return (CPC_INVALID_ATTRIBUTE);
				pic->src_type = source;
			}

			if (pic->src_type == 0)
				pic->src_type = HV_RK_PERF_SRC_STRAND;

			/*
			 * hpriv, sys, user are sent as bits 3, 2, 1 from kcpc.
			 * They are maintained by PCBE as bits 2, 1, & 0.
			 */
			*flagsp >>= 1;
			*flagsp &= PRIV_BITS_MASK;
			if (bits & SYN_BIT) {
				pic->sampler.flags = *flagsp;
				pic->sampler.syn_counter = bits;
				if (freq > INSTR_SAM_MAX_FREQ) {
					cmn_err(CE_NOTE, "CPU-%d: freq set "
					    "> MAX. Resetting to %d",
					    CPU->cpu_id, INSTR_SAM_MAX_FREQ);
					freq = INSTR_SAM_MAX_FREQ;
				}
				if (freq < INSTR_SAM_MIN_FREQ) {
					cmn_err(CE_NOTE, "CPU-%d: freq set "
					    "< MIN. Resetting to %d",
					    CPU->cpu_id, INSTR_SAM_MIN_FREQ);
					freq = INSTR_SAM_MIN_FREQ;
				}
				pic->sampler.frequency = freq;
			}
			/*
			 * When programming counter priv bits should be
			 * 0, 1, & 2, i.e., in reverse order. Therefore swap
			 * bits 2 & 0.
			 */
			*flagsp = ((*flagsp & PRIV_BIT0_MASK) << 2) |
			    ((*flagsp & PRIV_BIT2_MASK) >> 2) |
			    (*flagsp & PRIV_BIT1_MASK);
			break;
		case 2:	/* L2 counter */
			/*
			 * nouser and sys are also invalid attributes for L2
			 * and MMU counters. If user has not specified any
			 * attributes then *flagsp contains CPC_COUNT_USER.
			 * Any priv attrs are not applicable for L2 counters.
			 */
			if (*flagsp != CPC_COUNT_USER)
				return (CPC_INVALID_ATTRIBUTE);

			pic->counter_bits = L2_COUNTER_BITS;
			if ((bits & SYN_BIT) == 0) {
				/*
				 * Normal counter:
				 * Find the attibutes for L2 Counter.
				 */
				for (i = 0; i < nattrs; i++) {
					if ((strcmp(attrs[i].ka_name,
					    "single") == 0) && attrs[i].ka_val)
						pic->src_type |=
						    HV_RK_PERF_SRC_STRAND;
					else if ((strcmp(attrs[i].ka_name,
					    "shared") == 0) && attrs[i].ka_val)
						pic->src_type |=
						    HV_RK_PERF_SRC_STRAND_M;
					else if ((strcmp(attrs[i].ka_name,
					    "siu") == 0) && attrs[i].ka_val)
						pic->src_type |=
						    HV_RK_PERF_SRC_SIU;
					else if ((strcmp(attrs[i].ka_name,
					    "mmu") == 0) && attrs[i].ka_val)
						pic->src_type |=
						    HV_RK_PERF_SRC_MMU;
					else if ((strcmp(attrs[i].ka_name,
					    "source") == 0) && attrs[i].ka_val)
						source = attrs[i].ka_val &
						    HV_RK_PERF_SRC_MASK;
					else if (attrs[i].ka_val)
						return (CPC_INVALID_ATTRIBUTE);
				}
				if (source)
					pic->src_type = source;

				if (pic->src_type == 0)
					pic->src_type = HV_RK_PERF_SRC_STRAND;

				/* At least one hot Xn flag for L2 counters */
				*flagsp = bits;
			} else {
				/*
				 * Synthetic Counter
				 */
				pic->sampler.syn_counter = bits;
				/*
				 * Load default frequency and if freq attribute
				 * is specified, over write with that value
				 */
				switch (pic->sampler.syn_counter) {
					case L2_DS_DRAM:
						/* FALLTHROUGH */
					case L2_DS_L3:
						/* FALLTHROUGH */
					case L2_DS_MISS:
						freq = L2_DS_FREQ;
						break;
					case L2_DS_OTHER_L2:
						freq = L2_LOAD_FRM_OTH_L2_FREQ;
						break;
					case L2_TXN_LD_MISS:
						/* FALLTHROUGH */
					case L2_TXN_ST_MISS:
						freq = L2_MISS_FREQ;
						break;
					case L2_TXN_LD_HIT:
						/* FALLTHROUGH */
					case L2_TXN_ST_HIT:
						/* FALLTHROUGH */
					case L2_EVT_HIT:
						freq = L2_HIT_FREQ;
						break;
				}
				/*
				 * Find the attibutes for L2 Sampler.
				 */
				for (i = 0; i < nattrs; i++) {
					if ((strcmp(attrs[i].ka_name,
					    "freq") == 0) && attrs[i].ka_val)
						freq = attrs[i].ka_val;
					else if ((strcmp(attrs[i].ka_name,
					    "single") == 0) && attrs[i].ka_val)
						pic->src_type |=
						    HV_RK_PERF_SRC_STRAND;
					else if ((strcmp(attrs[i].ka_name,
					    "shared") == 0) && attrs[i].ka_val)
						pic->src_type |=
						    HV_RK_PERF_SRC_STRAND_M;
					else if ((strcmp(attrs[i].ka_name,
					    "siu") == 0) && attrs[i].ka_val)
						pic->src_type |=
						    HV_RK_PERF_SRC_SIU;
					else if ((strcmp(attrs[i].ka_name,
					    "mmu") == 0) && attrs[i].ka_val)
						pic->src_type |=
						    HV_RK_PERF_SRC_MMU;
					else if ((strcmp(attrs[i].ka_name,
					    "source") == 0) && attrs[i].ka_val)
						source = attrs[i].ka_val &
						    HV_RK_PERF_SRC_MASK;
					else if (attrs[i].ka_val)
						return (CPC_INVALID_ATTRIBUTE);
				}
				if (source)
					pic->src_type = source;

				if (pic->src_type == 0)
					pic->src_type = HV_RK_PERF_SRC_STRAND;

				/* Range check to avoid DOS */
				if (freq > L2_SAM_MAX_FREQ) {
					cmn_err(CE_NOTE, "CPU-%d: freq set "
					    "> MAX. Resetting to %d",
					    CPU->cpu_id, L2_SAM_MAX_FREQ);
					freq = L2_SAM_MAX_FREQ;
				}
				if (freq < L2_SAM_MIN_FREQ) {
					cmn_err(CE_NOTE, "CPU-%d: freq set "
					    "< MIN. Resetting to %d",
					    CPU->cpu_id, L2_SAM_MIN_FREQ);
					freq = L2_SAM_MIN_FREQ;
				}
				pic->sampler.frequency = freq;
				*flagsp = 0;
			}
			pic->counter = RK_PERF_L2;
			break;
		case 3:	/* MMU Counter */
			if (*flagsp != CPC_COUNT_USER)
				return (CPC_INVALID_ATTRIBUTE);

			*flagsp = bits;
			pic->counter_bits = MMU_COUNTER_BITS;

			for (i = 0; i < nattrs; i++) {
				if ((strcmp(attrs[i].ka_name, "single") == 0) &&
				    attrs[i].ka_val)
					pic->src_type |= HV_RK_PERF_SRC_STRAND;
				else if
				    ((strcmp(attrs[i].ka_name, "shared") ==
				    0) && attrs[i].ka_val)
					pic->src_type |=
					    HV_RK_PERF_SRC_STRAND_M;
				else if ((strcmp(attrs[i].ka_name,
				    "source") == 0) && attrs[i].ka_val)
					source = attrs[i].ka_val &
					    HV_RK_PERF_SRC_MASK;
				else if (attrs[i].ka_val)
					return (CPC_INVALID_ATTRIBUTE);
			}
			if (source) {
				if (source & (HV_RK_PERF_SRC_SIU |
				    HV_RK_PERF_SRC_MMU))
					return (CPC_INVALID_ATTRIBUTE);
				pic->src_type = source;
			}


			if (pic->src_type == 0)
				pic->src_type = HV_RK_PERF_SRC_STRAND;

			pic->counter = RK_PERF_MMU;
			break;
		case 4: /* YANK Counter */
			pic->counter = RK_PERF_YANK;
			pic->counter_bits = YANK_COUNTER_BITS;
			/* FALLTHROUGH */
		case 5: /* SIBLK Counter */
			if (pic->counter == 0) {
				pic->counter = RK_PERF_SIBLK;
				pic->counter_bits = SIBLK_COUNTER_BITS;
			}
			/* FALLTHROUGH */
		case 6: /* LVLK Counter */
			if (pic->counter == 0) {
				pic->counter = RK_PERF_LVLK;
				pic->counter_bits = LVLK_COUNTER_BITS;
			}

			if (*flagsp != CPC_COUNT_USER)
				return (CPC_INVALID_ATTRIBUTE);

			for (i = 0; i < nattrs; i++) {
				if ((strcmp(attrs[i].ka_name, "single") ==
				    0) && attrs[i].ka_val)
					pic->src_type |= HV_RK_PERF_SRC_STRAND;
				else if
				    ((strcmp(attrs[i].ka_name, "shared") ==
				    0) && attrs[i].ka_val)
					pic->src_type |=
					    HV_RK_PERF_SRC_STRAND_M;
				else if ((strcmp(attrs[i].ka_name,
				    "source") == 0) && attrs[i].ka_val)
					source = attrs[i].ka_val &
					    HV_RK_PERF_SRC_MASK;
				else if (attrs[i].ka_val)
					return (CPC_INVALID_ATTRIBUTE);
			}
			if (source) {
				if (source & (HV_RK_PERF_SRC_SIU |
				    HV_RK_PERF_SRC_MMU))
					return (CPC_INVALID_ATTRIBUTE);
				pic->src_type = source;
			}


			if (pic->src_type == 0)
				pic->src_type = HV_RK_PERF_SRC_STRAND;

			*flagsp = 0;
			pic->sampler.frequency = 0;
			pic->sampler.syn_counter = bits;
			break;
		}
#ifdef	RKPCBE_DBG
	set_pic_name(pic);
#endif
	return (0);
}

/*ARGSUSED7*/
static int
rk_pcbe_configure(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
		    uint_t nattrs, kcpc_attr_t *attrs, void **data, void *token)
{
	rk_pcbe_config_t *pic;
	const struct nametable *n;
	int		rc;

	/* Is API version for Rock pcbe hypervisor services negotiated? */
	if (rock_pcbe_hsvc_available == B_FALSE)
		return (CPC_RESOURCE_UNAVAIL);

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		pic = *data;
		pic->pcbe_pic = (uint64_t)preset;
		return (0);
	}

	if (picnum < (uint_t)0 || picnum > NUM_PCBE_COUNTERS)
		return (CPC_INVALID_PICNUM);

	/*
	 * Find other requests that will be programmed with this one, and ensure
	 * they don't conflict.
	 * Any other counter in this pic group is active?
	 */
	if (active_pics[picnum][CPU->cpu_id] != NULL)
		return (CPC_CONFLICTING_REQS);

	if ((n = find_event(picnum, event)) == NULL)
		return (CPC_INVALID_EVENT);

	/* Check for supported attributes and populate pic */
	pic = kmem_zalloc(sizeof (rk_pcbe_config_t), KM_SLEEP);
	pic->flags = flags;
	pic->pcbe_pic = preset;

	if (rc = populate_pic_config(picnum, nattrs, attrs, n->bits, pic)) {
		kmem_free(pic, sizeof (rk_pcbe_config_t));
		return (rc);
	}

	/*
	 * num_ringbuf_entries should be always even. Since this
	 * /etc/system tunable, need to check for this.
	 */
	if (num_ringbuf_entries & 1) {
		num_ringbuf_entries++;
		cmn_err(CE_WARN, "num_ringbuf_entries should be even."
		    " Changing %u to %u\n", num_ringbuf_entries - 1,
		    num_ringbuf_entries);
	}
	if (num_ringbuf_entries < MIN_RINGBUF_ENTRIES) {
		cmn_err(CE_WARN, "num_ringbuf_entries should be at least "
		    "%u. Changing %u to %u\n", MIN_RINGBUF_ENTRIES,
		    num_ringbuf_entries, MIN_RINGBUF_ENTRIES);
		num_ringbuf_entries = MIN_RINGBUF_ENTRIES;
	}

	pic->state = STATE_CONFIGURED;
	pic->cpu = CPU->cpu_id;
	active_pics[picnum][pic->cpu] = pic;
	*data = pic;

	if (pic->counter_type == NORMAL_COUNTER)
		PRINT_PIC(pic, "After Configuration (N)");
	return (0);
}

static void
rk_pcbe_program(void *token)
{
	rk_pcbe_config_t	*pic = NULL;
	int			rc;
	uint64_t		counter;

	while ((pic = (rk_pcbe_config_t *)kcpc_next_config(token, pic, NULL))
	    != NULL) {

		if (pic->inuse == B_FALSE)
			continue;

		counter = (uint64_t)(pic->counter | pic->src_type);
		rc = (int)hv_rk_perf_count_init(counter);

		if (curthread->t_cpc_ctx) {
			/*
			 * If in thread context, pic should get an exclusive
			 * lock. If it cannot then make the current thread
			 * passive.
			 */
			if (rc != H_EOK) {
				kcpc_passivate();
				continue;
			}
		} else {
			/* Must be cpu context */
			ASSERT(CPU->cpu_cpc_ctx);
			if (rc == H_EWOULDBLOCK &&
			    (pic->src_type & HV_RK_PERF_SRC_STRAND_M)) {
				/* pic in use by a cpu of current guest */
				pic->inuse = B_FALSE;
				continue;
			} else if (rc != H_EOK) {
				/*
				 * Either the counter is in use by a different
				 * guest or another cpu in the current guest is
				 * already using it in single source mode. In
				 * either case, invalidate the pic.
				 */
				kcpc_invalidate_config(token);
				continue;
			}
		}

		/*
		 * rc = H_EOK, hence current cpu was successful in
		 * obtaining exclusive access to the counter, Set this
		 * pic as active.
		 */
		if (CPU->cpu_id != pic->cpu) {
			active_pics[pic->pcbe_picno][pic->cpu] = NULL;
			pic->cpu = CPU->cpu_id;
			active_pics[pic->pcbe_picno][pic->cpu] = pic;
		}
		pic->inuse = B_TRUE;

		if (pic->counter_type == NORMAL_COUNTER)
			rc = rk_pcbe_program_normal(pic);
		else
			rc = rk_pcbe_program_synthetic(pic);

		pic->state = STATE_PROGRAMMED;

		if (rc != H_EOK) {
			kcpc_invalidate_config(token);
			continue;
		}
	}
}

static void
rk_pcbe_allstop(void)
{
	int 			i;
	rk_pcbe_config_t	*pic;

	for (i = 0; i <  NUM_PCBE_COUNTERS; i++) {
		pic = active_pics[i][CPU->cpu_id];

		if (pic == NULL || pic->state != STATE_PROGRAMMED)
			continue;

		ASSERT(pic->inuse == B_TRUE && CPU->cpu_id == pic->cpu);

		/* Stop all active pics */
		if (pic->counter_type == NORMAL_COUNTER) {
			hv_rk_perf_count_stop((uint64_t)(pic->counter |
			    pic->src_type));
			DBG_PRINT(("CPU-%d: Counter %s(%X) stopped.\n",
			    CPU->cpu_id, pic->name, pic->counter));
		} else {
			DBG_PRINT(("CPU-%d: Stopping counter %s(%lX)\n",
			    CPU->cpu_id, pic->name,
			    pic->sampler.synthetic_pic));
			rk_pcbe_stop_synthetic(pic);
		}

		/* Mark pic as stopped */
		pic->state = STATE_STOPPED;

		/*
		 * If running in lwp context, and context is invalid or
		 * if we get here when both cpu as well as lwp contexts
		 * are invalid, then release the counter. This is can happen
		 * when the lwp that pcbe is monitoring is terminated. In
		 * this situation, pcbe_free is called directly after allstop
		 * without calling pcbe_sample. pcbe_free may get executed on
		 * a differnt strand. If the free-ing strand is not the one that
		 * programmed this pic, HV does not allow that operaion and will
		 * return H_ENOACCESS. To prevent this, the counter is released
		 * if the lwp that pcbe is minitoring disappears.
		 */
		if ((curthread->t_cpc_ctx &&
		    curthread->t_cpc_ctx->kc_flags & KCPC_CTX_INVALID) || (
		    curthread->t_cpc_ctx == NULL && CPU->cpu_cpc_ctx == NULL)) {
			rk_pcbe_release(pic);
		}
	}
}

static void
rk_pcbe_sample(void *token)
{
	rk_pcbe_config_t	*pic = NULL;
	uint64_t		*pic_data, counter_value;
	int			rc;
	int64_t			diff;

	while ((pic = (rk_pcbe_config_t *)
	    kcpc_next_config(token, pic, &pic_data)) != NULL) {

		if (pic == NULL || pic->inuse != B_TRUE ||
		    pic->state == STATE_RELEASED) {
			*pic_data = (uint64_t)0;
			continue;
		}

		ASSERT(CPU->cpu_id == pic->cpu);

		if (pic->counter_type == NORMAL_COUNTER) {
			rc = (int)hv_rk_perf_count_get((uint64_t)(pic->counter |
			    pic->src_type), &counter_value);
			if (rc == H_EOK) {
				diff = counter_value - pic->pcbe_pic;
				pic->pcbe_pic = counter_value;
				if (diff < 0)
					diff += (0x1UL << pic->counter_bits);
			}
		} else {
			/*
			 * Difference returned by synthetic counters will
			 * be always +ve
			 */
			rc = rk_pcbe_sample_synthetic(pic, &diff);
		}

		*pic_data += diff;
		if (pic->state == STATE_STOPPED)
			rk_pcbe_release(pic);

		if (rc != H_EOK) {
			kcpc_invalidate_config(token);
			continue;
		}
	}
}

static void
rk_pcbe_free(void *config)
{
	rk_pcbe_config_t 	*pic = (rk_pcbe_config_t *)config;

	/* Release counter */
	if (pic->inuse == B_TRUE) {
		if (pic->state != STATE_RELEASED) {
			rk_pcbe_release(pic);
		}
		if (pic->counter_type == SYNTHETIC_COUNTER)
			rk_pcbe_free_synthetic(pic);
	}

	/* Mark pic as inactive */
	active_pics[pic->pcbe_picno][pic->cpu] = NULL;
	kmem_free(pic, sizeof (rk_pcbe_config_t));
}

static void
rk_pcbe_release(rk_pcbe_config_t *pic)
{
	int			rc = 0;

	ASSERT(pic->inuse == B_TRUE && pic->state != STATE_RELEASED);

	DBG_PRINT(("CPU-%d: Releasing Pic %s (#%d, cntr %X) %p",
	    CPU->cpu_id, pic->name, pic->pcbe_picno, pic->counter,
	    (void *)pic));

	rc = (int)hv_rk_perf_count_release((uint64_t)
	    (pic->counter | pic->src_type));
	if (rc != 0) {
		cmn_err(CE_WARN, "CPU-%d: Releasing Pic-%d, counter: %X failed "
		    "%p. rc=%d", CPU->cpu_id, pic->pcbe_picno, pic->counter,
		    (void *)pic, rc);
	}
	if (pic->counter_type == SYNTHETIC_COUNTER &&
	    !(pic->counter == RK_PERF_YANK || pic->counter == RK_PERF_SIBLK ||
	    pic->counter == RK_PERF_LVLK)) {
		rc = (int)hv_rk_perf_sample_release((uint64_t)
		    (pic->counter | pic->src_type));
		if (rc != 0) {
			cmn_err(CE_WARN, "CPU-%d: Releasing Pic-%d, sampler: %X"
			    " failed %p. rc=%d", CPU->cpu_id, pic->pcbe_picno,
			    pic->counter, (void *)pic, rc);
			return;
		}
	}
	pic->state = STATE_RELEASED;
}

static int
rk_pcbe_program_normal(rk_pcbe_config_t *pic)
{
	uint64_t		counter;
	uint64_t		config_value;
	uint64_t		rc;

	ASSERT(pic->inuse == B_TRUE);

	counter = (uint64_t)(pic->counter | pic->src_type);

	rc = (int)hv_rk_perf_count_init(counter);
	if (rc != H_EOK) {
		cmn_err(CE_WARN, "{%d} Pic %d cntr %X not started",
		    CPU->cpu_id, pic->pcbe_picno, pic->counter);
		PRINT_PIC(pic, "Init counter failed");
		return ((int)rc);
	}

	/* Preset the counter value if non zero */
	if (pic->pcbe_pic > 0)  {
		DBG_PRINT(("CPU-%d: Counter getting preset to %lu (%lX)\n",
		    CPU->cpu_id, pic->pcbe_pic, pic->pcbe_pic));
		rc = (int)hv_rk_perf_count_set(counter, pic->pcbe_pic);
	}

	if (rc != H_EOK) {
		cmn_err(CE_WARN, "{%d} Pic %d cntr %X not set",
		    CPU->cpu_id, pic->pcbe_picno, pic->counter);
		PRINT_PIC(pic, "Set counter failed");
		return ((int)rc);
	}

	/* Configure and start counter */
	config_value = ((uint64_t)pic->toe << RK_PERF_COUNT_TOE_SHIFT)
	    | pic->flags;
	rc = (int)hv_rk_perf_count_start(counter, config_value);

	if (rc != H_EOK) {
		cmn_err(CE_WARN, "{%d} Pic %d cntr %X not configured",
		    CPU->cpu_id, pic->pcbe_picno, pic->counter);
		PRINT_PIC(pic, "Configure counter failed");
	}
	return ((int)rc);
}

static int
rk_pcbe_program_synthetic(rk_pcbe_config_t *pic)
{
	int	rc;
	ASSERT(pic->inuse == B_TRUE);
	switch (pic->counter) {
		case RK_PERF_INSTR:
			rc = program_instr_sampler(pic);
			break;
		case RK_PERF_L2:
			rc = program_l2_sampler(pic);
			break;
		case RK_PERF_YANK:
			/* FALLTHROUGH */
		case RK_PERF_SIBLK:
			/* FALLTHROUGH */
		case RK_PERF_LVLK:
			rc = rk_pcbe_program_normal(pic);
			break;
		default:
			PRINT_PIC(pic, "rk_pcbe_program_synthetic");
			ASSERT(0);
			rc = H_EINVAL;
			break;
	}
	return (rc);
}

static void
rk_pcbe_free_synthetic(rk_pcbe_config_t *pic)
{
	ASSERT(pic->inuse == B_TRUE);
	switch (pic->counter) {
		case RK_PERF_INSTR:
			/* FALLTHROUGH */
		case RK_PERF_L2:
			free_ringbuffer(pic);
			break;
		case RK_PERF_YANK:
			/* FALLTHROUGH */
		case RK_PERF_SIBLK:
			/* FALLTHROUGH */
		case RK_PERF_LVLK:
			/* Do nothing */
			break;
		default:
			PRINT_PIC(pic, "rk_pcbe_free_synthetic");
			ASSERT(0);
			break;
	}
}

/* All sample_synthetic code may be executed at TL=1 */
static int
rk_pcbe_sample_synthetic(rk_pcbe_config_t *pic, int64_t *diffp)
{
	int	rc;
	ASSERT(pic->inuse == B_TRUE);
	switch (pic->counter) {
		case RK_PERF_INSTR:
			rc = sample_instr_sampler(pic, diffp);
			break;
		case RK_PERF_L2:
			rc = sample_l2_sampler(pic, diffp);
			break;
		case RK_PERF_YANK:
			/* FALLTHROUGH */
		case RK_PERF_SIBLK:
			/* FALLTHROUGH */
		case RK_PERF_LVLK:
			rc = sample_mccdesr(pic, diffp);
			break;
		default:
			PRINT_PIC(pic, "rk_pcbe_sample_synthetic");
			ASSERT(0);
			break;
	}
	return (rc);
}

static void
rk_pcbe_stop_synthetic(rk_pcbe_config_t *pic)
{
	uint64_t	counter = (uint64_t)(pic->counter | pic->src_type);

	ASSERT(pic->inuse == B_TRUE);
	switch (pic->counter) {
		case RK_PERF_INSTR:
			/* FALLTHROUGH */
		case RK_PERF_L2:
			hv_rk_perf_count_stop(counter);
			hv_rk_perf_sample_stop(counter);
			break;
		case RK_PERF_YANK:
			/* FALLTHROUGH */
		case RK_PERF_SIBLK:
			/* FALLTHROUGH */
		case RK_PERF_LVLK:
			hv_rk_perf_count_stop(counter);
			break;
		default:
			PRINT_PIC(pic, "rk_pcbe_stop_synthetic");
			ASSERT(0);
			break;
	}
}

static int
program_l2_sampler(rk_pcbe_config_t *pic)
{
#define	ASI_PERF_L2_TXN_INFO		0xF10010
#define	ASI_PERF_L2_EA_MASK		0xF10018
#define	ASI_PERF_L2_EA_MATCH		0xF10020
#define	ASI_PERF_L2_TXN_INFO_FILTER	0xF10030
#define	ASI_PERF_L2_CC			0xF10038
#define	TXN_ICACHE_LOAD			0x1
#define	TXN_DCACHE_LOAD			0x2
#define	TXN_INSTR_PREFETCH		0x4
#define	TXN_STORE_PREFETCH		0x8
#define	TXN_DCACHE_STORE		0x10
#define	TXN_ATOMIC_LOAD_STORE		0x20
#define	TXN_FLUSH			0x40
#define	L2_ALL_TXNS	(TXN_ICACHE_LOAD | TXN_DCACHE_LOAD | \
			TXN_INSTR_PREFETCH | TXN_STORE_PREFETCH | \
			TXN_DCACHE_STORE | TXN_ATOMIC_LOAD_STORE | TXN_FLUSH)
#define	L2_TXN_SHIFT			3
#define	L2_ALL_EVT			0x3
#define	L2_ALL_EVT_SHIFT		10
#define	L2_TXN_INFO_FILTER_MASK		(L2_ALL_EVT << L2_ALL_EVT_SHIFT) | \
					(L2_ALL_TXNS << L2_TXN_SHIFT)

	uint64_t	l2_load_valist[] = {ASI_PERF_L2_TXN_INFO};
	uint64_t	ringbuf_pa, l2_load_valist_pa, counter, rc;
	int		hv_call_cnt = 1, ret = 0;
	char		*funcname = "program_l2_sampler";

	counter = (uint64_t)(pic->counter | pic->src_type);

	if (pic->sampler.ring_buffer == NULL) {
		alloc_ringbuffer(pic, sizeof (l2_load_valist),
		    num_ringbuf_entries);
		pic->sampler.sample_size = sizeof (l2_load_valist);
		pic->flags = L2_ALL_TXNS; /* For L2 counter */
		PRINT_PIC(pic, "After Configuration (S)");
	}
	ringbuf_pa = va_to_pa(pic->sampler.ring_buffer);
	rc = hv_rk_perf_sample_init(counter, ringbuf_pa);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);
	/*
	 * If (((Reported EA ^ MATCH) & MASK) == 0) then sample is taken
	 */
	rc = hv_rk_perf_sample_config(counter, ASI_PERF_L2_EA_MASK, 0);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	rc = hv_rk_perf_sample_config(counter, ASI_PERF_L2_EA_MATCH, 0);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	rc = hv_rk_perf_sample_config(counter, ASI_PERF_L2_CC,
	    pic->sampler.frequency);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	rc = hv_rk_perf_sample_config(counter, ASI_PERF_L2_TXN_INFO_FILTER,
	    L2_TXN_INFO_FILTER_MASK);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	l2_load_valist_pa = va_to_pa(l2_load_valist);
	ret |= rk_pcbe_program_normal(pic); /* Reset to zero & start counting */

	rc = hv_rk_perf_sample_start(counter, pic->sampler.frequency,
	    sizeof (l2_load_valist), l2_load_valist_pa);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);
	return (ret);
}

static int
sample_l2_sampler(rk_pcbe_config_t *pic, int64_t *diffp)
{
#define	DS_SHIFT	34
#define	EVT_SHIFT	22
#define	TXN_SHIFT	7
#define	DS_MASK		MAKE_MASK(2, 0)
#define	EVT_MASK	MAKE_MASK(4, 0)
#define	TXN_MASK	MAKE_MASK(7, 0)

	rk_pcbe_ringbuf_t	*ringbuf = pic->sampler.ring_buffer;
	uint32_t	value, target;
	uint64_t	total_count, hit_count = 0, *head, ovf_count, rc;
	uint32_t	sample_count = 0, sample_hit_count = 0;
	uint32_t	size = pic->sampler.sample_size;
	int		hv_call_cnt = 1, ret = 0;
	char		*funcname = "sample_l2_sampler";
	uint8_t		ds, evt;

	head =  RINGBUF_GET_HEAD(ringbuf);
	if (head == NULL) {
		DBG_PRINT(("CPU-%d: Head is NULL to start with\n",
		    CPU->cpu_id));
	}

	while (head) {
		if (*head != 0) {
			uint64_t rawvalue = *head;
			DBG_PRINT(("CPU-%d: rawvalue=0x%lX\n",
			    CPU->cpu_id, rawvalue));
			target = TYPE(pic->sampler.syn_counter);

			switch (GROUP(pic->sampler.syn_counter)) {
			case L2_GROUP_DS:
				value = (rawvalue >> DS_SHIFT) & DS_MASK;
				DBG_PRINT(("CPU-%d: value=0x%X, target=0x%X\n",
				    CPU->cpu_id, value, target));
				switch (target) {
				case DS_DRAM: /* FALLTHROUGH */
				case DS_L3: /* FALLTHROUGH */
				case DS_OTHER_L2: /* FALLTHROUGH */
					if (value == target)
						sample_hit_count++;
					break;
				case DS_MISS:
					if (value != DS_LOCAL_L2)
						sample_hit_count++;
					break;
				}
				break;
			case L2_GROUP_TXN_MISS:
				value = (rawvalue >> TXN_SHIFT) & TXN_MASK;
				ds = (uint8_t)((rawvalue >> DS_SHIFT)
				    & DS_MASK);
				DBG_PRINT(("CPU-%d: value=0x%X, target=0x%X, "
				    "ds: 0x%X\n", CPU->cpu_id, value,
				    target, ds));
				if (((value & target) != 0) && ds !=
				    DS_LOCAL_L2)
					sample_hit_count++;
				break;
			case L2_GROUP_TXN_HIT:
				value = (rawvalue >> TXN_SHIFT) & TXN_MASK;
				ds = (uint8_t)((rawvalue >> DS_SHIFT)
				    & DS_MASK);
				evt = (uint8_t)((rawvalue >> EVT_SHIFT)
				    & EVT_MASK);
				DBG_PRINT(("CPU-%d: value=0x%X, target=0x%X, "
				    "ds: 0x%X, evt: 0x%X\n", CPU->cpu_id,
				    value, target, ds, evt));
				if (((value & target) != 0) && (evt ==
				    EVT_L2_NOEVENTS || evt == EVT_L2_PEND_ST) &&
				    (ds == DS_LOCAL_L2))
					sample_hit_count++;
				break;
			case L2_GROUP_EVT:
				value = (rawvalue >> EVT_SHIFT) & EVT_MASK;
				ds = (uint8_t)((rawvalue >> DS_SHIFT)
				    & DS_MASK);
				DBG_PRINT(("CPU-%d: value=0x%X, target=0x%X, "
				    "ds: 0x%X\n", CPU->cpu_id, value,
				    target, ds));
				if ((value == EVT_L2_NOEVENTS || value ==
				    EVT_L2_PEND_ST) && ds == DS_LOCAL_L2)
					sample_hit_count++;
				break;
			}
		}
		sample_count++;
		RINGBUF_MOVE_HEAD(ringbuf, head, size);
	}
	RINGBUF_SET_HEAD(ringbuf);

	/*
	 * Since ring buffer is consumed, clear pending sample count.
	 * Sample count is discarded, therefore reusing a variable.
	 */
	rc = hv_rk_perf_sample_pending((uint64_t)(pic->counter |
	    pic->src_type), &total_count);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	if (sample_count != total_count) {
		cmn_err(CE_WARN, "CPU-%d: Sample cnt mismatch:sol=%u, hv=%lu\n",
		    CPU->cpu_id, sample_count, total_count);
	}

	/* Check if the counter overflowed */
	rc = hv_rk_perf_count_overflow((uint64_t)(pic->counter |
	    pic->src_type), &ovf_count);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	if (rc != 0)
		ovf_count = 0;

	rc = hv_rk_perf_count_get((uint64_t)(pic->counter |
	    pic->src_type), &total_count);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);
	DBG_PRINT(("CPU-%d: Total Count: %lu\n", CPU->cpu_id, total_count));

	if (rc != 0)
		total_count = 0;

	/*
	 * Reset it to zero so that we need not maintain old value
	 */
	rc = hv_rk_perf_count_set((uint64_t)(pic->counter | pic->src_type), 0);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	if (ovf_count > 0) {
		DBG_PRINT(("CPU-%d: L2 counter overflowed: ovf_count: %lu\n",
		    CPU->cpu_id, ovf_count));
		/*
		 * ovf_count > 0 means, counter has hit max, ovf_count times
		 * before counting total_count of l2 transactions. Therefore
		 * add total_count to ovf_count times max count value.
		 */
		while (ovf_count--)
			total_count += (0x1UL << pic->counter_bits);
	}

	if (sample_count > 0)
		hit_count = (sample_hit_count * total_count) / sample_count;

	*diffp = (int64_t)hit_count;
	DBG_PRINT(("CPU-%d: sample_l2_sampler. hit_count: %lu, *diffp: %ld\n",
	    CPU->cpu_id, hit_count, *diffp));
	if (*diffp < 0) {
		cmn_err(CE_WARN, "CPU-%d Negative l2 count. hit_count: %lu, "
		    "*diffp: %ld\n", CPU->cpu_id, hit_count, *diffp);
	}
	return (ret);
}

static int
program_instr_sampler(rk_pcbe_config_t *pic)
{
#define	ASI_PERF_IS_PC_MASK		0x10
#define	ASI_PERF_IS_PC_MATCH		0x18
#define	ASI_PERF_IS_CC_LATENCY_MASK	0x160
#define	ASI_PERF_IS_CONTEXT_FILTER	0x168
#define	ASI_PERF_IS_INFO_MASK		0x170
#define	ASI_PERF_IS_INFO_MATCH		0x178

#define	ASI_PERF_IS_CONTEXT		0x108
#define	ASI_PERF_IS_INFO		0x148

#define	IS_BHR_LATENCY_CLAT_MASK	0xFFF
#define	IS_CC_FILTER_TGTF_MASK		0x10
#define	IS_CC_FILTER_TOF_MASK		0x8
#define	IS_CC_LATENCY_FREQ_SHIFT	22

	uint64_t	instr_sampler_valist[] =
			    {ASI_PERF_IS_INFO, ASI_PERF_IS_CONTEXT};
	uint64_t	ringbuf_pa, instr_sampler_valist_pa, counter, rc;
	int		hv_call_cnt = 1, ret = 0;
	char		*funcname = "program_instr_sampler";

	counter = (uint64_t)(pic->counter | pic->src_type);

	if (pic->sampler.ring_buffer == NULL) {
		alloc_ringbuffer(pic, sizeof (instr_sampler_valist),
		    num_ringbuf_entries);
		pic->sampler.sample_size = sizeof (instr_sampler_valist);
		PRINT_PIC(pic, "After Configuration (S)");
	}

	ringbuf_pa = va_to_pa(pic->sampler.ring_buffer);
	rc = hv_rk_perf_sample_init(counter, ringbuf_pa);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	/*
	 * If (((Reported Value ^ MATCH) & MASK) == 0) then sample is taken;
	 */
	rc = hv_rk_perf_sample_config(counter, ASI_PERF_IS_PC_MASK, 0);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	rc = hv_rk_perf_sample_config(counter, ASI_PERF_IS_PC_MATCH, 0);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	/*
	 * Set CLAT_MASK to 0xFFF, meaning, drop instruction samples
	 * whose latency is zero, means, sample all of them, because
	 * all instructions has at least a latency of 1 cycle.
	 */
	rc = hv_rk_perf_sample_config(counter, ASI_PERF_IS_CONTEXT_FILTER,
	    (uint64_t)(IS_CC_FILTER_TGTF_MASK | IS_CC_FILTER_TOF_MASK |
	    pic->sampler.flags));
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	/*
	 * Even though frequency is set when started, it has to be
	 * specified here, because, if left zero, then a PET is
	 * immediately generated since the candidate counter is zero.
	 */
	rc = hv_rk_perf_sample_config(counter, ASI_PERF_IS_CC_LATENCY_MASK,
	    (((uint64_t)pic->sampler.frequency) << IS_CC_LATENCY_FREQ_SHIFT) |
	    IS_BHR_LATENCY_CLAT_MASK);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	rc = hv_rk_perf_sample_config(counter, ASI_PERF_IS_INFO_MASK, 0);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	rc = hv_rk_perf_sample_config(counter, ASI_PERF_IS_INFO_MATCH, 0);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	instr_sampler_valist_pa = va_to_pa(instr_sampler_valist);
	ret |= rk_pcbe_program_normal(pic); /* Reset to zero & start counting */

	/* Start sampling */
	rc = hv_rk_perf_sample_start(counter, pic->sampler.frequency,
	    sizeof (instr_sampler_valist), instr_sampler_valist_pa);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);
	return (ret);
}

static int
sample_instr_sampler(rk_pcbe_config_t *pic, int64_t *diffp)
{
#define	I_MODE_SHIFT	34
#define	I_TYPE_SHIFT	0
#define	I_EVT_SHIFT	7
#define	I_MODE_MASK	MAKE_MASK(3, 0)
#define	I_TYPE_MASK	MAKE_MASK(7, 0)
#define	I_EVT_MASK	MAKE_MASK(12, 0)

	rk_pcbe_ringbuf_t	*ringbuf = pic->sampler.ring_buffer;
	uint32_t	size = pic->sampler.sample_size;
	uint32_t	value, target, shift, mask;
	uint32_t	sample_count = 0, sample_hit_count = 0;
	uint64_t	total_count, hit_count = 0, *head, ovf_count, rc;
	int		hv_call_cnt = 1, ret = 0;
	char		*funcname = "sample_instr_sampler";

	switch (GROUP(pic->sampler.syn_counter)) {
	case I_GROUP_MODE:
		mask = I_MODE_MASK;
		shift = I_MODE_SHIFT;
		break;
	case I_GROUP_TYPE:
		mask = I_TYPE_MASK;
		shift = I_TYPE_SHIFT;
		break;
	case I_GROUP_EVT:
		mask = I_EVT_MASK;
		shift = I_EVT_SHIFT;
		break;
	default:
		PRINT_PIC(pic, "No I_GROUP found");
		ASSERT(0);
		break;
	}

	head =  RINGBUF_GET_HEAD(ringbuf);

	if (head == NULL) {
		DBG_PRINT(("CPU-%d: Head is NULL to start with\n",
		    CPU->cpu_id));
	}

	while (head) {
		uint64_t	rawvalue = *head;
		uint64_t	context = *(head + 1);
		uint8_t		tl = (uint8_t)((context >> 2) & 7);
		int		drop_sample = B_FALSE;

		if (rawvalue != 0) {
			value = (rawvalue >> shift) & mask;
			target = TYPE(pic->sampler.syn_counter);
			DBG_PRINT(("CPU-%d: rawvalue=0x%lX, value=0x%X,"
			    "target=0x%X\n", CPU->cpu_id, rawvalue, value,
			    target));

			/*
			 * Several EVT fields are only valid for certain
			 * instruction types.  Need to check TYP field
			 * before trusting what's in EVT.
			 */
			if (GROUP(pic->sampler.syn_counter) == I_GROUP_EVT) {
				uint64_t type = rawvalue >> I_TYPE_SHIFT;

				switch (target) {
				case EVT_DC_MISS:
				case EVT_PRIOR_MISS:
				case EVT_LDB_FULL:
				case EVT_BYPASS_RAW:
				case EVT_NONBYPASS_RAW:
					if ((type & TYPE_LD) == 0)
						drop_sample = B_TRUE;
					break;
				case EVT_STB_FULL:
					if ((type & TYPE_ST) == 0)
						drop_sample = B_TRUE;
					break;
				case EVT_DTLB_MISS:
					if ((type & (TYPE_LD|TYPE_ST)) == 0)
						drop_sample = B_TRUE;
					break;
				case EVT_CORRECT_BP:
				case EVT_CTI_TAKEN:
					if ((type & TYPE_CTI) == 0)
						drop_sample = B_TRUE;
					break;
				}
				DBG_PRINT(("CPU-%d: rawvalue=%lX, cleaned value"
				    "=%X, target=%X\n", CPU->cpu_id, rawvalue,
				    value, target));
			}

			/*
			 * If user does not want to count instructions in scout
			 * mode, and if the instruction sampled was in scout
			 * mode, drop the sample.
			 */
			if (pic->sampler.nohws == B_TRUE) {
				uint64_t mode = (rawvalue >> I_MODE_SHIFT) &
				    I_MODE_MASK;
				if (mode == MODE_HWS)
					drop_sample = B_TRUE;
			}

			/*
			 * If user wants to count instructions at a particular
			 * trap level (0 or >0), and the samples are in
			 * different trap level, drop the sample.
			 */
			switch (pic->sampler.tl) {
			case TLZ: /* Sample ONLY instr at TL == 0 */
				if (tl != 0)
					drop_sample = B_TRUE;
				break;
			case TLNZ: /* Sample ONLY instr at TL > 0 */
				if (tl == 0)
					drop_sample = B_TRUE;
				break;
			}

			switch (GROUP(pic->sampler.syn_counter)) {
			case I_GROUP_MODE:
				/* Fields that are integers */
				if (value == target && drop_sample == B_FALSE)
					sample_hit_count++;
				break;
			case I_GROUP_EVT:
			case I_GROUP_TYPE:
				/* Fields that are bit vectors */
				if (value & target && drop_sample == B_FALSE)
					sample_hit_count++;
				break;
			default:
				ASSERT(0); /* missing case statement */
			}
		}
		sample_count++;
		DBG_PRINT(("CPU-%d: Target %X, sample_count: %d\n",
		    CPU->cpu_id, sample_count, target));
		RINGBUF_MOVE_HEAD(ringbuf, head, size);
	}

	RINGBUF_SET_HEAD(ringbuf);

	/*
	 * Since ring buffer is consumed, clear pending sample count.
	 * Sample count is discarded, therefore reusing a variable.
	 */
	rc = hv_rk_perf_sample_pending((uint64_t)(pic->counter |
	    pic->src_type), &total_count);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	if (sample_count != total_count) {
		cmn_err(CE_WARN, "CPU-%d: Sample cnt mismatch:sol=%u, hv=%lu\n",
		    CPU->cpu_id, sample_count, total_count);
	}

	/* Check if the counter overflowed */
	rc = hv_rk_perf_count_overflow((uint64_t)(pic->counter |
	    pic->src_type), &ovf_count);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	if (rc != H_EOK)
		ovf_count = 0;

	rc = hv_rk_perf_count_get((uint64_t)(pic->counter |
	    pic->src_type), &total_count);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	if (rc != H_EOK)
		total_count = 0;

	/*
	 * Reset it to zero so that we need not maintain old value
	 */
	rc = hv_rk_perf_count_set((uint64_t)(pic->counter | pic->src_type), 0);
	ret |= (int)rc;
	print_hv_error(rc, &hv_call_cnt, funcname, pic);

	if (ovf_count > 0) {
		/*
		 * ovf_count > 0 means, counter has hit max, ovf_count times
		 * before counting total_count of instructions. Therefore
		 * add total_count to ovf_count times max count value.
		 */
		while (ovf_count--)
			total_count += (0x1UL << pic->counter_bits);
	}

	if (sample_count > 0)
		hit_count = (sample_hit_count * total_count) / sample_count;

	*diffp = (int64_t)hit_count;
	DBG_PRINT(("CPU-%d: sample_instr_load. hit_count: %lu, *diffp: %ld\n",
	    CPU->cpu_id, hit_count, *diffp));
	if (*diffp < 0) {
		cmn_err(CE_WARN, "CPU-%d Negative instr count. hit_count: %lu, "
		    "*diffp: %ld\n", CPU->cpu_id, hit_count, *diffp);
	}
	return (ret);
}

/*
 * mccdesr counters are synthetic counters. Hypervisor maintains
 * a 64 bit memory based counter. Therefore we can assume that
 * this counter never overflows.
 */
static	int
sample_mccdesr(rk_pcbe_config_t *pic, int64_t *diffp)
{
	uint64_t	rc = 0;
	uint64_t	counter_value;
	rc = hv_rk_perf_count_get((uint64_t)(pic->counter |
	    pic->src_type), &counter_value);
	if (rc == H_EOK) {
		*diffp = counter_value - pic->pcbe_pic;
		pic->pcbe_pic = counter_value;
		if (*diffp < 0) {
			cmn_err(CE_WARN, "CPU-%d: Pic-%d, counter: %X overflow",
			    CPU->cpu_id, pic->pcbe_picno, pic->counter);
		}
	} else {
		cmn_err(CE_WARN, "CPU-%d: Failed to sample pic-%d, counter-%X",
		    CPU->cpu_id, pic->pcbe_picno, pic->counter);
	}
	return ((int)rc);
}

static void
alloc_ringbuffer(rk_pcbe_config_t *pic, uint32_t size,
						uint32_t num_samples)
{
	uint32_t	ringbuf_size;
	rk_pcbe_ringbuf_t	*ringbuf;
	ASSERT(!(num_samples & 1)); /* Assert number of samples is even */

	ringbuf_size = sizeof (rk_pcbe_ringbuf_t) + (size * num_samples);
	ringbuf = (void *)kmem_alloc(ringbuf_size, KM_SLEEP);
	pic->sampler.ring_buffer = ringbuf;
	ringbuf->head = NULL;
	ringbuf->tail = NULL;
	ringbuf->size = size * num_samples;
	ringbuf->hwm = ringbuf->size >> 1;
}

static void
free_ringbuffer(rk_pcbe_config_t *pic)
{
	rk_pcbe_ringbuf_t	*ringbuf = pic->sampler.ring_buffer;
	/*
	 * When multiple pics are used and one of the pics was not configurable
	 * (eg: Bad attribute), then cpc calls rk_pcbe_free for the pics that
	 * were already configured. This results in calling this routine with
	 * NULL ringbuf, since ringbuf is allocated when the first sample is
	 * taken. To protect against this condition, we need do the following
	 * check before calling kmem_free since it uses ringbuf->size.
	 */
	if (ringbuf) {
		DBG_PRINT(("CPU-%d: free_ringbuffer freeing %d bytes\n",
		    CPU->cpu_id,
		    (int)(sizeof (rk_pcbe_ringbuf_t) + ringbuf->size)));
		kmem_free(ringbuf, sizeof (rk_pcbe_ringbuf_t) + ringbuf->size);
	} else {
		DBG_PRINT(("CPU-%d: free_ringbuffer: Ringbuffer not "
		    "configured\n", CPU->cpu_id));
	}
}

static void
print_hv_error(uint64_t rc, int *cntp, char *funcname, rk_pcbe_config_t *pic)
{
	ASSERT(cntp && pic);
	if (rc != H_EOK) {
		cmn_err(CE_WARN, "{%d} pgm-hw call-%d in %s returned 0x%lX for "
		    "pic %d cntr %X", CPU->cpu_id, *cntp, funcname, rc,
		    pic->pcbe_picno, pic->counter);
	}
	(*cntp)++;
}

static	void
set_string_constants(void)
{
	if (strncmp(cpu_module_name, "SUNW,", 5) == 0)
		rock_name = &cpu_module_name[5];
	else
		rock_name = cpu_module_name;
	(void) strcpy(rock_cpuref, "See the \"");
	(void) strcat(rock_cpuref, rock_name);
	(void) strcat(rock_cpuref, " User's Manual\" for descriptions of "
	    "these events. "CPU_REF_URL);
	(void) strcat(pcbe_module_name, cpu_module_name);
}

#ifdef RKPCBE_DBG
static	void
set_pic_name(rk_pcbe_config_t *pic)
{
	uint32_t	bits;
	const struct nametable	*n;

	/*
	 * For normal cycle and instruction counters, the 'bits' value
	 * is not saved.
	 */
	if (pic->counter == RK_PERF_CYC) {
		(void) strcpy(pic->name, "Cycles");
		return;
	}

	if (pic->counter_type == NORMAL_COUNTER) {
		if (pic->counter == RK_PERF_INSTR) {
			(void) strcpy(pic->name, "Instr_All");
			return;
		}
		bits = pic->flags;
	}
	else
		bits = pic->sampler.syn_counter;

	for (n = events[pic->pcbe_picno]; n->bits != NT_END; n++) {
		if (n->bits == bits) {
			(void) strcpy(pic->name, n->name);
			break;
		}
	}
}

static void
print_pic(rk_pcbe_config_t *pic, char *heading)
{
	ASSERT(pic);
	/*
	 * On multi strand system, the print gets clobberd. Therefore
	 * grab a lock so that the output is legible.
	 */
	mutex_enter(&print_pic_lock);
	printf("{CPU-%d} %s:\n", CPU->cpu_id, heading);
	printf("pic addr     : %p\n", (void *)pic);
	printf("name         : %s\n", pic->name);
	printf("pcbe_picno   : %d\n", pic->pcbe_picno);
	printf("counter_bits : 0x%X\n", pic->counter_bits);
	printf("counter_type : 0x%X\n", pic->counter_type);
	printf("toe          : %d\n", pic->toe);
	printf("counter      : 0x%X\n", pic->counter);
	printf("src_type     : 0x%X\n", pic->src_type);
	printf("flags        : 0x%X\n", pic->flags);
	printf("pcbe_pic     : %d\n", (int)pic->pcbe_pic);
	printf("inuse        : %d\n", pic->inuse);
	printf("state        : 0x%X\n", pic->state);
	printf("cpu          : %d\n", pic->cpu);
	if (pic->counter_type == SYNTHETIC_COUNTER) {
		printf("Synthetic counter:\n");
		printf("\tsyn_pic: 0x%X\n", (int)pic->sampler.synthetic_pic);
		printf("\tfreq   : %d\n", pic->sampler.frequency);
		printf("\tsyn_cnt: 0x%X\n", pic->sampler.syn_counter);
		printf("\tsize   : %d bytes\n", pic->sampler.sample_size);
		printf("\tflags  : 0x%X\n", pic->sampler.flags);
		printf("\ttl     : 0x%X\n", pic->sampler.tl);
		printf("\tnohws  : 0x%X\n", pic->sampler.nohws);
		printf("\trbuf   : 0x%p\n", (void *)pic->sampler.ring_buffer);
		if (pic->sampler.ring_buffer) {
			rk_pcbe_ringbuf_t *rb = pic->sampler.ring_buffer;
			printf("\tRingbuffer:\n");
			printf("\t\tHead: 0x%X\n", rb->head);
			printf("\t\tTail: 0x%X\n", rb->tail);
			printf("\t\tSize: 0x%X\n", rb->size);
			printf("\t\tHwm : 0x%X\n", rb->hwm);
		}
	}
	printf("-----------------\n");
	mutex_exit(&print_pic_lock);
}
#endif
