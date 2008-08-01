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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Performance Counter Back-End for Pentiums I, II, and III.
 */

#include <sys/cpuvar.h>
#include <sys/param.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/modctl.h>
#include <sys/inttypes.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/x86_archext.h>
#include <sys/sdt.h>
#include <sys/archsystm.h>
#include <sys/privregs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

static int64_t diff3931(uint64_t sample, uint64_t old);
static uint64_t trunc3931(uint64_t value);

static int ptm_pcbe_init(void);
static uint_t ptm_pcbe_ncounters(void);
static const char *ptm_pcbe_impl_name(void);
static const char *ptm_pcbe_cpuref(void);
static char *ptm_pcbe_list_events(uint_t picnum);
static char *ptm_pcbe_list_attrs(void);
static uint64_t ptm_pcbe_event_coverage(char *event);
static int ptm_pcbe_pic_index(char *picname);
static uint64_t	ptm_pcbe_overflow_bitmap(void);
static int ptm_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void ptm_pcbe_program(void *token);
static void ptm_pcbe_allstop(void);
static void ptm_pcbe_sample(void *token);
static void ptm_pcbe_free(void *config);

pcbe_ops_t ptm_pcbe_ops = {
	PCBE_VER_1,
	0,
	ptm_pcbe_ncounters,
	ptm_pcbe_impl_name,
	ptm_pcbe_cpuref,
	ptm_pcbe_list_events,
	ptm_pcbe_list_attrs,
	ptm_pcbe_event_coverage,
	ptm_pcbe_overflow_bitmap,
	ptm_pcbe_configure,
	ptm_pcbe_program,
	ptm_pcbe_allstop,
	ptm_pcbe_sample,
	ptm_pcbe_free
};

typedef enum _ptm_ver {
	PTM_VER_P5,
	PTM_VER_P6
} ptm_ver_t;

static ptm_ver_t ptm_ver;
static const char *ptm_impl_name;
static const char *ptm_cpuref;
static char *pic_events[2] = { NULL, NULL };

/*
 * Indicates whether the "rdpmc" instruction is available on this processor.
 */
static int ptm_rdpmc_avail = 0;

#define	ALL_STOPPED	0ULL

typedef struct _ptm_pcbe_config {
	uint8_t		ptm_picno;	/* 0 for pic0 or 1 for pic1 */
	uint32_t	ptm_ctl;    /* P6: PerfEventSelect; P5: cesr, shifted */
	uint64_t	ptm_rawpic;
} ptm_pcbe_config_t;

struct nametable {
	uint8_t		bits;
	const char	*name;
};

#define	NT_END 0xFF

/*
 * Basic Pentium events
 */
#define	P5_EVENTS				\
	{0x0,	"data_read"},			\
	{0x1,	"data_write"},			\
	{0x2,	"data_tlb_miss"},		\
	{0x3,	"data_read_miss"},		\
	{0x4,	"data_write_miss"},		\
	{0x5,	"write_hit_to_M_or_E"},		\
	{0x6,	"dcache_lines_wrback"},		\
	{0x7,	"external_snoops"},		\
	{0x8,	"external_dcache_snoop_hits"},	\
	{0x9,	"memory_access_in_both_pipes"},	\
	{0xa,	"bank_conflicts"},		\
	{0xb,	"misaligned_ref"},		\
	{0xc,	"code_read"},			\
	{0xd,	"code_tlb_miss"},		\
	{0xe,	"code_cache_miss"},		\
	{0xf,	"any_segreg_loaded"},		\
	{0x12,	"branches"},			\
	{0x13,	"btb_hits"},			\
	{0x14,	"taken_or_btb_hit"},		\
	{0x15,	"pipeline_flushes"},		\
	{0x16,	"instr_exec"},			\
	{0x17,	"instr_exec_V_pipe"},		\
	{0x18,	"clks_bus_cycle"},		\
	{0x19,	"clks_full_wbufs"},		\
	{0x1a,	"pipe_stall_read"},		\
	{0x1b,	"stall_on_write_ME"},		\
	{0x1c,	"locked_bus_cycle"},		\
	{0x1d,	"io_rw_cycles"},		\
	{0x1e,	"reads_noncache_mem"},		\
	{0x1f,	"pipeline_agi_stalls"},		\
	{0x22,	"flops"},			\
	{0x23,	"bp_match_dr0"},		\
	{0x24,	"bp_match_dr1"},		\
	{0x25,	"bp_match_dr2"},		\
	{0x26,	"bp_match_dr3"},		\
	{0x27,	"hw_intrs"},			\
	{0x28,	"data_rw"},			\
	{0x29,	"data_rw_miss"}

static const struct nametable P5mmx_names0[] = {
	P5_EVENTS,
	{0x2a,	"bus_ownership_latency"},
	{0x2b,	"mmx_instr_upipe"},
	{0x2c,	"cache_M_line_sharing"},
	{0x2d,	"emms_instr"},
	{0x2e,	"bus_util_processor"},
	{0x2f,	"sat_mmx_instr"},
	{0x30,	"clks_not_HLT"},
	{0x31,	"mmx_data_read"},
	{0x32,	"clks_fp_stall"},
	{0x33,	"d1_starv_fifo_0"},
	{0x34,	"mmx_data_write"},
	{0x35,	"pipe_flush_wbp"},
	{0x36,	"mmx_misalign_data_refs"},
	{0x37,	"rets_pred_incorrect"},
	{0x38,	"mmx_multiply_unit_interlock"},
	{0x39,	"rets"},
	{0x3a,	"btb_false_entries"},
	{0x3b,	"clocks_stall_full_wb"},
	{NT_END, ""}
};

static const struct nametable P5mmx_names1[] = {
	P5_EVENTS,
	{0x2a,	"bus_ownership_transfers"},
	{0x2b,	"mmx_instr_vpipe"},
	{0x2c,	"cache_lint_sharing"},
	{0x2d,	"mmx_fp_transitions"},
	{0x2e,	"writes_noncache_mem"},
	{0x2f,	"sats_performed"},
	{0x30,	"clks_dcache_tlb_miss"},
	{0x31,	"mmx_data_read_miss"},
	{0x32,	"taken_br"},
	{0x33,	"d1_starv_fifo_1"},
	{0x34,	"mmx_data_write_miss"},
	{0x35,	"pipe_flush_wbp_wb"},
	{0x36,	"mmx_pipe_stall_data_read"},
	{0x37,	"rets_pred"},
	{0x38,	"movd_movq_stall"},
	{0x39,	"rsb_overflow"},
	{0x3a,	"btb_mispred_nt"},
	{0x3b,	"mmx_stall_write_ME"},
	{NT_END, ""}
};

static const struct nametable *P5mmx_names[2] = {
	P5mmx_names0,
	P5mmx_names1
};

/*
 * Pentium Pro and Pentium II events
 */
static const struct nametable _P6_names[] = {
	/*
	 * Data cache unit
	 */
	{0x43,	"data_mem_refs"},
	{0x45,	"dcu_lines_in"},
	{0x46,	"dcu_m_lines_in"},
	{0x47,	"dcu_m_lines_out"},
	{0x48,	"dcu_miss_outstanding"},

	/*
	 * Instruction fetch unit
	 */
	{0x80,	"ifu_ifetch"},
	{0x81,	"ifu_ifetch_miss"},
	{0x85,	"itlb_miss"},
	{0x86,	"ifu_mem_stall"},
	{0x87,	"ild_stall"},

	/*
	 * L2 cache
	 */
	{0x28,	"l2_ifetch"},
	{0x29,	"l2_ld"},
	{0x2a,	"l2_st"},
	{0x24,	"l2_lines_in"},
	{0x26,	"l2_lines_out"},
	{0x25,	"l2_m_lines_inm"},
	{0x27,	"l2_m_lines_outm"},
	{0x2e,	"l2_rqsts"},
	{0x21,	"l2_ads"},
	{0x22,	"l2_dbus_busy"},
	{0x23,	"l2_dbus_busy_rd"},

	/*
	 * External bus logic
	 */
	{0x62,	"bus_drdy_clocks"},
	{0x63,	"bus_lock_clocks"},
	{0x60,	"bus_req_outstanding"},
	{0x65,	"bus_tran_brd"},
	{0x66,	"bus_tran_rfo"},
	{0x67,	"bus_trans_wb"},
	{0x68,	"bus_tran_ifetch"},
	{0x69,	"bus_tran_inval"},
	{0x6a,	"bus_tran_pwr"},
	{0x6b,	"bus_trans_p"},
	{0x6c,	"bus_trans_io"},
	{0x6d,	"bus_tran_def"},
	{0x6e,	"bus_tran_burst"},
	{0x70,	"bus_tran_any"},
	{0x6f,	"bus_tran_mem"},
	{0x64,	"bus_data_rcv"},
	{0x61,	"bus_bnr_drv"},
	{0x7a,	"bus_hit_drv"},
	{0x7b,	"bus_hitm_drv"},
	{0x7e,	"bus_snoop_stall"},

	/*
	 * Floating point unit
	 */
	{0xc1,	"flops"},		/* 0 only */
	{0x10,	"fp_comp_ops_exe"},	/* 0 only */
	{0x11,	"fp_assist"},		/* 1 only */
	{0x12,	"mul"},			/* 1 only */
	{0x13,	"div"},			/* 1 only */
	{0x14,	"cycles_div_busy"},	/* 0 only */

	/*
	 * Memory ordering
	 */
	{0x3,	"ld_blocks"},
	{0x4,	"sb_drains"},
	{0x5,	"misalign_mem_ref"},

	/*
	 * Instruction decoding and retirement
	 */
	{0xc0,	"inst_retired"},
	{0xc2,	"uops_retired"},
	{0xd0,	"inst_decoder"},

	/*
	 * Interrupts
	 */
	{0xc8,	"hw_int_rx"},
	{0xc6,	"cycles_int_masked"},
	{0xc7,	"cycles_int_pending_and_masked"},

	/*
	 * Branches
	 */
	{0xc4,	"br_inst_retired"},
	{0xc5,	"br_miss_pred_retired"},
	{0xc9,	"br_taken_retired"},
	{0xca,	"br_miss_pred_taken_ret"},
	{0xe0,	"br_inst_decoded"},
	{0xe2,	"btb_misses"},
	{0xe4,	"br_bogus"},
	{0xe6,	"baclears"},

	/*
	 * Stalls
	 */
	{0xa2,	"resource_stalls"},
	{0xd2,	"partial_rat_stalls"},

	/*
	 * Segment register loads
	 */
	{0x6,	"segment_reg_loads"},

	/*
	 * Clocks
	 */
	{0x79,	"cpu_clk_unhalted"},

	/*
	 * MMX
	 */
	{0xb0,	"mmx_instr_exec"},
	{0xb1,	"mmx_sat_instr_exec"},
	{0xb2,	"mmx_uops_exec"},
	{0xb3,	"mmx_instr_type_exec"},
	{0xcc,	"fp_mmx_trans"},
	{0xcd,	"mmx_assists"},
	{0xce,	"mmx_instr_ret"},
	{0xd4,	"seg_rename_stalls"},
	{0xd5,	"seg_reg_renames"},
	{0xd6,	"ret_seg_renames"},

	{NT_END, ""}
};

static const struct nametable *P6_names[2] = {
	_P6_names,
	_P6_names
};

static const struct nametable **events;

#define	BITS(v, u, l)	\
	(((v) >> (l)) & ((1 << (1 + (u) - (l))) - 1))

/*
 * "Well known" bit fields in the Pentium CES register
 * The interfaces in libcpc should make these #defines uninteresting.
 */
#define	CPC_P5_CESR_ES0_SHIFT	0
#define	CPC_P5_CESR_ES0_MASK	0x3f
#define	CPC_P5_CESR_ES1_SHIFT	16
#define	CPC_P5_CESR_ES1_MASK	0x3f

#define	CPC_P5_CESR_OS0		6
#define	CPC_P5_CESR_USR0	7
#define	CPC_P5_CESR_CLK0	8
#define	CPC_P5_CESR_PC0		9
#define	CPC_P5_CESR_OS1		(CPC_P5_CESR_OS0 + 16)
#define	CPC_P5_CESR_USR1	(CPC_P5_CESR_USR0 + 16)
#define	CPC_P5_CESR_CLK1	(CPC_P5_CESR_CLK0 + 16)
#define	CPC_P5_CESR_PC1		(CPC_P5_CESR_PC0 + 16)

/*
 * "Well known" bit fields in the Pentium Pro PerfEvtSel registers
 * The interfaces in libcpc should make these #defines uninteresting.
 */
#define	CPC_P6_PES_INV		23
#define	CPC_P6_PES_EN		22
#define	CPC_P6_PES_INT		20
#define	CPC_P6_PES_PC		19
#define	CPC_P6_PES_E		18
#define	CPC_P6_PES_OS		17
#define	CPC_P6_PES_USR		16

#define	CPC_P6_PES_UMASK_SHIFT	8
#define	CPC_P6_PES_UMASK_MASK	(0xffu)

#define	CPC_P6_PES_CMASK_SHIFT	24
#define	CPC_P6_PES_CMASK_MASK	(0xffu)

#define	CPC_P6_PES_PIC0_MASK	(0xffu)
#define	CPC_P6_PES_PIC1_MASK	(0xffu)

#define	P6_PES_EN	(UINT32_C(1) << CPC_P6_PES_EN)
#define	P6_PES_INT	(UINT32_C(1) << CPC_P6_PES_INT)
#define	P6_PES_OS	(UINT32_C(1) << CPC_P6_PES_OS)

/*
 * Pentium 5 attributes
 */
#define	P5_NOEDGE	0x1	/* "noedge"	- no edge detection */
#define	P5_PC		0x2	/* "pc"		- pin control */

/*
 * Pentium 6 attributes
 */
#define	P6_NOEDGE	0x1
#define	P6_PC		0x2
#define	P6_INV		0x4	/* "inv" - count inverted transitions */
#define	P6_INT		0x8	/* "int" - interrupt on overflow */

/*
 * CPU reference strings
 */

#define	P5_CPUREF	"See Appendix A.4 of the \"IA-32 Intel Architecture "  \
			"Software Developer's Manual Volume 3: System "	       \
			"Programming Guide,\" Order # 245472-012, 2003"

#define	P6_CPUREF	"See Appendix A.3 of the \"IA-32 Intel Architecture "  \
			"Software Developer's Manual Volume 3: System "	       \
			"Programming Guide,\" Order # 245472-012, 2003"

static int
ptm_pcbe_init(void)
{
	const struct nametable	*n;
	int			i;
	size_t			size;

	if (x86_feature & X86_MMX)
		ptm_rdpmc_avail = 1;

	/*
	 * Discover type of CPU and set events pointer appropriately.
	 *
	 * Map family and model into the performance
	 * counter architectures we currently understand.
	 *
	 * See application note AP485 (from developer.intel.com)
	 * for further explanation.
	 */
	if (cpuid_getvendor(CPU) != X86_VENDOR_Intel)
		return (-1);
	switch (cpuid_getfamily(CPU)) {
	case 5:		/* Pentium and Pentium with MMX */
		events = P5mmx_names;
		ptm_ver = PTM_VER_P5;
		ptm_cpuref = P5_CPUREF;
		if (cpuid_getmodel(CPU) < 4)
			ptm_impl_name = "Pentium";
		else
			ptm_impl_name = "Pentium with MMX";
		break;
	case 6:		/* Pentium Pro and Pentium II and III */
		events = P6_names;
		ptm_ver = PTM_VER_P6;
		ptm_cpuref = P6_CPUREF;
		ptm_pcbe_ops.pcbe_caps = CPC_CAP_OVERFLOW_INTERRUPT;
		if (x86_feature & X86_MMX)
			ptm_impl_name = "Pentium Pro with MMX, Pentium II";
		else
			ptm_impl_name = "Pentium Pro, Pentium II";
		break;
	default:
		return (-1);
	}

	/*
	 * Initialize the list of events for each PIC.
	 * Do two passes: one to compute the size necessary and another
	 * to copy the strings. Need room for event, comma, and NULL terminator.
	 */
	for (i = 0; i < 2; i++) {
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
	}

	return (0);
}

static uint_t
ptm_pcbe_ncounters(void)
{
	return (2);
}

static const char *
ptm_pcbe_impl_name(void)
{
	return (ptm_impl_name);
}

static const char *
ptm_pcbe_cpuref(void)
{
	return (ptm_cpuref);
}

static char *
ptm_pcbe_list_events(uint_t picnum)
{
	ASSERT(picnum >= 0 && picnum < cpc_ncounters);

	if (pic_events[0] == NULL) {
		ASSERT(pic_events[1] == NULL);
	}

	return (pic_events[picnum]);
}

static char *
ptm_pcbe_list_attrs(void)
{
	if (ptm_ver == PTM_VER_P5)
		return ("noedge,pc");
	else
		return ("noedge,pc,inv,int,umask,cmask");
}

static const struct nametable *
find_event(int regno, char *name)
{
	const struct nametable *n;

	n = events[regno];

	for (; n->bits != NT_END; n++)
		if (strcmp(name, n->name) == 0)
			return (n);

	return (NULL);
}

static uint64_t
ptm_pcbe_event_coverage(char *event)
{
	uint64_t bitmap = 0;

	if (find_event(0, event) != NULL)
		bitmap = 0x1;
	if (find_event(1, event) != NULL)
		bitmap |= 0x2;

	return (bitmap);
}

static uint64_t
ptm_pcbe_overflow_bitmap(void)
{
	uint64_t	ret = 0;
	uint64_t	pes[2];

	/*
	 * P5 is not capable of generating interrupts.
	 */
	ASSERT(ptm_ver == PTM_VER_P6);

	/*
	 * CPC could have caused an interrupt provided that
	 *
	 * 1) Counters are enabled
	 * 2) Either counter has requested an interrupt
	 */

	pes[0] = rdmsr(REG_PERFEVNT0);
	if (((uint32_t)pes[0] & P6_PES_EN) != P6_PES_EN)
		return (0);

	/*
	 * If a particular counter requested an interrupt, assume it caused
	 * this interrupt. There is no way to determine which counter overflowed
	 * on this hardware other than by using unreliable heuristics.
	 */

	pes[1] = rdmsr(REG_PERFEVNT1);
	if ((uint32_t)pes[0] & P6_PES_INT)
		ret |= 0x1;
	if ((uint32_t)pes[1] & P6_PES_INT)
		ret |= 0x2;

	return (ret);
}

/*ARGSUSED*/
static int
ptm_pcbe_configure(uint_t picnum, char *eventname, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token)
{
	ptm_pcbe_config_t	*conf;
	const struct nametable	*n;
	struct nametable	nt_raw = { 0, "raw" };
	int			i;
	int			ptm_flags = 0;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		conf = *data;
		conf->ptm_rawpic = trunc3931(preset);
		return (0);
	}

	if (picnum != 0 && picnum != 1)
		return (CPC_INVALID_PICNUM);

	if ((n = find_event(picnum, eventname)) == NULL) {
		long tmp;

		/*
		 * If ddi_strtol() likes this event, use it as a raw event code.
		 */
		if (ddi_strtol(eventname, NULL, 0, &tmp) != 0)
			return (CPC_INVALID_EVENT);

		nt_raw.bits = tmp;

		if (ptm_ver == PTM_VER_P5)
			nt_raw.bits &= CPC_P5_CESR_ES0_MASK;
		else
			nt_raw.bits &= CPC_P6_PES_PIC0_MASK;

		n = &nt_raw;
	}

	conf = kmem_alloc(sizeof (ptm_pcbe_config_t), KM_SLEEP);

	conf->ptm_picno = picnum;
	conf->ptm_rawpic = trunc3931(preset);
	conf->ptm_ctl = 0;

	if (ptm_ver == PTM_VER_P5) {
		int picshift;
		picshift = (picnum == 0) ? 0 : 16;

		for (i = 0; i < nattrs; i++) {
			/*
			 * Value of these attributes is ignored; their presence
			 * alone tells us to set the corresponding flag.
			 */
			if (strncmp(attrs[i].ka_name, "noedge", 7) == 0) {
				if (attrs[i].ka_val != 0)
					ptm_flags |= P5_NOEDGE;
			} else if (strncmp(attrs[i].ka_name, "pc", 3) == 0) {
				if (attrs[i].ka_val != 0)
					ptm_flags |= P5_PC;
			} else {
				kmem_free(conf, sizeof (ptm_pcbe_config_t));
				return (CPC_INVALID_ATTRIBUTE);
			}
		}

		if (flags & CPC_COUNT_USER)
			conf->ptm_ctl |= (1 << (CPC_P5_CESR_USR0 + picshift));
		if (flags & CPC_COUNT_SYSTEM)
			conf->ptm_ctl |= (1 << (CPC_P5_CESR_OS0 + picshift));
		if (ptm_flags & P5_NOEDGE)
			conf->ptm_ctl |= (1 << (CPC_P5_CESR_CLK0 + picshift));
		if (ptm_flags & P5_PC)
			conf->ptm_ctl |= (1 << (CPC_P5_CESR_PC0 + picshift));

		ASSERT((n->bits | CPC_P5_CESR_ES0_MASK) ==
		    CPC_P5_CESR_ES0_MASK);

		conf->ptm_ctl |= (n->bits << picshift);
	} else {
		for (i = 0; i < nattrs; i++) {
			if (strncmp(attrs[i].ka_name, "noedge", 6) == 0) {
				if (attrs[i].ka_val != 0)
					ptm_flags |= P6_NOEDGE;
			} else if (strncmp(attrs[i].ka_name, "pc", 2) == 0) {
				if (attrs[i].ka_val != 0)
					ptm_flags |= P6_PC;
			} else if (strncmp(attrs[i].ka_name, "inv", 3) == 0) {
				if (attrs[i].ka_val != 0)
					ptm_flags |= P6_INV;
			} else if (strncmp(attrs[i].ka_name, "umask", 5) == 0) {
				if ((attrs[i].ka_val | CPC_P6_PES_UMASK_MASK) !=
				    CPC_P6_PES_UMASK_MASK) {
					kmem_free(conf,
					    sizeof (ptm_pcbe_config_t));
					return (CPC_ATTRIBUTE_OUT_OF_RANGE);
				}
				conf->ptm_ctl |= (uint8_t)attrs[i].ka_val <<
				    CPC_P6_PES_UMASK_SHIFT;
			} else if (strncmp(attrs[i].ka_name, "cmask", 5) == 0) {
				if ((attrs[i].ka_val | CPC_P6_PES_CMASK_MASK) !=
				    CPC_P6_PES_CMASK_MASK) {
					kmem_free(conf,
					    sizeof (ptm_pcbe_config_t));
					return (CPC_ATTRIBUTE_OUT_OF_RANGE);
				}
				conf->ptm_ctl |= (uint8_t)attrs[i].ka_val <<
				    CPC_P6_PES_CMASK_SHIFT;
			} else if (strncmp(attrs[i].ka_name, "int", 3) == 0) {
				if (attrs[i].ka_val != 0)
					ptm_flags |= P6_INT;
			} else {
				kmem_free(conf, sizeof (ptm_pcbe_config_t));
				return (CPC_INVALID_ATTRIBUTE);
			}
		}

		if (flags & CPC_OVF_NOTIFY_EMT)
			/*
			 * If the user has requested notification of overflows,
			 * we automatically program the hardware to generate
			 * overflow interrupts.
			 */
			ptm_flags |= P6_INT;
		if (flags & CPC_COUNT_USER)
			conf->ptm_ctl |= (1 << CPC_P6_PES_USR);
		if (flags & CPC_COUNT_SYSTEM)
			conf->ptm_ctl |= (1 << CPC_P6_PES_OS);
		if ((ptm_flags & P6_NOEDGE) == 0)
			conf->ptm_ctl |= (1 << CPC_P6_PES_E);
		if (ptm_flags & P6_PC)
			conf->ptm_ctl |= (1 << CPC_P6_PES_PC);
		if (ptm_flags & P6_INV)
			conf->ptm_ctl |= (1 << CPC_P6_PES_INV);
		if (ptm_flags & P6_INT)
			conf->ptm_ctl |= (1 << CPC_P6_PES_INT);

		ASSERT((n->bits | CPC_P6_PES_PIC0_MASK) ==
		    CPC_P6_PES_PIC0_MASK);

		conf->ptm_ctl |= n->bits;
	}

	*data = conf;
	return (0);
}

static void
ptm_pcbe_program(void *token)
{
	ptm_pcbe_config_t	*pic0;
	ptm_pcbe_config_t	*pic1;
	ptm_pcbe_config_t	*tmp;
	ptm_pcbe_config_t	empty = { 1, 0, 0 }; /* assume pic1 to start */

	if ((pic0 = kcpc_next_config(token, NULL, NULL)) == NULL)
		panic("ptm_pcbe: token %p has no configs", token);

	if ((pic1 = kcpc_next_config(token, pic0, NULL)) == NULL)
		pic1 = &empty;

	if (pic0->ptm_picno != 0) {
		empty.ptm_picno = 0;
		tmp = pic1;
		pic1 = pic0;
		pic0 = tmp;
	}

	ASSERT(pic0->ptm_picno == 0 && pic1->ptm_picno == 1);

	if (ptm_rdpmc_avail) {
		ulong_t curcr4 = getcr4();
		if (kcpc_allow_nonpriv(token))
			setcr4(curcr4 | CR4_PCE);
		else
			setcr4(curcr4 & ~CR4_PCE);
	}

	if (ptm_ver == PTM_VER_P5) {
		wrmsr(P5_CESR, ALL_STOPPED);
		wrmsr(P5_CTR0, pic0->ptm_rawpic);
		wrmsr(P5_CTR1, pic1->ptm_rawpic);
		wrmsr(P5_CESR, pic0->ptm_ctl | pic1->ptm_ctl);
		pic0->ptm_rawpic = rdmsr(P5_CTR0);
		pic1->ptm_rawpic = rdmsr(P5_CTR1);
	} else {
		uint64_t	pes;
		wrmsr(REG_PERFEVNT0, ALL_STOPPED);
		wrmsr(REG_PERFCTR0, pic0->ptm_rawpic);
		wrmsr(REG_PERFCTR1, pic1->ptm_rawpic);
		pes = pic1->ptm_ctl;
		DTRACE_PROBE1(ptm__pes1, uint64_t, pes);
		wrmsr(REG_PERFEVNT1, pes);
		pes = pic0->ptm_ctl | (1 << CPC_P6_PES_EN);
		DTRACE_PROBE1(ptm__pes0, uint64_t, pes);
		wrmsr(REG_PERFEVNT0, pes);
	}
}

static void
ptm_pcbe_allstop(void)
{
	if (ptm_ver == PTM_VER_P5)
		wrmsr(P5_CESR, ALL_STOPPED);
	else {
		wrmsr(REG_PERFEVNT0, ALL_STOPPED);
		setcr4(getcr4() & ~CR4_PCE);
	}
}

static void
ptm_pcbe_sample(void *token)
{
	ptm_pcbe_config_t	*pic0;
	ptm_pcbe_config_t	*pic1;
	ptm_pcbe_config_t	*swap;
	ptm_pcbe_config_t	empty = { 1, 0, 0 }; /* assume pic1 to start */
	uint64_t		tmp;
	uint64_t		*pic0_data;
	uint64_t		*pic1_data;
	uint64_t		*dtmp;
	uint64_t		curpic[2];

	if ((pic0 = kcpc_next_config(token, NULL, &pic0_data)) == NULL)
		panic("ptm_pcbe: token %p has no configs", token);

	if ((pic1 = kcpc_next_config(token, pic0, &pic1_data)) == NULL) {
		pic1 = &empty;
		pic1_data = &tmp;
	}

	if (pic0->ptm_picno != 0) {
		empty.ptm_picno = 0;
		swap = pic0;
		pic0 = pic1;
		pic1 = swap;
		dtmp = pic0_data;
		pic0_data = pic1_data;
		pic1_data = dtmp;
	}

	ASSERT(pic0->ptm_picno == 0 && pic1->ptm_picno == 1);

	if (ptm_ver == PTM_VER_P5) {
		curpic[0] = rdmsr(P5_CTR0);
		curpic[1] = rdmsr(P5_CTR1);
	} else {
		curpic[0] = rdmsr(REG_PERFCTR0);
		curpic[1] = rdmsr(REG_PERFCTR1);
	}

	DTRACE_PROBE1(ptm__curpic0, uint64_t, curpic[0]);
	DTRACE_PROBE1(ptm__curpic1, uint64_t, curpic[1]);

	*pic0_data += diff3931(curpic[0], pic0->ptm_rawpic);
	pic0->ptm_rawpic = trunc3931(*pic0_data);

	*pic1_data += diff3931(curpic[1], pic1->ptm_rawpic);
	pic1->ptm_rawpic = trunc3931(*pic1_data);
}

static void
ptm_pcbe_free(void *config)
{
	kmem_free(config, sizeof (ptm_pcbe_config_t));
}

/*
 * Virtualizes the 40-bit field of the %pic
 * register into a 64-bit software register.
 *
 * We can retrieve 40 (signed) bits from the counters,
 * but we can set only 32 (signed) bits into the counters.
 * This makes virtualizing more than 31-bits of registers
 * quite tricky.
 *
 * If bits 39 to 31 are set in the virtualized pic register,
 * then we can preset the counter to this value using the fact
 * that wrmsr sign extends bit 31.   Though it might look easier
 * to only use the bottom 31-bits of the register, we have to allow
 * the full 40-bits to be used to perform overflow profiling.
 */

#define	MASK40		UINT64_C(0xffffffffff)
#define	MASK31		UINT64_C(0x7fffffff)
#define	BITS_39_31	UINT64_C(0xff80000000)

static int64_t
diff3931(uint64_t sample, uint64_t old)
{
	int64_t diff;

	if ((old & BITS_39_31) == BITS_39_31) {
		diff = (MASK40 & sample) - old;
		if (diff < 0)
			diff += (UINT64_C(1) << 40);
	} else {
		diff = (MASK31 & sample) - old;
		if (diff < 0)
			diff += (UINT64_C(1) << 31);
	}
	return (diff);
}

static uint64_t
trunc3931(uint64_t value)
{
	if ((value & BITS_39_31) == BITS_39_31)
		return (MASK40 & value);
	return (MASK31 & value);
}

static struct modlpcbe modlpcbe = {
	&mod_pcbeops,
	"Pentium Performance Counters",
	&ptm_pcbe_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modlpcbe,
};

int
_init(void)
{
	if (ptm_pcbe_init() != 0)
		return (ENOTSUP);
	return (mod_install(&modl));
}

int
_fini(void)
{
	return (mod_remove(&modl));
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&modl, mi));
}
