/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <string.h>
#include <alloca.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>

#include "libcpc.h"
#include "libcpc_impl.h"

/*
 * Configuration data for Pentium Pro performance counters.
 *
 * Definitions taken from [3].  See the reference to
 * understand what any of these settings actually means.
 *
 * [3] "Pentium Pro Family Developer's Manual, Volume 3:
 *     Operating Systems Writer's Manual," January 1996
 */

#define	V_P5	(1u << 0)		/* specific to Pentium cpus */
#define	V_P5mmx	(1u << 1)		/* " MMX instructions */
#define	V_P6	(1u << 2)		/* specific to Pentium II cpus */
#define	V_P6mmx	(1u << 3)		/* " MMX instructions */
#define	V_END	0

/*
 * map from "cpu version" to flag bits
 */
static const uint_t cpuvermap[] = {
	V_P5,		/* CPC_PENTIUM */
	V_P5 | V_P5mmx,	/* CPC_PENTIUM_MMX */
	V_P6,		/* CPC_PENTIUM_PRO */
	V_P6 | V_P6mmx,	/* CPC_PENTIUM_PRO_MMX */
};

struct nametable {
	const uint_t	ver;
	const uint8_t	bits;
	const char	*name;
};

/*
 * Basic Pentium events
 */
#define	P5_EVENTS(v)						\
	{v,		0x0,	"data_read"},			\
	{v,		0x1,	"data_write"},			\
	{v,		0x2,	"data_tlb_miss"},		\
	{v,		0x3,	"data_read_miss"},		\
	{v,		0x4,	"data_write_miss"},		\
	{v,		0x5,	"write_hit_to_M_or_E"},		\
	{v,		0x6,	"dcache_lines_wrback"},		\
	{v,		0x7,	"external_snoops"},		\
	{v,		0x8,	"external_dcache_snoop_hits"},	\
	{v,		0x9,	"memory_access_in_both_pipes"},	\
	{v,		0xa,	"bank_conflicts"},		\
	{v,		0xb,	"misaligned_ref"},		\
	{v,		0xc,	"code_read"},			\
	{v,		0xd,	"code_tlb_miss"},		\
	{v,		0xe,	"code_cache_miss"},		\
	{v,		0xf,	"any_segreg_loaded"},		\
	{v,		0x12,	"branches"},			\
	{v,		0x13,	"btb_hits"},			\
	{v,		0x14,	"taken_or_btb_hit"},		\
	{v,		0x15,	"pipeline_flushes"},		\
	{v,		0x16,	"instr_exec"},			\
	{v,		0x17,	"instr_exec_V_pipe"},		\
	{v,		0x18,	"clks_bus_cycle"},		\
	{v,		0x19,	"clks_full_wbufs"},		\
	{v,		0x1a,	"pipe_stall_read"},		\
	{v,		0x1b,	"stall_on_write_ME"},		\
	{v,		0x1c,	"locked_bus_cycle"},		\
	{v,		0x1d,	"io_rw_cycles"},		\
	{v,		0x1e,	"reads_noncache_mem"},		\
	{v,		0x1f,	"pipeline_agi_stalls"},		\
	{v,		0x22,	"flops"},			\
	{v,		0x23,	"bp_match_dr0"},		\
	{v,		0x24,	"bp_match_dr1"},		\
	{v,		0x25,	"bp_match_dr2"},		\
	{v,		0x26,	"bp_match_dr3"},		\
	{v,		0x27,	"hw_intrs"},			\
	{v,		0x28,	"data_rw"},			\
	{v,		0x29,	"data_rw_miss"}

static const struct nametable P5mmx_names0[] = {
	P5_EVENTS(V_P5),
	{V_P5mmx,	0x2a,	"bus_ownership_latency"},
	{V_P5mmx,	0x2b,	"mmx_instr_upipe"},
	{V_P5mmx,	0x2c,	"cache_M_line_sharing"},
	{V_P5mmx,	0x2d,	"emms_instr"},
	{V_P5mmx,	0x2e,	"bus_util_processor"},
	{V_P5mmx,	0x2f,	"sat_mmx_instr"},
	{V_P5mmx,	0x30,	"clks_not_HLT"},
	{V_P5mmx,	0x31,	"mmx_data_read"},
	{V_P5mmx,	0x32,	"clks_fp_stall"},
	{V_P5mmx,	0x33,	"d1_starv_fifo_0"},
	{V_P5mmx,	0x34,	"mmx_data_write"},
	{V_P5mmx,	0x35,	"pipe_flush_wbp"},
	{V_P5mmx,	0x36,	"mmx_misalign_data_refs"},
	{V_P5mmx,	0x37,	"rets_pred_incorrect"},
	{V_P5mmx,	0x38,	"mmx_multiply_unit_interlock"},
	{V_P5mmx,	0x39,	"rets"},
	{V_P5mmx,	0x3a,	"btb_false_entries"},
	{V_P5mmx,	0x3b,	"clocks_stall_full_wb"},
	{V_END}
};

static const struct nametable P5mmx_names1[] = {
	P5_EVENTS(V_P5),
	{V_P5mmx,	0x2a,	"bus_ownership_transfers"},
	{V_P5mmx,	0x2b,	"mmx_instr_vpipe"},
	{V_P5mmx,	0x2c,	"cache_lint_sharing"},
	{V_P5mmx,	0x2d,	"mmx_fp_transitions"},
	{V_P5mmx,	0x2e,	"writes_noncache_mem"},
	{V_P5mmx,	0x2f,	"sats_performed"},
	{V_P5mmx,	0x30,	"clks_dcache_tlb_miss"},
	{V_P5mmx,	0x31,	"mmx_data_read_miss"},
	{V_P5mmx,	0x32,	"taken_br"},
	{V_P5mmx,	0x33,	"d1_starv_fifo_1"},
	{V_P5mmx,	0x34,	"mmx_data_write_miss"},
	{V_P5mmx,	0x35,	"pipe_flush_wbp_wb"},
	{V_P5mmx,	0x36,	"mmx_pipe_stall_data_read"},
	{V_P5mmx,	0x37,	"rets_pred"},
	{V_P5mmx,	0x38,	"movd_movq_stall"},
	{V_P5mmx,	0x39,	"rsb_overflow"},
	{V_P5mmx,	0x3a,	"btb_mispred_nt"},
	{V_P5mmx,	0x3b,	"mmx_stall_write_ME"},
	{V_END}
};

static const struct nametable *P5mmx_names[2] = {
	P5mmx_names0,
	P5mmx_names1
};

/*
 * Pentium Pro and Pentium II events
 */
static const struct nametable P6_names[] = {
	/*
	 * Data cache unit
	 */
	{V_P6,		0x43,	"data_mem_refs"},
	{V_P6,		0x45,	"dcu_lines_in"},
	{V_P6,		0x46,	"dcu_m_lines_in"},
	{V_P6,		0x47,	"dcu_m_lines_out"},
	{V_P6,		0x48,	"dcu_miss_outstanding"},

	/*
	 * Instruction fetch unit
	 */
	{V_P6,		0x80,	"ifu_ifetch"},
	{V_P6,		0x81,	"ifu_ifetch_miss"},
	{V_P6,		0x85,	"itlb_miss"},
	{V_P6,		0x86,	"ifu_mem_stall"},
	{V_P6,		0x87,	"ild_stall"},

	/*
	 * L2 cache
	 */
	{V_P6,		0x28,	"l2_ifetch"},
	{V_P6,		0x29,	"l2_ld"},
	{V_P6,		0x2a,	"l2_st"},
	{V_P6,		0x24,	"l2_lines_in"},
	{V_P6,		0x26,	"l2_lines_out"},
	{V_P6,		0x25,	"l2_m_lines_inm"},
	{V_P6,		0x27,	"l2_m_lines_outm"},
	{V_P6,		0x2e,	"l2_rqsts"},
	{V_P6,		0x21,	"l2_ads"},
	{V_P6,		0x22,	"l2_dbus_busy"},
	{V_P6,		0x23,	"l2_dbus_busy_rd"},

	/*
	 * External bus logic
	 */
	{V_P6,		0x62,	"bus_drdy_clocks"},
	{V_P6,		0x63,	"bus_lock_clocks"},
	{V_P6,		0x60,	"bus_req_outstanding"},
	{V_P6,		0x65,	"bus_tran_brd"},
	{V_P6,		0x66,	"bus_tran_rfo"},
	{V_P6,		0x67,	"bus_trans_wb"},
	{V_P6,		0x68,	"bus_tran_ifetch"},
	{V_P6,		0x69,	"bus_tran_inval"},
	{V_P6,		0x6a,	"bus_tran_pwr"},
	{V_P6,		0x6b,	"bus_trans_p"},
	{V_P6,		0x6c,	"bus_trans_io"},
	{V_P6,		0x6d,	"bus_tran_def"},
	{V_P6,		0x6e,	"bus_tran_burst"},
	{V_P6,		0x70,	"bus_tran_any"},
	{V_P6,		0x6f,	"bus_tran_mem"},
	{V_P6,		0x64,	"bus_data_rcv"},
	{V_P6,		0x61,	"bus_bnr_drv"},
	{V_P6,		0x7a,	"bus_hit_drv"},
	{V_P6,		0x7b,	"bus_hitm_drv"},
	{V_P6,		0x7e,	"bus_snoop_stall"},

	/*
	 * Floating point unit
	 */
	{V_P6,		0xc1,	"flops"},		/* 0 only */
	{V_P6,		0x10,	"fp_comp_ops_exe"},	/* 0 only */
	{V_P6,		0x11,	"fp_assist"},		/* 1 only */
	{V_P6,		0x12,	"mul"},			/* 1 only */
	{V_P6,		0x13,	"div"},			/* 1 only */
	{V_P6,		0x14,	"cycles_div_busy"},	/* 0 only */

	/*
	 * Memory ordering
	 */
	{V_P6,		0x3,	"ld_blocks"},
	{V_P6,		0x4,	"sb_drains"},
	{V_P6,		0x5,	"misalign_mem_ref"},

	/*
	 * Instruction decoding and retirement
	 */
	{V_P6,		0xc0,	"inst_retired"},
	{V_P6,		0xc2,	"uops_retired"},
	{V_P6,		0xd0,	"inst_decoder"},

	/*
	 * Interrupts
	 */
	{V_P6,		0xc8,	"hw_int_rx"},
	{V_P6,		0xc6,	"cycles_int_masked"},
	{V_P6,		0xc7,	"cycles_int_pending_and_masked"},

	/*
	 * Branches
	 */
	{V_P6,		0xc4,	"br_inst_retired"},
	{V_P6,		0xc5,	"br_miss_pred_retired"},
	{V_P6,		0xc9,	"br_taken_retired"},
	{V_P6,		0xca,	"br_miss_pred_taken_ret"},
	{V_P6,		0xe0,	"br_inst_decoded"},
	{V_P6,		0xe2,	"btb_misses"},
	{V_P6,		0xe4,	"br_bogus"},
	{V_P6,		0xe6,	"baclears"},

	/*
	 * Stalls
	 */
	{V_P6,		0xa2,	"resource_stalls"},
	{V_P6,		0xd2,	"partial_rat_stalls"},

	/*
	 * Segment register loads
	 */
	{V_P6,		0x6,	"segment_reg_loads"},

	/*
	 * Clocks
	 */
	{V_P6,		0x79,	"cpu_clk_unhalted"},

	/*
	 * MMX
	 */
	{V_P6mmx,	0xb0,	"mmx_instr_exec"},
	{V_P6mmx,	0xb1,	"mmx_sat_instr_exec"},
	{V_P6mmx,	0xb2,	"mmx_uops_exec"},
	{V_P6mmx,	0xb3,	"mmx_instr_type_exec"},
	{V_P6mmx,	0xcc,	"fp_mmx_trans"},
	{V_P6mmx,	0xcd,	"mmx_assists"},
	{V_P6mmx,	0xce,	"mmx_instr_ret"},
	{V_P6mmx,	0xd4,	"seg_rename_stalls"},
	{V_P6mmx,	0xd5,	"seg_reg_renames"},
	{V_P6mmx,	0xd6,	"ret_seg_renames"},

	{V_END}
};

#define	MAPCPUVER(cpuver)	(cpuvermap[(cpuver) - CPC_PENTIUM])

static int
validargs(int cpuver, int regno)
{
	if (regno < 0 || regno > 1)
		return (0);
	cpuver -= CPC_PENTIUM;
	if (cpuver < 0 ||
	    cpuver >= sizeof (cpuvermap) / sizeof (cpuvermap[0]))
		return (0);
	return (1);
}

/*ARGSUSED*/
static int
versionmatch(int cpuver, int regno, const struct nametable *n)
{
	if (!validargs(cpuver, regno) || (n->ver & MAPCPUVER(cpuver)) == 0)
		return (0);

	switch (MAPCPUVER(cpuver)) {
	case V_P5:
	case V_P5 | V_P5mmx:
		break;
	case V_P6:
	case V_P6 | V_P6mmx:
		switch (n->bits) {
		case 0xc1:	/* flops */
		case 0x10:	/* fp_comp_ops_exe */
		case 0x14:	/* cycles_div_busy */
			/* only reg0 counts these */
			if (regno == 1)
				return (0);
			break;
		case 0x11:	/* fp_assist */
		case 0x12:	/* mul */
		case 0x13:	/* div */
			/* only 1 can count these */
			if (regno == 0)
				return (0);
			break;
		default:
			break;
		}
		break;
	default:
		return (0);
	}

	return (1);
}

static const struct nametable *
getnametable(int cpuver, int regno)
{
	const struct nametable *n;

	if (!validargs(cpuver, regno))
		return (NULL);

	switch (MAPCPUVER(cpuver)) {
	case V_P5:
	case V_P5 | V_P5mmx:
		n = P5mmx_names[regno];
		break;
	case V_P6:
	case V_P6 | V_P6mmx:
		n = P6_names;
		break;
	default:
		n = NULL;
		break;
	}

	return (n);
}

void
cpc_walk_names(int cpuver, int regno, void *arg,
    void (*action)(void *, int, const char *, uint8_t))
{
	const struct nametable *n;

	if ((n = getnametable(cpuver, regno)) == NULL)
		return;
	for (; n->ver != V_END; n++)
		if (versionmatch(cpuver, regno, n))
			action(arg, regno, n->name, n->bits);
}

const char *
__cpc_reg_to_name(int cpuver, int regno, uint8_t bits)
{
	const struct nametable *n;

	if ((n = getnametable(cpuver, regno)) == NULL)
		return (NULL);
	for (; n->ver != V_END; n++)
		if (bits == n->bits && versionmatch(cpuver, regno, n))
			return (n->name);
	return (NULL);
}

/*
 * Register names can be specified as strings or even as numbers
 */
int
__cpc_name_to_reg(int cpuver, int regno, const char *name, uint8_t *bits)
{
	const struct nametable *n;
	char *eptr = NULL;
	long value;

	if ((n = getnametable(cpuver, regno)) == NULL || name == NULL)
		return (-1);
	for (; n->ver != V_END; n++)
		if (strcmp(name, n->name) == 0 &&
		    versionmatch(cpuver, regno, n)) {
			*bits = n->bits;
			return (0);
		}

	value = strtol(name, &eptr, 0);
	if (name != eptr && value >= 0 && value <= UINT8_MAX) {
		*bits = (uint8_t)value;
		return (0);
	}

	return (-1);
}

const char *
cpc_getcciname(int cpuver)
{
	if (validargs(cpuver, 0))
		switch (MAPCPUVER(cpuver)) {
		case V_P5:
			return ("Pentium");
		case V_P5 | V_P5mmx:
			return ("Pentium with MMX");
		case V_P6:
			return ("Pentium Pro, Pentium II");
		case V_P6 | V_P6mmx:
			return ("Pentium Pro with MMX, Pentium II");
		default:
			break;
		}
	return (NULL);
}

const char *
cpc_getcpuref(int cpuver)
{
	if (validargs(cpuver, 0))
		switch (MAPCPUVER(cpuver)) {
		case V_P5:
		case V_P5 | V_P5mmx:
			return (gettext(
			    "See Appendix A.2 of the \"Intel Architecture "
			    "Software Developer's Manual,\" 243192, 1997"));
		case V_P6:
		case V_P6 | V_P6mmx:
			return (gettext(
			    "See Appendix A.1 of the \"Intel Architecture "
			    "Software Developer's Manual,\" 243192, 1997"));
		default:
			break;
		}
	return (NULL);
}

/*
 * This is a functional interface to allow CPUs with fewer %pic registers
 * to share the same data structure as those with more %pic registers
 * within the same instruction set family.
 */
uint_t
cpc_getnpic(int cpuver)
{
	switch (cpuver) {
	case CPC_PENTIUM:
	case CPC_PENTIUM_MMX:
	case CPC_PENTIUM_PRO:
	case CPC_PENTIUM_PRO_MMX:
#define	EVENT	((cpc_event_t *)0)
		return (sizeof (EVENT->ce_pic) / sizeof	(EVENT->ce_pic[0]));
#undef	EVENT
	default:
		return (0);
	}
}

#define	BITS(v, u, l)	\
	(((v) >> (l)) & ((1 << (1 + (u) - (l))) - 1))

#include "getcpuid.h"

/*
 * Return the version of the current processor.
 *
 * Version -1 is defined as 'not performance counter capable'
 */
int
cpc_getcpuver(void)
{
	static int ver = -1;
	uint32_t maxeax;
	uint32_t vbuf[4];

	if (ver != -1)
		return (ver);

	maxeax = cpc_getcpuid(0, &vbuf[0], &vbuf[2], &vbuf[1]);
	{
		char *vendor = (char *)vbuf;
		vendor[12] = '\0';

		if (strcmp(vendor, "GenuineIntel") != 0)
			return (ver);
	}

	if (maxeax >= 1) {
		int family, model;
		uint32_t eax, ebx, ecx, edx;

		eax = cpc_getcpuid(1, &ebx, &ecx, &edx);

		if ((family = BITS(eax, 11, 8)) == 0xf)
			family = BITS(eax, 27, 20);
		if ((model = BITS(eax, 7, 4)) == 0xf)
			model = BITS(eax, 19, 16);

		/*
		 * map family and model into the performance
		 * counter architectures we currently understand.
		 *
		 * See application note AP485 (from developer.intel.com)
		 * for further explanation.
		 */
		switch (family) {
		case 5:		/* Pentium and Pentium with MMX */
			ver = model < 4 ?
				CPC_PENTIUM : CPC_PENTIUM_MMX;
			break;
		case 6:		/* Pentium Pro and Pentium II and III */
			ver = BITS(edx, 23, 23) ?	   /* mmx check */
				CPC_PENTIUM_PRO_MMX : CPC_PENTIUM_PRO;
			break;
		default:
		case 0xf:	/* Pentium IV */
			break;
		}
	}

	return (ver);
}
