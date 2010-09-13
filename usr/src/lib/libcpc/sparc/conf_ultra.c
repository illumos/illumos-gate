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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <string.h>
#include <alloca.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <libdevinfo.h>

#include "libcpc.h"
#include "libcpc_impl.h"

/*
 * Configuration data for UltraSPARC performance counters.
 *
 * Definitions taken from [1], [2], [3]  [4] and [5].  See the references to
 * understand what any of these settings actually means.
 *
 * Note that in the current draft of [2], there is some re-use
 * of existing bit assignments in the various fields of the %pcr
 * register - this may change before FCS.
 *
 * The following are the Internal Documents. Customers need to be
 * told about the Public docs in cpc_getcpuref().
 * [1] "UltraSPARC I & II User's Manual," January 1997.
 * [2] "UltraSPARC-III Programmer's Reference Manual," April 1999.
 * [3] "Cheetah+ Programmer's Reference Manual," November 2000.
 * [4] "UltraSPARC-IIIi Programmer's Reference Manual," November 2000.
 * [5] "UltraSPARC-IV+ Programmer's Reference Manual," October 2004.
 */

#define	V_US12		(1u << 0)	/* specific to UltraSPARC 1 and 2 */
#define	V_US3		(1u << 1)	/* specific to UltraSPARC 3 */
#define	V_US3_PLUS	(1u << 2)	/* specific to UltraSPARC 3 PLUS */
#define	V_US3_I		(1u << 3)	/* specific to UltraSPARC-IIIi */
#define	V_US4_PLUS	(1u << 4)	/* specific to UltraSPARC-IV+ */
#define	V_END		(1u << 31)

/*
 * map from "cpu version" to flag bits
 */
static const uint_t cpuvermap[] = {
	V_US12,			/* CPC_ULTRA1 */
	V_US12,			/* CPC_ULTRA2 */
	V_US3,			/* CPC_ULTRA3 */
	V_US3_PLUS,		/* CPC_ULTRA3_PLUS */
	V_US3_I,		/* CPC_ULTRA3I */
	V_US4_PLUS		/* CPC_ULTRA4_PLUS */
};

struct nametable {
	const uint_t	ver;
	const uint8_t	bits;
	const char	*name;
};

/*
 * Definitions for counter 0
 */

#define	USall_EVENTS_0(v)					\
	{v,		0x0,	"Cycle_cnt"},			\
	{v,		0x1,	"Instr_cnt"},			\
	{v,		0x2,	"Dispatch0_IC_miss"},		\
	{v,		0x8,	"IC_ref"},			\
	{v,		0x9,	"DC_rd"},			\
	{v,		0xa,	"DC_wr"},			\
	{v,		0xc,	"EC_ref"},			\
	{v,		0xe,	"EC_snoop_inv"}

static const struct nametable US12_names0[] = {
	USall_EVENTS_0(V_US12),
	{V_US12,	0x3,	"Dispatch0_storeBuf"},
	{V_US12,	0xb,	"Load_use"},
	{V_US12,	0xd,	"EC_write_hit_RDO"},
	{V_US12,	0xf,	"EC_rd_hit"},
	{V_END}
};

#define	US3all_EVENTS_0(v)					\
	{v,		0x3,	"Dispatch0_br_target"},		\
	{v,		0x4,	"Dispatch0_2nd_br"},		\
	{v,		0x5,	"Rstall_storeQ"},		\
	{v,		0x6,	"Rstall_IU_use"},		\
	{v,		0xd,	"EC_write_hit_RTO"},		\
	{v,		0xf,	"EC_rd_miss"},			\
	{v,		0x10,	"PC_port0_rd"},			\
	{v,		0x11,	"SI_snoop"},			\
	{v,		0x12,	"SI_ciq_flow"},			\
	{v,		0x13,	"SI_owned"},			\
	{v,		0x14,	"SW_count_0"},			\
	{v,		0x15,	"IU_Stat_Br_miss_taken"},	\
	{v,		0x16,	"IU_Stat_Br_count_taken"},	\
	{v,		0x17,	"Dispatch_rs_mispred"},		\
	{v,		0x18,	"FA_pipe_completion"}

#define	US3_MC_EVENTS_0(v)					\
	{v,		0x20,	"MC_reads_0"},			\
	{v,		0x21,	"MC_reads_1"},			\
	{v,		0x22,	"MC_reads_2"},			\
	{v,		0x23,	"MC_reads_3"},			\
	{v,		0x24,	"MC_stalls_0"},			\
	{v,		0x25,	"MC_stalls_2"}

#define	US3_I_MC_EVENTS_0(v)					\
	{v,		0x20,	"MC_read_dispatched"},		\
	{v,		0x21,	"MC_write_dispatched"},		\
	{v,		0x22,	"MC_read_returned_to_JBU"},	\
	{v,		0x23,	"MC_msl_busy_stall"},		\
	{v,		0x24,	"MC_mdb_overflow_stall"},	\
	{v,		0x25,	"MC_miu_spec_request"}

static const struct nametable US3_names0[] = {
	USall_EVENTS_0(V_US3),
	US3all_EVENTS_0(V_US3),
	US3_MC_EVENTS_0(V_US3),
	{V_END}
};

static const struct nametable US4_PLUS_names0[] = {
	{V_US4_PLUS,	0x0,   "Cycle_cnt"},
	{V_US4_PLUS,	0x1,   "Instr_cnt"},
	{V_US4_PLUS,	0x2,   "Dispatch0_IC_miss"},
	{V_US4_PLUS,	0x3,   "IU_stat_jmp_correct_pred"},
	{V_US4_PLUS,	0x4,   "Dispatch0_2nd_br"},
	{V_US4_PLUS,	0x5,   "Rstall_storeQ"},
	{V_US4_PLUS,	0x6,   "Rstall_IU_use"},
	{V_US4_PLUS,	0x7,   "IU_stat_ret_correct_pred"},
	{V_US4_PLUS,	0x8,   "IC_ref"},
	{V_US4_PLUS,	0x9,   "DC_rd"},
	{V_US4_PLUS,	0xa,   "Rstall_FP_use"},
	{V_US4_PLUS,	0xb,   "SW_pf_instr"},
	{V_US4_PLUS,	0xc,   "L2_ref"},
	{V_US4_PLUS,	0xd,   "L2_write_hit_RTO"},
	{V_US4_PLUS,	0xe,   "L2_snoop_inv_sh"},
	{V_US4_PLUS,	0xf,   "L2_rd_miss"},
	{V_US4_PLUS,	0x10,  "PC_rd"},
	{V_US4_PLUS,	0x11,  "SI_snoop_sh"},
	{V_US4_PLUS,	0x12,  "SI_ciq_flow_sh"},
	{V_US4_PLUS,	0x13,  "Re_DC_miss"},
	{V_US4_PLUS,	0x14,  "SW_count_NOP"},
	{V_US4_PLUS,	0x15,  "IU_stat_br_miss_taken"},
	{V_US4_PLUS,	0x16,  "IU_stat_br_count_untaken"},
	{V_US4_PLUS,	0x17,  "HW_pf_exec"},
	{V_US4_PLUS,	0x18,  "FA_pipe_completion"},
	{V_US4_PLUS,	0x19,  "SSM_L3_wb_remote"},
	{V_US4_PLUS,	0x1a,  "SSM_L3_miss_local"},
	{V_US4_PLUS,	0x1b,  "SSM_L3_miss_mtag_remote"},
	{V_US4_PLUS,	0x1c,  "SW_pf_str_trapped"},
	{V_US4_PLUS,	0x1d,  "SW_pf_PC_installed"},
	{V_US4_PLUS,	0x1e,  "IPB_to_IC_fill"},
	{V_US4_PLUS,	0x1f,  "L2_write_miss"},
	{V_US4_PLUS,	0x20,  "MC_reads_0_sh"},
	{V_US4_PLUS,	0x21,  "MC_reads_1_sh"},
	{V_US4_PLUS,	0x22,  "MC_reads_2_sh"},
	{V_US4_PLUS,	0x23,  "MC_reads_3_sh"},
	{V_US4_PLUS,	0x24,  "MC_stalls_0_sh"},
	{V_US4_PLUS,	0x25,  "MC_stalls_2_sh"},
	{V_US4_PLUS,	0x26,  "L2_hit_other_half"},
	{V_US4_PLUS,	0x28,  "L3_rd_miss"},
	{V_US4_PLUS,	0x29,  "Re_L2_miss"},
	{V_US4_PLUS,	0x2a,  "IC_miss_cancelled"},
	{V_US4_PLUS,	0x2b,  "DC_wr_miss"},
	{V_US4_PLUS,	0x2c,  "L3_hit_I_state_sh"},
	{V_US4_PLUS,	0x2d,  "SI_RTS_src_data"},
	{V_US4_PLUS,	0x2e,  "L2_IC_miss"},
	{V_US4_PLUS,	0x2f,  "SSM_new_transaction_sh"},
	{V_US4_PLUS,	0x30,  "L2_SW_pf_miss"},
	{V_US4_PLUS,	0x31,  "L2_wb"},
	{V_US4_PLUS,	0x32,  "L2_wb_sh"},
	{V_US4_PLUS,	0x33,  "L2_snoop_cb_sh"},
	{V_END}
};

static const struct nametable US3_PLUS_names0[] = {
	USall_EVENTS_0(V_US3_PLUS),
	US3all_EVENTS_0(V_US3_PLUS),
	US3_MC_EVENTS_0(V_US3_PLUS),
	{V_US3_PLUS,	0x19,	"EC_wb_remote"},
	{V_US3_PLUS,	0x1a,	"EC_miss_local"},
	{V_US3_PLUS,	0x1b,	"EC_miss_mtag_remote"},
	{V_END}
};

static const struct nametable US3_I_names0[] = {
	USall_EVENTS_0(V_US3_I),
	US3all_EVENTS_0(V_US3_I),
	US3_I_MC_EVENTS_0(V_US3_I),
	{V_US3_PLUS,	0x19,	"EC_wb_remote"},
	{V_US3_PLUS,	0x1a,	"EC_miss_local"},
	{V_US3_PLUS,	0x1b,	"EC_miss_mtag_remote"},
	{V_END}
};

#undef	USall_EVENTS_0
#undef	US3all_EVENTS_0

#define	USall_EVENTS_1(v)					\
	{v,		0x0,	"Cycle_cnt"},			\
	{v,		0x1,	"Instr_cnt"},			\
	{v,		0x2,	"Dispatch0_mispred"},		\
	{v,		0xd,	"EC_wb"},			\
	{v,		0xe,	"EC_snoop_cb"}

static const struct nametable US12_names1[] = {
	USall_EVENTS_1(V_US12),
	{V_US12,	0x3,	"Dispatch0_FP_use"},
	{V_US12,	0x8,	"IC_hit"},
	{V_US12,	0x9,	"DC_rd_hit"},
	{V_US12,	0xa,	"DC_wr_hit"},
	{V_US12,	0xb,	"Load_use_RAW"},
	{V_US12,	0xc,	"EC_hit"},
	{V_US12,	0xf,	"EC_ic_hit"},
	{V_END}
};

#define	US3all_EVENTS_1(v)					\
	{v,		0x3,	"IC_miss_cancelled"},		\
	{v,		0x5,	"Re_FPU_bypass"},		\
	{v,		0x6,	"Re_DC_miss"},			\
	{v,		0x7,	"Re_EC_miss"},			\
	{v,		0x8,	"IC_miss"},			\
	{v,		0x9,	"DC_rd_miss"},			\
	{v,		0xa,	"DC_wr_miss"},			\
	{v,		0xb,	"Rstall_FP_use"},		\
	{v,		0xc,	"EC_misses"},			\
	{v,		0xf,	"EC_ic_miss"},			\
	{v,		0x10,	"Re_PC_miss"},			\
	{v,		0x11,	"ITLB_miss"},			\
	{v,		0x12,	"DTLB_miss"},			\
	{v,		0x13,	"WC_miss"},			\
	{v,		0x14,	"WC_snoop_cb"},			\
	{v,		0x15,	"WC_scrubbed"},			\
	{v,		0x16,	"WC_wb_wo_read"},		\
	{v,		0x18,	"PC_soft_hit"},			\
	{v,		0x19,	"PC_snoop_inv"},		\
	{v,		0x1a,	"PC_hard_hit"},			\
	{v,		0x1b,	"PC_port1_rd"},			\
	{v,		0x1c,	"SW_count_1"},			\
	{v,		0x1d,	"IU_Stat_Br_miss_untaken"},	\
	{v,		0x1e,	"IU_Stat_Br_count_untaken"},	\
	{v,		0x1f,	"PC_MS_misses"},		\
	{v,		0x26,	"Re_RAW_miss"},			\
	{v,		0x27,	"FM_pipe_completion"}

#define	US3_MC_EVENTS_1(v)					\
	{v,		0x20,	"MC_writes_0"},			\
	{v,		0x21,	"MC_writes_1"},			\
	{v,		0x22,	"MC_writes_2"},			\
	{v,		0x23,	"MC_writes_3"},			\
	{v,		0x24,	"MC_stalls_1"},			\
	{v,		0x25,	"MC_stalls_3"}

#define	US3_I_MC_EVENTS_1(v)					\
	{v,		0x20,	"MC_open_bank_cmds"},		\
	{v,		0x21,	"MC_reads"},			\
	{v,		0x22,	"MC_writes"},			\
	{v,		0x23,	"MC_page_close_stall"}

static const struct nametable US3_names1[] = {
	USall_EVENTS_1(V_US3),
	US3all_EVENTS_1(V_US3),
	US3_MC_EVENTS_1(V_US3),
	{V_US3,		0x4,	"Re_endian_miss"},
	{V_END}
};

static const struct nametable US3_PLUS_names1[] = {
	USall_EVENTS_1(V_US3_PLUS),
	US3all_EVENTS_1(V_US3_PLUS),
	US3_MC_EVENTS_1(V_US3_PLUS),
	{V_US3_PLUS,	0x4,	"Re_DC_missovhd"},
	{V_US3_PLUS,	0x28,	"EC_miss_mtag_remote"},
	{V_US3_PLUS,	0x29,	"EC_miss_remote"},
	{V_END}
};

static const struct nametable US3_I_names1[] = {
	USall_EVENTS_1(V_US3_I),
	US3all_EVENTS_1(V_US3_I),
	US3_I_MC_EVENTS_1(V_US3_I),
	{V_US3_I,	0x4,	"Re_DC_missovhd"},
	{V_END}
};

static const struct nametable US4_PLUS_names1[] = {
	{V_US4_PLUS,	0x0,   "Cycle_cnt"},
	{V_US4_PLUS,	0x1,   "Instr_cnt"},
	{V_US4_PLUS,	0x2,   "Dispatch0_other"},
	{V_US4_PLUS,	0x3,   "DC_wr"},
	{V_US4_PLUS,	0x4,   "Re_DC_missovhd"},
	{V_US4_PLUS,	0x5,   "Re_FPU_bypass"},
	{V_US4_PLUS,	0x6,   "L3_write_hit_RTO"},
	{V_US4_PLUS,	0x7,   "L2L3_snoop_inv_sh"},
	{V_US4_PLUS,	0x8,   "IC_L2_req"},
	{V_US4_PLUS,	0x9,   "DC_rd_miss"},
	{V_US4_PLUS,	0xa,   "L2_hit_I_state_sh"},
	{V_US4_PLUS,	0xb,   "L3_write_miss_RTO"},
	{V_US4_PLUS,	0xc,   "L2_miss"},
	{V_US4_PLUS,	0xd,   "SI_owned_sh"},
	{V_US4_PLUS,	0xe,   "SI_RTO_src_data"},
	{V_US4_PLUS,	0xf,   "SW_pf_duplicate"},
	{V_US4_PLUS,	0x10,  "IU_stat_jmp_mispred"},
	{V_US4_PLUS,	0x11,  "ITLB_miss"},
	{V_US4_PLUS,	0x12,  "DTLB_miss"},
	{V_US4_PLUS,	0x13,  "WC_miss"},
	{V_US4_PLUS,	0x14,  "IC_fill"},
	{V_US4_PLUS,	0x15,  "IU_stat_ret_mispred"},
	{V_US4_PLUS,	0x16,  "Re_L3_miss"},
	{V_US4_PLUS,	0x17,  "Re_PFQ_full"},
	{V_US4_PLUS,	0x18,  "PC_soft_hit"},
	{V_US4_PLUS,	0x19,  "PC_inv"},
	{V_US4_PLUS,	0x1a,  "PC_hard_hit"},
	{V_US4_PLUS,	0x1b,  "IC_pf"},
	{V_US4_PLUS,	0x1c,  "SW_count_NOP"},
	{V_US4_PLUS,	0x1d,  "IU_stat_br_miss_untaken"},
	{V_US4_PLUS,	0x1e,  "IU_stat_br_count_taken"},
	{V_US4_PLUS,	0x1f,  "PC_miss"},
	{V_US4_PLUS,	0x20,  "MC_writes_0_sh"},
	{V_US4_PLUS,	0x21,  "MC_writes_1_sh"},
	{V_US4_PLUS,	0x22,  "MC_writes_2_sh"},
	{V_US4_PLUS,	0x23,  "MC_writes_3_sh"},
	{V_US4_PLUS,	0x24,  "MC_stalls_1_sh"},
	{V_US4_PLUS,	0x25,  "MC_stalls_3_sh"},
	{V_US4_PLUS,	0x26,  "Re_RAW_miss"},
	{V_US4_PLUS,	0x27,  "FM_pipe_completion"},
	{V_US4_PLUS,	0x28,  "SSM_L3_miss_mtag_remote"},
	{V_US4_PLUS,	0x29,  "SSM_L3_miss_remote"},
	{V_US4_PLUS,	0x2a,  "SW_pf_exec"},
	{V_US4_PLUS,	0x2b,  "SW_pf_str_exec"},
	{V_US4_PLUS,	0x2c,  "SW_pf_dropped"},
	{V_US4_PLUS,	0x2d,  "SW_pf_L2_installed"},
	{V_US4_PLUS,	0x2f,  "L2_HW_pf_miss"},
	{V_US4_PLUS,	0x31,  "L3_miss"},
	{V_US4_PLUS,	0x32,  "L3_IC_miss"},
	{V_US4_PLUS,	0x33,  "L3_SW_pf_miss"},
	{V_US4_PLUS,	0x34,  "L3_hit_other_half"},
	{V_US4_PLUS,	0x35,  "L3_wb"},
	{V_US4_PLUS,	0x36,  "L3_wb_sh"},
	{V_US4_PLUS,	0x37,  "L2L3_snoop_cb_sh"},
	{V_END}
};

#undef	USall_EVENTS_1
#undef	US3all_EVENTS_1

static const struct nametable *US12_names[2] = {
	US12_names0,
	US12_names1
};

static const struct nametable *US3_names[2] = {
	US3_names0,
	US3_names1
};

static const struct nametable *US3_PLUS_names[2] = {
	US3_PLUS_names0,
	US3_PLUS_names1
};

static const struct nametable *US3_I_names[2] = {
	US3_I_names0,
	US3_I_names1
};

static const struct nametable *US4_PLUS_names[2] = {
	US4_PLUS_names0,
	US4_PLUS_names1
};

#define	MAPCPUVER(cpuver)	(cpuvermap[(cpuver) - CPC_ULTRA1])

static int
validargs(int cpuver, int regno)
{
	if (regno < 0 || regno > 1)
		return (0);
	cpuver -= CPC_ULTRA1;
	if (cpuver < 0 ||
	    cpuver >= sizeof (cpuvermap) / sizeof (cpuvermap[0]))
		return (0);
	return (1);
}

/*ARGSUSED*/
static int
versionmatch(int cpuver, int regno, const struct nametable *n)
{
	if (!validargs(cpuver, regno) || n->ver != MAPCPUVER(cpuver))
		return (0);
	return (1);
}

static const struct nametable *
getnametable(int cpuver, int regno)
{
	const struct nametable *n;

	if (!validargs(cpuver, regno))
		return (NULL);

	switch (MAPCPUVER(cpuver)) {
	case V_US12:
		n = US12_names[regno];
		break;
	case V_US3:
		n = US3_names[regno];
		break;
	case V_US3_PLUS:
		n = US3_PLUS_names[regno];
		break;
	case V_US3_I:
		n = US3_I_names[regno];
		break;
	case V_US4_PLUS:
		n = US4_PLUS_names[regno];
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
		case V_US12:
			return ("UltraSPARC I&II");
		case V_US3:
			return ("UltraSPARC III");
		case V_US3_PLUS:
			return ("UltraSPARC III+ & IV");
		case V_US3_I:
			return ("UltraSPARC IIIi & IIIi+");
		case V_US4_PLUS:
			return ("UltraSPARC IV+");
		default:
			break;
		}
	return (NULL);
}

#define	CPU_REF_URL " Documentation for Sun processors can be found at: " \
			"http://www.sun.com/processors/manuals"

const char *
cpc_getcpuref(int cpuver)
{
	if (validargs(cpuver, 0))
		switch (MAPCPUVER(cpuver)) {
		case V_US12:
			return (gettext(
			    "See the \"UltraSPARC I/II User\'s Manual\" "
			    "(Part No. 802-7220-02) "
			    "for descriptions of these events." CPU_REF_URL));
		case V_US3:
		case V_US3_PLUS:
			return (gettext(
			    "See the \"UltraSPARC III Cu User's Manual\" "
			    "for descriptions of these events." CPU_REF_URL));
		case V_US3_I:
			return (gettext(
			    "See the \"UltraSPARC IIIi User's Manual\"  "
			    "for descriptions of these events." CPU_REF_URL));
		case V_US4_PLUS:
			return (gettext(
			    "See the \"UltraSPARC IV User's Manual"
			    "Supplement\"  "
			    "for descriptions of these events." CPU_REF_URL));
		default:
			break;
		}
	return (NULL);
}

/*
 * This is a functional interface to allow CPUs with fewer %pic registers
 * to share the same data structure as those with more %pic registers
 * within the same instruction family.
 */
uint_t
cpc_getnpic(int cpuver)
{
	/*LINTED*/
	cpc_event_t *event;

	switch (cpuver) {
	case CPC_ULTRA1:
	case CPC_ULTRA2:
	case CPC_ULTRA3:
	case CPC_ULTRA3_PLUS:
	case CPC_ULTRA3_I:
	case CPC_ULTRA4_PLUS:
		return (sizeof (event->ce_pic) / sizeof (event->ce_pic[0]));
	default:
		return (0);
	}
}

/*
 * Compares the given string against the list of all known CPU node names, and
 * returns the CPC CPU version code if there is a match. If there is no match,
 * returns -1.
 */
static int
node2ver(char *node)
{
	if (strcmp(node, "SUNW,UltraSPARC") == 0 ||
	    strcmp(node, "SUNW,UltraSPARC-II") == 0 ||
	    strcmp(node, "SUNW,UltraSPARC-IIi") == 0 ||
	    strcmp(node, "SUNW,UltraSPARC-IIe") == 0) {
		return (CPC_ULTRA1);
	} else if (strcmp(node, "SUNW,UltraSPARC-III") == 0)
		return (CPC_ULTRA3);
	else if (strcmp(node, "SUNW,UltraSPARC-III+") == 0 ||
	    strcmp(node, "SUNW,UltraSPARC-IV") == 0)
		return (CPC_ULTRA3_PLUS);
	else if (strcmp(node, "SUNW,UltraSPARC-IIIi") == 0 ||
	    strcmp(node, "SUNW,UltraSPARC-IIIi+") == 0)
		return (CPC_ULTRA3_I);
	else if (strcmp(node, "SUNW,UltraSPARC-IV+") == 0)
		return (CPC_ULTRA4_PLUS);

	return (-1);
}

static int
cpc_get_cpu_ver(di_node_t di_node, void *arg)
{
	char		*node_name, *compatible_array;
	int		n_names, i, found = 0;
	int		*ver = arg;

	node_name = di_node_name(di_node);
	if (node_name != NULL) {
		if ((*ver = node2ver(node_name)) != -1)
			found = 1;
		else if (strncmp(node_name, "cpu", 4) == 0) {
			/*
			 * CPU nodes associated with CMP use the generic name
			 * of "cpu".  We must look at the compatible property
			 * in order to find the implementation specific name.
			 */
			if ((n_names = di_compatible_names(di_node,
			    &compatible_array)) > 0) {
				for (i = 0; i < n_names; i++) {
					if ((*ver = node2ver(compatible_array))
					    != -1) {
						found = 1;
						break;
					}
					compatible_array +=
					    strlen(compatible_array) + 1;
				}
			}
		}
	}

	if (found == 0)
		return (DI_WALK_CONTINUE);

	return (DI_WALK_TERMINATE);
}

/*
 * Return the version of the current processor.
 *
 * Version -1 is defined as 'not performance counter capable'
 *
 * XXX  A better solution would be to use the di_prom_props for the cpu
 * devinfo nodes. That way we could look at the 'device-type', 'sparc-version'
 * and 'implementation#' properties in order to determine which version of
 * UltraSPARC we are running on.
 *
 * The problem with this is that di_prom_init() requires root access to
 * open /dev/openprom and cputrack is not a root-only application so
 * we have to settle for the di_props that we can see as non-root users.
 */
int
cpc_getcpuver(void)
{
	static int ver = -1;

	if (ver == -1) {
		di_node_t	di_root_node;

		if ((di_root_node = di_init("/", DINFOCPYALL)) == DI_NODE_NIL)
			return (-1);

		(void) di_walk_node(di_root_node, DI_WALK_CLDFIRST,
			(void *)&ver, cpc_get_cpu_ver);

		di_fini(di_root_node);
	}
	return (ver);
}
