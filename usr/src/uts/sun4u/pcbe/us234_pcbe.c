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
 * This file contains preset event names from the Performance Application
 * Programming Interface v3.5 which included the following notice:
 *
 *                             Copyright (c) 2005,6
 *                           Innovative Computing Labs
 *                         Computer Science Department,
 *                            University of Tennessee,
 *                                 Knoxville, TN.
 *                              All Rights Reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the University of Tennessee nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This open source software license conforms to the BSD License template.
 */

/*
 * UltraSPARC Performance Counter Backend
 */

#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/spitregs.h>
#include <sys/cheetahregs.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/modctl.h>
#include <sys/machsystm.h>
#include <sys/sdt.h>

static int us_pcbe_init(void);
static uint_t us_pcbe_ncounters(void);
static const char *us_pcbe_impl_name(void);
static const char *us_pcbe_cpuref(void);
static char *us_pcbe_list_events(uint_t picnum);
static char *us_pcbe_list_attrs(void);
static uint64_t us_pcbe_event_coverage(char *event);
static uint64_t us_pcbe_overflow_bitmap(void);
static int us_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void us_pcbe_program(void *token);
static void us_pcbe_allstop(void);
static void us_pcbe_sample(void *token);
static void us_pcbe_free(void *config);

extern void ultra_setpcr(uint64_t);
extern uint64_t ultra_getpcr(void);
extern void ultra_setpic(uint64_t);
extern uint64_t ultra_getpic(void);
extern uint64_t ultra_gettick(void);

pcbe_ops_t us_pcbe_ops = {
	PCBE_VER_1,
	CPC_CAP_OVERFLOW_INTERRUPT,
	us_pcbe_ncounters,
	us_pcbe_impl_name,
	us_pcbe_cpuref,
	us_pcbe_list_events,
	us_pcbe_list_attrs,
	us_pcbe_event_coverage,
	us_pcbe_overflow_bitmap,
	us_pcbe_configure,
	us_pcbe_program,
	us_pcbe_allstop,
	us_pcbe_sample,
	us_pcbe_free
};

typedef struct _us_pcbe_config {
	uint8_t		us_picno;	/* 0 for pic0 or 1 for pic1 */
	uint32_t	us_bits;	/* %pcr event code unshifted */
	uint32_t	us_flags;	/* user/system/priv */
	uint32_t	us_pic;		/* unshifted raw %pic value */
} us_pcbe_config_t;

struct nametable {
	const uint8_t	bits;
	const char	*name;
};

typedef struct _us_generic_event {
	char *name;
	char *event;
} us_generic_event_t;

#define	PIC0_MASK (((uint64_t)1 << 32) - 1)

#define	ULTRA_PCR_SYS		(UINT64_C(1) << CPC_ULTRA_PCR_SYS)
#define	ULTRA_PCR_PRIVPIC	(UINT64_C(1) << CPC_ULTRA_PCR_PRIVPIC)

#define	CPC_ULTRA_PCR_USR		2
#define	CPC_ULTRA_PCR_SYS		1
#define	CPC_ULTRA_PCR_PRIVPIC		0

#define	CPC_ULTRA_PCR_PIC0_SHIFT	4
#define	CPC_ULTRA2_PCR_PIC_MASK		UINT64_C(0xf)
#define	CPC_ULTRA3_PCR_PIC_MASK		UINT64_C(0x3f)
#define	CPC_ULTRA_PCR_PIC1_SHIFT	11

#define	NT_END 0xFF
#define	CPC_GEN_END { NULL, NULL }

static const uint64_t   allstopped = ULTRA_PCR_PRIVPIC;

#define	USall_EVENTS_0						\
	{0x0,	"Cycle_cnt"},					\
	{0x1,	"Instr_cnt"},					\
	{0x2,	"Dispatch0_IC_miss"},				\
	{0x8,	"IC_ref"},					\
	{0x9,	"DC_rd"},					\
	{0xa,	"DC_wr"},					\
	{0xc,	"EC_ref"},					\
	{0xe,	"EC_snoop_inv"}

static const struct nametable US12_names0[] = {
	USall_EVENTS_0,
	{0x3,	"Dispatch0_storeBuf"},
	{0xb,	"Load_use"},
	{0xd,	"EC_write_hit_RDO"},
	{0xf,	"EC_rd_hit"},
	{NT_END, ""}
};

#define	US3all_EVENTS_0						\
	{0x3,	"Dispatch0_br_target"},				\
	{0x4,	"Dispatch0_2nd_br"},				\
	{0x5,	"Rstall_storeQ"},				\
	{0x6,	"Rstall_IU_use"},				\
	{0xd,	"EC_write_hit_RTO"},				\
	{0xf,	"EC_rd_miss"},					\
	{0x10,	"PC_port0_rd"},					\
	{0x11,	"SI_snoop"},					\
	{0x12,	"SI_ciq_flow"},					\
	{0x13,	"SI_owned"},					\
	{0x14,	"SW_count_0"},					\
	{0x15,	"IU_Stat_Br_miss_taken"},			\
	{0x16,	"IU_Stat_Br_count_taken"},			\
	{0x17,	"Dispatch_rs_mispred"},				\
	{0x18,	"FA_pipe_completion"}

#define	US3_MC_EVENTS_0						\
	{0x20,	"MC_reads_0"},					\
	{0x21,	"MC_reads_1"},					\
	{0x22,	"MC_reads_2"},					\
	{0x23,	"MC_reads_3"},					\
	{0x24,	"MC_stalls_0"},					\
	{0x25,	"MC_stalls_2"}

#define	US3_I_MC_EVENTS_0					\
	{0x20,	"MC_read_dispatched"},				\
	{0x21,	"MC_write_dispatched"},				\
	{0x22,	"MC_read_returned_to_JBU"},			\
	{0x23,	"MC_msl_busy_stall"},				\
	{0x24,	"MC_mdb_overflow_stall"},			\
	{0x25,	"MC_miu_spec_request"}

#define	USall_EVENTS_1						\
	{0x0,	"Cycle_cnt"},					\
	{0x1,	"Instr_cnt"},					\
	{0x2,	"Dispatch0_mispred"},				\
	{0xd,	"EC_wb"},					\
	{0xe,	"EC_snoop_cb"}

static const struct nametable US3_names0[] = {
	USall_EVENTS_0,
	US3all_EVENTS_0,
	US3_MC_EVENTS_0,
	{NT_END, ""}
};

static const struct nametable US3_PLUS_names0[] = {
	USall_EVENTS_0,
	US3all_EVENTS_0,
	US3_MC_EVENTS_0,
	{0x19,	"EC_wb_remote"},
	{0x1a,	"EC_miss_local"},
	{0x1b,	"EC_miss_mtag_remote"},
	{NT_END, ""}
};

static const struct nametable US3_I_names0[] = {
	USall_EVENTS_0,
	US3all_EVENTS_0,
	US3_I_MC_EVENTS_0,
	{NT_END, ""}
};

static const struct nametable US4_PLUS_names0[] = {
	{0x0,   "Cycle_cnt"},
	{0x1,   "Instr_cnt"},
	{0x2,   "Dispatch0_IC_miss"},
	{0x3,   "IU_stat_jmp_correct_pred"},
	{0x4,   "Dispatch0_2nd_br"},
	{0x5,   "Rstall_storeQ"},
	{0x6,   "Rstall_IU_use"},
	{0x7,   "IU_stat_ret_correct_pred"},
	{0x8,   "IC_ref"},
	{0x9,   "DC_rd"},
	{0xa,   "Rstall_FP_use"},
	{0xb,   "SW_pf_instr"},
	{0xc,   "L2_ref"},
	{0xd,   "L2_write_hit_RTO"},
	{0xe,   "L2_snoop_inv_sh"},
	{0xf,   "L2_rd_miss"},
	{0x10,  "PC_rd"},
	{0x11,  "SI_snoop_sh"},
	{0x12,  "SI_ciq_flow_sh"},
	{0x13,  "Re_DC_miss"},
	{0x14,  "SW_count_NOP"},
	{0x15,  "IU_stat_br_miss_taken"},
	{0x16,  "IU_stat_br_count_untaken"},
	{0x17,  "HW_pf_exec"},
	{0x18,  "FA_pipe_completion"},
	{0x19,  "SSM_L3_wb_remote"},
	{0x1a,  "SSM_L3_miss_local"},
	{0x1b,  "SSM_L3_miss_mtag_remote"},
	{0x1c,  "SW_pf_str_trapped"},
	{0x1d,  "SW_pf_PC_installed"},
	{0x1e,  "IPB_to_IC_fill"},
	{0x1f,  "L2_write_miss"},
	{0x20,  "MC_reads_0_sh"},
	{0x21,  "MC_reads_1_sh"},
	{0x22,  "MC_reads_2_sh"},
	{0x23,  "MC_reads_3_sh"},
	{0x24,  "MC_stalls_0_sh"},
	{0x25,  "MC_stalls_2_sh"},
	{0x26,  "L2_hit_other_half"},
	{0x28,  "L3_rd_miss"},
	{0x29,  "Re_L2_miss"},
	{0x2a,  "IC_miss_cancelled"},
	{0x2b,  "DC_wr_miss"},
	{0x2c,  "L3_hit_I_state_sh"},
	{0x2d,  "SI_RTS_src_data"},
	{0x2e,  "L2_IC_miss"},
	{0x2f,  "SSM_new_transaction_sh"},
	{0x30,  "L2_SW_pf_miss"},
	{0x31,  "L2_wb"},
	{0x32,  "L2_wb_sh"},
	{0x33,  "L2_snoop_cb_sh"},
	{NT_END, ""}
};


#define	US3all_EVENTS_1				\
	{0x3,	"IC_miss_cancelled"},		\
	{0x5,	"Re_FPU_bypass"},		\
	{0x6,	"Re_DC_miss"},			\
	{0x7,	"Re_EC_miss"},			\
	{0x8,	"IC_miss"},			\
	{0x9,	"DC_rd_miss"},			\
	{0xa,	"DC_wr_miss"},			\
	{0xb,	"Rstall_FP_use"},		\
	{0xc,	"EC_misses"},			\
	{0xf,	"EC_ic_miss"},			\
	{0x10,	"Re_PC_miss"},			\
	{0x11,	"ITLB_miss"},			\
	{0x12,	"DTLB_miss"},			\
	{0x13,	"WC_miss"},			\
	{0x14,	"WC_snoop_cb"},			\
	{0x15,	"WC_scrubbed"},			\
	{0x16,	"WC_wb_wo_read"},		\
	{0x18,	"PC_soft_hit"},			\
	{0x19,	"PC_snoop_inv"},		\
	{0x1a,	"PC_hard_hit"},			\
	{0x1b,	"PC_port1_rd"},			\
	{0x1c,	"SW_count_1"},			\
	{0x1d,	"IU_Stat_Br_miss_untaken"},	\
	{0x1e,	"IU_Stat_Br_count_untaken"},	\
	{0x1f,	"PC_MS_misses"},		\
	{0x26,	"Re_RAW_miss"},			\
	{0x27,	"FM_pipe_completion"}

#define	US3_MC_EVENTS_1				\
	{0x20,	"MC_writes_0"},			\
	{0x21,	"MC_writes_1"},			\
	{0x22,	"MC_writes_2"},			\
	{0x23,	"MC_writes_3"},			\
	{0x24,	"MC_stalls_1"},			\
	{0x25,	"MC_stalls_3"}

#define	US3_I_MC_EVENTS_1			\
	{0x20,	"MC_open_bank_cmds"},		\
	{0x21,	"MC_reads"},			\
	{0x22,	"MC_writes"},			\
	{0x23,	"MC_page_close_stall"}

static const struct nametable US3_names1[] = {
	USall_EVENTS_1,
	US3all_EVENTS_1,
	US3_MC_EVENTS_1,
	{0x4,	"Re_endian_miss"},
	{NT_END, ""}
};

static const struct nametable US3_PLUS_names1[] = {
	USall_EVENTS_1,
	US3all_EVENTS_1,
	US3_MC_EVENTS_1,
	{0x4,	"Re_DC_missovhd"},
	{0x28,	"EC_miss_mtag_remote"},
	{0x29,	"EC_miss_remote"},
	{NT_END, ""}
};

static const struct nametable US3_I_names1[] = {
	USall_EVENTS_1,
	US3all_EVENTS_1,
	US3_I_MC_EVENTS_1,
	{0x4,	"Re_DC_missovhd"},
	{NT_END, ""}
};

static const struct nametable US4_PLUS_names1[] = {
	{0x0,   "Cycle_cnt"},
	{0x1,   "Instr_cnt"},
	{0x2,   "Dispatch0_other"},
	{0x3,   "DC_wr"},
	{0x4,   "Re_DC_missovhd"},
	{0x5,   "Re_FPU_bypass"},
	{0x6,   "L3_write_hit_RTO"},
	{0x7,   "L2L3_snoop_inv_sh"},
	{0x8,   "IC_L2_req"},
	{0x9,   "DC_rd_miss"},
	{0xa,   "L2_hit_I_state_sh"},
	{0xb,   "L3_write_miss_RTO"},
	{0xc,   "L2_miss"},
	{0xd,   "SI_owned_sh"},
	{0xe,   "SI_RTO_src_data"},
	{0xf,   "SW_pf_duplicate"},
	{0x10,  "IU_stat_jmp_mispred"},
	{0x11,  "ITLB_miss"},
	{0x12,  "DTLB_miss"},
	{0x13,  "WC_miss"},
	{0x14,  "IC_fill"},
	{0x15,  "IU_stat_ret_mispred"},
	{0x16,  "Re_L3_miss"},
	{0x17,  "Re_PFQ_full"},
	{0x18,  "PC_soft_hit"},
	{0x19,  "PC_inv"},
	{0x1a,  "PC_hard_hit"},
	{0x1b,  "IC_pf"},
	{0x1c,  "SW_count_NOP"},
	{0x1d,  "IU_stat_br_miss_untaken"},
	{0x1e,  "IU_stat_br_count_taken"},
	{0x1f,  "PC_miss"},
	{0x20,  "MC_writes_0_sh"},
	{0x21,  "MC_writes_1_sh"},
	{0x22,  "MC_writes_2_sh"},
	{0x23,  "MC_writes_3_sh"},
	{0x24,  "MC_stalls_1_sh"},
	{0x25,  "MC_stalls_3_sh"},
	{0x26,  "Re_RAW_miss"},
	{0x27,  "FM_pipe_completion"},
	{0x28,  "SSM_L3_miss_mtag_remote"},
	{0x29,  "SSM_L3_miss_remote"},
	{0x2a,  "SW_pf_exec"},
	{0x2b,  "SW_pf_str_exec"},
	{0x2c,  "SW_pf_dropped"},
	{0x2d,  "SW_pf_L2_installed"},
	{0x2f,  "L2_HW_pf_miss"},
	{0x31,  "L3_miss"},
	{0x32,  "L3_IC_miss"},
	{0x33,  "L3_SW_pf_miss"},
	{0x34,  "L3_hit_other_half"},
	{0x35,  "L3_wb"},
	{0x36,  "L3_wb_sh"},
	{0x37,  "L2L3_snoop_cb_sh"},
	{NT_END, ""}
};

static const struct nametable US12_names1[] = {
	USall_EVENTS_1,
	{0x3,	"Dispatch0_FP_use"},
	{0x8,	"IC_hit"},
	{0x9,	"DC_rd_hit"},
	{0xa,	"DC_wr_hit"},
	{0xb,	"Load_use_RAW"},
	{0xc,	"EC_hit"},
	{0xf,	"EC_ic_hit"},
	{NT_END, ""}
};

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

static const struct nametable *US4_PLUS_names[2] = {
	US4_PLUS_names0,
	US4_PLUS_names1
};

static const struct nametable *US3_I_names[2] = {
	US3_I_names0,
	US3_I_names1
};

static const us_generic_event_t US12_generic_names0[] = {
	{ "PAPI_tot_cyc",  "Cycle_cnt" },
	{ "PAPI_tot_ins",  "Instr_cnt" },
	{ "PAPI_tot_iis",  "Instr_cnt" },
	{ "PAPI_l1_dcr",   "DC_rd" },
	{ "PAPI_l1_dcw",   "DC_wr" },
	{ "PAPI_l1_ica",   "IC_ref" },
	{ "PAPI_l2_tca",   "EC_ref" },
	{ "PAPI_l2_dch",   "EC_rd_hit" },
	{ "PAPI_ca_inv",   "EC_snoop_inv" },
	CPC_GEN_END
};

static const us_generic_event_t US12_generic_names1[] = {
	{ "PAPI_tot_cyc",  "Cycle_cnt" },
	{ "PAPI_tot_ins",  "Instr_cnt" },
	{ "PAPI_tot_iis",  "Instr_cnt" },
	{ "PAPI_br_msp",   "Dispatch0_mispred" },
	{ "PAPI_ca_snp",   "EC_snoop_cb" },
	{ "PAPI_l1_ich",   "IC_hit" },
	{ "PAPI_l2_tch",   "EC_hit" },
	{ "PAPI_l2_ich",   "EC_ic_hit" },
	CPC_GEN_END
};

static const us_generic_event_t US3_generic_names0[] = {
	{ "PAPI_tot_cyc",  "Cycle_cnt" },
	{ "PAPI_tot_ins",  "Instr_cnt" },
	{ "PAPI_tot_iis",  "Instr_cnt" },
	{ "PAPI_fad_ins",  "FA_pipe_completion" },
	{ "PAPI_l1_dcr",   "DC_rd" },
	{ "PAPI_l1_dcw",   "DC_wr" },
	{ "PAPI_l1_ica",   "IC_ref" },
	{ "PAPI_l2_tca",   "EC_ref" },
	{ "PAPI_l2_ldm",   "EC_rd_miss" },
	{ "PAPI_ca_inv",   "EC_snoop_inv" },
	{ "PAPI_br_tkn",   "IU_Stat_Br_count_taken" },
	CPC_GEN_END
};

static const us_generic_event_t US3_generic_names1[] = {
	{ "PAPI_tot_cyc",  "Cycle_cnt" },
	{ "PAPI_tot_ins",  "Instr_cnt" },
	{ "PAPI_tot_iis",  "Instr_cnt" },
	{ "PAPI_fml_ins",  "FM_pipe_completion" },
	{ "PAPI_l1_icm",   "IC_miss" },
	{ "PAPI_l1_ldm",   "DC_rd_miss" },
	{ "PAPI_l1_stm",   "DC_wr_miss" },
	{ "PAPI_l2_tcm",   "EC_misses" },
	{ "PAPI_l2_icm",   "EC_ic_miss" },
	{ "PAPI_tlb_dm",   "DTLB_miss" },
	{ "PAPI_tlb_im",   "ITLB_miss" },
	{ "PAPI_br_ntk",   "IU_Stat_Br_count_untaken" },
	{ "PAPI_br_msp",   "Dispatch0_mispred" },
	{ "PAPI_ca_snp",   "EC_snoop_cb" },
	CPC_GEN_END
};

static const us_generic_event_t US4_PLUS_generic_names0[] = {
	{ "PAPI_tot_cyc",  "Cycle_cnt" },
	{ "PAPI_tot_ins",  "Instr_cnt" },
	{ "PAPI_tot_iis",  "Instr_cnt" },
	{ "PAPI_fma_ins",  "FA_pipe_completion" },
	{ "PAPI_l1_dcr",   "DC_rd" },
	{ "PAPI_l1_stm",   "DC_wr_miss" },
	{ "PAPI_l1_ica",   "IC_ref" },
	{ "PAPI_l2_tca",   "L2_ref" },
	{ "PAPI_l2_ldm",   "L2_rd_miss" },
	{ "PAPI_l2_icm",   "L2_IC_miss" },
	{ "PAPI_l2_stm",   "L2_write_miss" },
	{ "PAPI_l3_ldm",   "L3_rd_miss" },
	{ "PAPI_br_ntk",   "IU_stat_br_count_untaken" },
	CPC_GEN_END
};

static const us_generic_event_t US4_PLUS_generic_names1[] = {
	{ "PAPI_tot_cyc", "Cycle_cnt" },
	{ "PAPI_tot_ins", "Instr_cnt" },
	{ "PAPI_tot_iis",  "Instr_cnt" },
	{ "PAPI_fml_ins",  "FM_pipe_completion" },
	{ "PAPI_l1_icm",   "IC_L2_req" },
	{ "PAPI_l1_ldm",   "DC_rd_miss" },
	{ "PAPI_l1_dcw",   "DC_wr" },
	{ "PAPI_l2_tcm",   "L2_miss" },
	{ "PAPI_l3_tcm",   "L3_miss" },
	{ "PAPI_l3_icm",   "L3_IC_miss" },
	{ "PAPI_tlb_im",   "ITLB_miss" },
	{ "PAPI_tlb_dm",   "DTLB_miss" },
	{ "PAPI_br_tkn",   "IU_stat_br_count_taken" },
	CPC_GEN_END
};

static const us_generic_event_t *US12_generic_names[2] = {
	US12_generic_names0,
	US12_generic_names1
};

static const us_generic_event_t *US3_generic_names[2] = {
	US3_generic_names0,
	US3_generic_names1
};

static const us_generic_event_t *US4_PLUS_generic_names[2] = {
	US4_PLUS_generic_names0,
	US4_PLUS_generic_names1
};

static const struct nametable **events;
static const us_generic_event_t **generic_events;
static const char *us_impl_name;
static const char *us_cpuref;
static char *pic_events[2];
static uint16_t pcr_pic_mask;

#define	CPU_REF_URL " Documentation for Sun processors can be found at: " \
			"http://www.sun.com/processors/manuals"

static const char *us_2_ref = "See the \"UltraSPARC I/II User\'s Manual\" "
			"(Part No. 802-7220-02) "
			"for descriptions of these events." CPU_REF_URL;

static const char *us_3cu_ref = "See the \"UltraSPARC III Cu User's Manual\" "
			"for descriptions of these events." CPU_REF_URL;

static const char *us4_plus_ref = "See the \"UltraSPARC IV+ User's Manual\" "
			"for descriptions of these events." CPU_REF_URL;

static const char *us_3i_ref = "See the \"UltraSPARC IIIi User's Manual\"  "
			"for descriptions of these events." CPU_REF_URL;

static int
us_pcbe_init(void)
{
	const struct nametable		*n;
	const us_generic_event_t	*gevp;
	int				i;
	size_t				size;

	/*
	 * Discover type of CPU
	 *
	 * Point nametable to that CPU's table
	 */
	switch (ULTRA_VER_IMPL(ultra_getver())) {
	case SPITFIRE_IMPL:
	case BLACKBIRD_IMPL:
	case SABRE_IMPL:
	case HUMMBRD_IMPL:
		events = US12_names;
		generic_events = US12_generic_names;
		us_impl_name = "UltraSPARC I&II";
		us_cpuref = us_2_ref;
		pcr_pic_mask = CPC_ULTRA2_PCR_PIC_MASK;
		us_pcbe_ops.pcbe_caps &= ~CPC_CAP_OVERFLOW_INTERRUPT;
		break;
	case CHEETAH_IMPL:
		events = US3_names;
		generic_events = US3_generic_names;
		us_impl_name = "UltraSPARC III";
		us_cpuref = us_3cu_ref;
		pcr_pic_mask = CPC_ULTRA3_PCR_PIC_MASK;
		break;
	case CHEETAH_PLUS_IMPL:
	case JAGUAR_IMPL:
		events = US3_PLUS_names;
		generic_events = US3_generic_names;
		us_impl_name = "UltraSPARC III+ & IV";
		us_cpuref = us_3cu_ref;
		pcr_pic_mask = CPC_ULTRA3_PCR_PIC_MASK;
		break;
	case PANTHER_IMPL:
		events = US4_PLUS_names;
		generic_events = US4_PLUS_generic_names;
		us_impl_name = "UltraSPARC IV+";
		us_cpuref = us4_plus_ref;
		pcr_pic_mask = CPC_ULTRA3_PCR_PIC_MASK;
		break;
	case JALAPENO_IMPL:
	case SERRANO_IMPL:
		events = US3_I_names;
		generic_events = US3_generic_names;
		us_impl_name = "UltraSPARC IIIi & IIIi+";
		us_cpuref = us_3i_ref;
		pcr_pic_mask = CPC_ULTRA3_PCR_PIC_MASK;
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
		for (gevp = generic_events[i]; gevp->name != NULL; gevp++)
			size += strlen(gevp->name) + 1;
		pic_events[i] = kmem_alloc(size + 1, KM_SLEEP);
		*pic_events[i] = '\0';
		for (n = events[i]; n->bits != NT_END; n++) {
			(void) strcat(pic_events[i], n->name);
			(void) strcat(pic_events[i], ",");
		}
		for (gevp = generic_events[i]; gevp->name != NULL; gevp++) {
			(void) strcat(pic_events[i], gevp->name);
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
us_pcbe_ncounters(void)
{
	return (2);
}

static const char *
us_pcbe_impl_name(void)
{
	return (us_impl_name);
}

static const char *
us_pcbe_cpuref(void)
{
	return (us_cpuref);
}

static char *
us_pcbe_list_events(uint_t picnum)
{
	ASSERT(picnum >= 0 && picnum < cpc_ncounters);

	return (pic_events[picnum]);
}

static char *
us_pcbe_list_attrs(void)
{
	return ("");
}

static const us_generic_event_t *
find_generic_event(int regno, char *name)
{
	const us_generic_event_t *gevp;

	for (gevp = generic_events[regno]; gevp->name != NULL; gevp++)
		if (strcmp(name, gevp->name) == 0)
			return (gevp);

	return (NULL);
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
us_pcbe_event_coverage(char *event)
{
	uint64_t bitmap = 0;

	if ((find_event(0, event) != NULL) ||
	    (find_generic_event(0, event) != NULL))
		bitmap = 0x1;
	if ((find_event(1, event) != NULL) ||
	    (find_generic_event(1, event) != NULL))
		bitmap |= 0x2;

	return (bitmap);
}

/*
 * These processors cannot tell which counter overflowed. The PCBE interface
 * requires such processors to act as if _all_ counters had overflowed.
 */
static uint64_t
us_pcbe_overflow_bitmap(void)
{
	return (0x3);
}

/*ARGSUSED*/
static int
us_pcbe_configure(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
    uint_t nattrs, kcpc_attr_t *attrs, void **data, void *token)
{
	us_pcbe_config_t		*conf;
	const struct nametable		*n;
	const us_generic_event_t	*gevp;
	us_pcbe_config_t		*other_config;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		conf = *data;
		conf->us_pic = (uint32_t)preset;
		return (0);
	}

	if (picnum < 0 || picnum > 1)
		return (CPC_INVALID_PICNUM);

	if (nattrs != 0)
		return (CPC_INVALID_ATTRIBUTE);

	/*
	 * Find other requests that will be programmed with this one, and ensure
	 * the flags don't conflict.
	 */
	if (((other_config = kcpc_next_config(token, NULL, NULL)) != NULL) &&
	    (other_config->us_flags != flags))
		return (CPC_CONFLICTING_REQS);

	if ((n = find_event(picnum, event)) == NULL) {
		if ((gevp = find_generic_event(picnum, event)) != NULL) {
			n = find_event(picnum, gevp->event);
			ASSERT(n != NULL);
		} else {
			return (CPC_INVALID_EVENT);
		}
	}

	conf = kmem_alloc(sizeof (us_pcbe_config_t), KM_SLEEP);

	conf->us_picno = picnum;
	conf->us_bits = (uint32_t)n->bits;
	conf->us_flags = flags;
	conf->us_pic = (uint32_t)preset;

	*data = conf;
	return (0);
}

static void
us_pcbe_program(void *token)
{
	us_pcbe_config_t	*pic0;
	us_pcbe_config_t	*pic1;
	us_pcbe_config_t	*tmp;
	us_pcbe_config_t	empty = { 1, 0x1c, 0, 0 }; /* SW_count_1 */
	uint64_t		pcr;
	uint64_t		curpic;

	if ((pic0 = (us_pcbe_config_t *)kcpc_next_config(token, NULL, NULL)) ==
	    NULL)
		panic("us_pcbe: token %p has no configs", token);

	if ((pic1 = kcpc_next_config(token, pic0, NULL)) == NULL) {
		pic1 = &empty;
		empty.us_flags = pic0->us_flags;
	}

	if (pic0->us_picno != 0) {
		/*
		 * pic0 is counter 1, so if we need the empty config it should
		 * be counter 0.
		 */
		empty.us_picno = 0;
		empty.us_bits = 0x14; /* SW_count_0 - won't overflow */
		tmp = pic0;
		pic0 = pic1;
		pic1 = tmp;
	}

	if (pic0->us_picno != 0 || pic1->us_picno != 1)
		panic("us_pcbe: bad config on token %p\n", token);

	/*
	 * UltraSPARC does not allow pic0 to be configured differently
	 * from pic1. If the flags on these two configurations are
	 * different, they are incompatible. This condition should be
	 * caught at configure time.
	 */
	ASSERT(pic0->us_flags == pic1->us_flags);

	ultra_setpcr(allstopped);
	ultra_setpic(((uint64_t)pic1->us_pic << 32) | (uint64_t)pic0->us_pic);

	pcr = (pic0->us_bits & pcr_pic_mask) <<
	    CPC_ULTRA_PCR_PIC0_SHIFT;
	pcr |= (pic1->us_bits & pcr_pic_mask) <<
	    CPC_ULTRA_PCR_PIC1_SHIFT;

	if (pic0->us_flags & CPC_COUNT_USER)
		pcr |= (1ull << CPC_ULTRA_PCR_USR);
	if (pic0->us_flags & CPC_COUNT_SYSTEM)
		pcr |= (1ull << CPC_ULTRA_PCR_SYS);

	DTRACE_PROBE1(ultra__pcr, uint64_t, pcr);

	ultra_setpcr(pcr);

	/*
	 * On UltraSPARC, only read-to-read counts are accurate. We cannot
	 * expect the value we wrote into the PIC, above, to be there after
	 * starting the counter. We must sample the counter value now and use
	 * that as the baseline for future samples.
	 */
	curpic = ultra_getpic();
	pic0->us_pic = (uint32_t)(curpic & PIC0_MASK);
	pic1->us_pic = (uint32_t)(curpic >> 32);
}

static void
us_pcbe_allstop(void)
{
	ultra_setpcr(allstopped);
}


static void
us_pcbe_sample(void *token)
{
	uint64_t		curpic;
	int64_t			diff;
	uint64_t		*pic0_data;
	uint64_t		*pic1_data;
	uint64_t		*dtmp;
	uint64_t		tmp;
	us_pcbe_config_t	*pic0;
	us_pcbe_config_t	*pic1;
	us_pcbe_config_t	empty = { 1, 0, 0, 0 };
	us_pcbe_config_t	*ctmp;

	curpic = ultra_getpic();

	if ((pic0 = kcpc_next_config(token, NULL, &pic0_data)) == NULL)
		panic("us_pcbe: token %p has no configs", token);

	if ((pic1 = kcpc_next_config(token, pic0, &pic1_data)) == NULL) {
		pic1 = &empty;
		pic1_data = &tmp;
	}

	if (pic0->us_picno != 0) {
		empty.us_picno = 0;
		ctmp = pic0;
		pic0 = pic1;
		pic1 = ctmp;
		dtmp = pic0_data;
		pic0_data = pic1_data;
		pic1_data = dtmp;
	}

	if (pic0->us_picno != 0 || pic1->us_picno != 1)
		panic("us_pcbe: bad config on token %p\n", token);

	diff = (curpic & PIC0_MASK) - (uint64_t)pic0->us_pic;
	if (diff < 0)
		diff += (1ll << 32);
	*pic0_data += diff;

	diff = (curpic >> 32) - (uint64_t)pic1->us_pic;
	if (diff < 0)
		diff += (1ll << 32);
	*pic1_data += diff;

	pic0->us_pic = (uint32_t)(curpic & PIC0_MASK);
	pic1->us_pic = (uint32_t)(curpic >> 32);
}

static void
us_pcbe_free(void *config)
{
	kmem_free(config, sizeof (us_pcbe_config_t));
}


static struct modlpcbe modlpcbe = {
	&mod_pcbeops,
	"UltraSPARC Performance Counters",
	&us_pcbe_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modlpcbe,
};

int
_init(void)
{
	if (us_pcbe_init() != 0)
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
