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
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *    * Neither the name of the University of Tennessee nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *	this software without specific prior written permission.
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
 * Portions Copyright 2009 Advanced Micro Devices, Inc.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Performance Counter Back-End for AMD Opteron, AMD Athlon 64, and Zen
 * era processors.
 */

#include <sys/cpuvar.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpc_pcbe.h>
#include <sys/kmem.h>
#include <sys/sdt.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/archsystm.h>
#include <sys/x86_archext.h>
#include <sys/privregs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "opteron_pcbe_table.h"
#include <opteron_pcbe_cpcgen.h>

static int opt_pcbe_init(void);
static uint_t opt_pcbe_ncounters(void);
static const char *opt_pcbe_impl_name(void);
static const char *opt_pcbe_cpuref(void);
static char *opt_pcbe_list_events(uint_t picnum);
static char *opt_pcbe_list_attrs(void);
static uint64_t opt_pcbe_event_coverage(char *event);
static uint64_t opt_pcbe_overflow_bitmap(void);
static int opt_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void opt_pcbe_program(void *token);
static void opt_pcbe_allstop(void);
static void opt_pcbe_sample(void *token);
static void opt_pcbe_free(void *config);

static pcbe_ops_t opt_pcbe_ops = {
	PCBE_VER_1,
	CPC_CAP_OVERFLOW_INTERRUPT,
	opt_pcbe_ncounters,
	opt_pcbe_impl_name,
	opt_pcbe_cpuref,
	opt_pcbe_list_events,
	opt_pcbe_list_attrs,
	opt_pcbe_event_coverage,
	opt_pcbe_overflow_bitmap,
	opt_pcbe_configure,
	opt_pcbe_program,
	opt_pcbe_allstop,
	opt_pcbe_sample,
	opt_pcbe_free
};

/*
 * Base MSR addresses for the PerfEvtSel registers and the counters themselves.
 * Add counter number to base address to get corresponding MSR address.
 */
#define	PES_BASE_ADDR	0xC0010000
#define	PIC_BASE_ADDR	0xC0010004

/*
 * Base MSR addresses for the PerfEvtSel registers and counters. The counter and
 * event select registers are interleaved, so one needs to multiply the counter
 * number by two to determine what they should be set to.
 */
#define	PES_EXT_BASE_ADDR	0xC0010200
#define	PIC_EXT_BASE_ADDR	0xC0010201

/*
 * The number of counters present depends on which CPU features are present.
 */
#define	OPT_PCBE_DEF_NCOUNTERS	4
#define	OPT_PCBE_EXT_NCOUNTERS	6

/*
 * Define offsets and masks for the fields in the Performance
 * Event-Select (PES) registers.
 */
#define	OPT_PES_HOST_SHIFT	41
#define	OPT_PES_GUEST_SHIFT	40
#define	OPT_PES_EVSELHI_SHIFT	32
#define	OPT_PES_CMASK_SHIFT	24
#define	OPT_PES_CMASK_MASK	0xFF
#define	OPT_PES_INV_SHIFT	23
#define	OPT_PES_ENABLE_SHIFT	22
#define	OPT_PES_INT_SHIFT	20
#define	OPT_PES_PC_SHIFT	19
#define	OPT_PES_EDGE_SHIFT	18
#define	OPT_PES_OS_SHIFT	17
#define	OPT_PES_USR_SHIFT	16
#define	OPT_PES_UMASK_SHIFT	8
#define	OPT_PES_UMASK_MASK	0xFF

#define	OPT_PES_INV		(1ULL << OPT_PES_INV_SHIFT)
#define	OPT_PES_ENABLE		(1ULL << OPT_PES_ENABLE_SHIFT)
#define	OPT_PES_INT		(1ULL << OPT_PES_INT_SHIFT)
#define	OPT_PES_PC		(1ULL << OPT_PES_PC_SHIFT)
#define	OPT_PES_EDGE		(1ULL << OPT_PES_EDGE_SHIFT)
#define	OPT_PES_OS		(1ULL << OPT_PES_OS_SHIFT)
#define	OPT_PES_USR		(1ULL << OPT_PES_USR_SHIFT)
#define	OPT_PES_HOST		(1ULL << OPT_PES_HOST_SHIFT)
#define	OPT_PES_GUEST		(1ULL << OPT_PES_GUEST_SHIFT)

typedef struct _opt_pcbe_config {
	uint8_t		opt_picno;	/* Counter number: 0, 1, 2, or 3 */
	uint64_t	opt_evsel;	/* Event Selection register */
	uint64_t	opt_rawpic;	/* Raw counter value */
} opt_pcbe_config_t;

opt_pcbe_config_t nullcfgs[OPT_PCBE_EXT_NCOUNTERS] = {
	{ 0, 0, 0 },
	{ 1, 0, 0 },
	{ 2, 0, 0 },
	{ 3, 0, 0 },
	{ 4, 0, 0 },
	{ 5, 0, 0 },
};

typedef uint64_t (*opt_pcbe_addr_f)(uint_t);

typedef struct opt_pcbe_data {
	uint_t		opd_ncounters;
	uint_t		opd_cmask;
	opt_pcbe_addr_f	opd_pesf;
	opt_pcbe_addr_f	opd_picf;
} opt_pcbe_data_t;

opt_pcbe_data_t opd;

#define	MASK48		0xFFFFFFFFFFFF

#define	EV_END {NULL, 0}
#define	GEN_EV_END {NULL, NULL, 0 }

/*
 * The following Macros are used to define tables of events that are used by
 * various families and some generic classes of events.
 *
 * When programming a performance counter there are two different values that we
 * need to set:
 *
 *   o Event - Determines the general class of event that is being used.
 *   o Unit  - A further breakdown that gives more specific value.
 *
 * Prior to the introduction of family 17h support, all family specific events
 * were programmed based on their event. The generic events, which tried to
 * provide PAPI mappings to events specified an additional unit mask.
 *
 * Starting with Family 17h, CPU performance counters default to using both the
 * unit mask and the event select. Generic events are always aliases to a
 * specific event/unit pair, hence why the units for them are always zero. In
 * addition, the naming of events in family 17h has been changed to reflect
 * AMD's guide. While this is a departure from what people are used to, it is
 * believed that matching the more detailed literature that folks are told to
 * reference is more valuable.
 */

#define	AMD_cmn_events						\
	{ "FP_dispatched_fpu_ops",			0x0 },	\
	{ "FP_cycles_no_fpu_ops_retired",		0x1 },	\
	{ "FP_dispatched_fpu_ops_ff",			0x2 },	\
	{ "LS_seg_reg_load",				0x20 },	\
	{ "LS_uarch_resync_self_modify",		0x21 },	\
	{ "LS_uarch_resync_snoop",			0x22 },	\
	{ "LS_buffer_2_full",				0x23 },	\
	{ "LS_locked_operation",			0x24 },	\
	{ "LS_retired_cflush",				0x26 },	\
	{ "LS_retired_cpuid",				0x27 },	\
	{ "DC_access",					0x40 },	\
	{ "DC_miss",					0x41 },	\
	{ "DC_refill_from_L2",				0x42 },	\
	{ "DC_refill_from_system",			0x43 },	\
	{ "DC_copyback",				0x44 },	\
	{ "DC_dtlb_L1_miss_L2_hit",			0x45 },	\
	{ "DC_dtlb_L1_miss_L2_miss",			0x46 },	\
	{ "DC_misaligned_data_ref",			0x47 },	\
	{ "DC_uarch_late_cancel_access",		0x48 },	\
	{ "DC_uarch_early_cancel_access",		0x49 },	\
	{ "DC_1bit_ecc_error_found",			0x4A },	\
	{ "DC_dispatched_prefetch_instr",		0x4B },	\
	{ "DC_dcache_accesses_by_locks",		0x4C },	\
	{ "BU_memory_requests",				0x65 },	\
	{ "BU_data_prefetch",				0x67 },	\
	{ "BU_system_read_responses",			0x6C },	\
	{ "BU_cpu_clk_unhalted",			0x76 },	\
	{ "BU_internal_L2_req",				0x7D },	\
	{ "BU_fill_req_missed_L2",			0x7E },	\
	{ "BU_fill_into_L2",				0x7F },	\
	{ "IC_fetch",					0x80 },	\
	{ "IC_miss",					0x81 },	\
	{ "IC_refill_from_L2",				0x82 },	\
	{ "IC_refill_from_system",			0x83 },	\
	{ "IC_itlb_L1_miss_L2_hit",			0x84 },	\
	{ "IC_itlb_L1_miss_L2_miss",			0x85 },	\
	{ "IC_uarch_resync_snoop",			0x86 },	\
	{ "IC_instr_fetch_stall",			0x87 },	\
	{ "IC_return_stack_hit",			0x88 },	\
	{ "IC_return_stack_overflow",			0x89 },	\
	{ "FR_retired_x86_instr_w_excp_intr",		0xC0 },	\
	{ "FR_retired_uops",				0xC1 },	\
	{ "FR_retired_branches_w_excp_intr",		0xC2 },	\
	{ "FR_retired_branches_mispred",		0xC3 },	\
	{ "FR_retired_taken_branches",			0xC4 },	\
	{ "FR_retired_taken_branches_mispred",		0xC5 },	\
	{ "FR_retired_far_ctl_transfer",		0xC6 },	\
	{ "FR_retired_resyncs",				0xC7 },	\
	{ "FR_retired_near_rets",			0xC8 },	\
	{ "FR_retired_near_rets_mispred",		0xC9 },	\
	{ "FR_retired_taken_branches_mispred_addr_miscomp",	0xCA },\
	{ "FR_retired_fastpath_double_op_instr",	0xCC },	\
	{ "FR_intr_masked_cycles",			0xCD },	\
	{ "FR_intr_masked_while_pending_cycles",	0xCE },	\
	{ "FR_taken_hardware_intrs",			0xCF },	\
	{ "FR_nothing_to_dispatch",			0xD0 },	\
	{ "FR_dispatch_stalls",				0xD1 },	\
	{ "FR_dispatch_stall_branch_abort_to_retire",	0xD2 },	\
	{ "FR_dispatch_stall_serialization",		0xD3 },	\
	{ "FR_dispatch_stall_segment_load",		0xD4 },	\
	{ "FR_dispatch_stall_reorder_buffer_full",	0xD5 },	\
	{ "FR_dispatch_stall_resv_stations_full",	0xD6 },	\
	{ "FR_dispatch_stall_fpu_full",			0xD7 },	\
	{ "FR_dispatch_stall_ls_full",			0xD8 },	\
	{ "FR_dispatch_stall_waiting_all_quiet",	0xD9 },	\
	{ "FR_dispatch_stall_far_ctl_trsfr_resync_branch_pend",	0xDA },\
	{ "FR_fpu_exception",				0xDB },	\
	{ "FR_num_brkpts_dr0",				0xDC },	\
	{ "FR_num_brkpts_dr1",				0xDD },	\
	{ "FR_num_brkpts_dr2",				0xDE },	\
	{ "FR_num_brkpts_dr3",				0xDF },	\
	{ "NB_mem_ctrlr_page_access",			0xE0 },	\
	{ "NB_mem_ctrlr_turnaround",			0xE3 },	\
	{ "NB_mem_ctrlr_bypass_counter_saturation",	0xE4 },	\
	{ "NB_cpu_io_to_mem_io",			0xE9 },	\
	{ "NB_cache_block_commands",			0xEA },	\
	{ "NB_sized_commands",				0xEB },	\
	{ "NB_ht_bus0_bandwidth",			0xF6 }

#define	AMD_FAMILY_f_events					\
	{ "BU_quadwords_written_to_system",		0x6D },	\
	{ "FR_retired_fpu_instr",			0xCB },	\
	{ "NB_mem_ctrlr_page_table_overflow",		0xE1 },	\
	{ "NB_sized_blocks",				0xE5 },	\
	{ "NB_ECC_errors",				0xE8 },	\
	{ "NB_probe_result",				0xEC },	\
	{ "NB_gart_events",				0xEE },	\
	{ "NB_ht_bus1_bandwidth",			0xF7 },	\
	{ "NB_ht_bus2_bandwidth",			0xF8 }

#define	AMD_FAMILY_10h_events					\
	{ "FP_retired_sse_ops",				0x3 },	\
	{ "FP_retired_move_ops",			0x4 },	\
	{ "FP_retired_serialize_ops",			0x5 },	\
	{ "FP_serialize_ops_cycles",			0x6 },	\
	{ "LS_cancelled_store_to_load_fwd_ops",		0x2A },	\
	{ "LS_smi_received",				0x2B },	\
	{ "DC_dtlb_L1_hit",				0x4D },	\
	{ "LS_ineffective_prefetch",			0x52 },	\
	{ "LS_global_tlb_flush",			0x54 },	\
	{ "BU_octwords_written_to_system",		0x6D },	\
	{ "Page_size_mismatches",			0x165 },	\
	{ "IC_eviction",				0x8B },	\
	{ "IC_cache_lines_invalidate",			0x8C },	\
	{ "IC_itlb_reload",				0x99 },	\
	{ "IC_itlb_reload_aborted",			0x9A },	\
	{ "FR_retired_mmx_sse_fp_instr",		0xCB },	\
	{ "Retired_x87_fp_ops",				0x1C0 },	\
	{ "IBS_ops_tagged",				0x1CF },	\
	{ "LFENCE_inst_retired",			0x1D3 },	\
	{ "SFENCE_inst_retired",			0x1D4 },	\
	{ "MFENCE_inst_retired",			0x1D5 },	\
	{ "NB_mem_ctrlr_page_table_overflow",		0xE1 },	\
	{ "NB_mem_ctrlr_dram_cmd_slots_missed",		0xE2 },	\
	{ "NB_thermal_status",				0xE8 },	\
	{ "NB_probe_results_upstream_req",		0xEC },	\
	{ "NB_gart_events",				0xEE },	\
	{ "NB_mem_ctrlr_req",				0x1F0 },	\
	{ "CB_cpu_to_dram_req_to_target",		0x1E0 },	\
	{ "CB_io_to_dram_req_to_target",		0x1E1 },	\
	{ "CB_cpu_read_cmd_latency_to_target_0_to_3",	0x1E2 },	\
	{ "CB_cpu_read_cmd_req_to_target_0_to_3",	0x1E3 },	\
	{ "CB_cpu_read_cmd_latency_to_target_4_to_7",	0x1E4 },	\
	{ "CB_cpu_read_cmd_req_to_target_4_to_7",	0x1E5 },	\
	{ "CB_cpu_cmd_latency_to_target_0_to_7",	0x1E6 },	\
	{ "CB_cpu_req_to_target_0_to_7",		0x1E7 },	\
	{ "NB_ht_bus1_bandwidth",			0xF7 },	\
	{ "NB_ht_bus2_bandwidth",			0xF8 },	\
	{ "NB_ht_bus3_bandwidth",			0x1F9 },	\
	{ "L3_read_req",				0x4E0 },	\
	{ "L3_miss",					0x4E1 },	\
	{ "L3_l2_eviction_l3_fill",			0x4E2 },	\
	{ "L3_eviction",				0x4E3 }

#define	AMD_FAMILY_11h_events					\
	{ "BU_quadwords_written_to_system",		0x6D },	\
	{ "FR_retired_mmx_fp_instr",			0xCB },	\
	{ "NB_mem_ctrlr_page_table_events",		0xE1 },	\
	{ "NB_thermal_status",				0xE8 },	\
	{ "NB_probe_results_upstream_req",		0xEC },	\
	{ "NB_dev_events",				0xEE },	\
	{ "NB_mem_ctrlr_req",				0x1F0 }

#define	AMD_cmn_generic_events						\
	{ "PAPI_br_ins",	"FR_retired_branches_w_excp_intr", 0x0 },\
	{ "PAPI_br_msp",	"FR_retired_branches_mispred",	0x0 },	\
	{ "PAPI_br_tkn",	"FR_retired_taken_branches",	0x0 },	\
	{ "PAPI_fp_ops",	"FP_dispatched_fpu_ops",	0x3 },	\
	{ "PAPI_fad_ins",	"FP_dispatched_fpu_ops",	0x1 },	\
	{ "PAPI_fml_ins",	"FP_dispatched_fpu_ops",	0x2 },	\
	{ "PAPI_fpu_idl",	"FP_cycles_no_fpu_ops_retired",	0x0 },	\
	{ "PAPI_tot_cyc",	"BU_cpu_clk_unhalted",		0x0 },	\
	{ "PAPI_tot_ins",	"FR_retired_x86_instr_w_excp_intr", 0x0 }, \
	{ "PAPI_l1_dca",	"DC_access",			0x0 },	\
	{ "PAPI_l1_dcm",	"DC_miss",			0x0 },	\
	{ "PAPI_l1_ldm",	"DC_refill_from_L2",		0xe },	\
	{ "PAPI_l1_stm",	"DC_refill_from_L2",		0x10 },	\
	{ "PAPI_l1_ica",	"IC_fetch",			0x0 },	\
	{ "PAPI_l1_icm",	"IC_miss",			0x0 },	\
	{ "PAPI_l1_icr",	"IC_fetch",			0x0 },	\
	{ "PAPI_l2_dch",	"DC_refill_from_L2",		0x1e },	\
	{ "PAPI_l2_dcm",	"DC_refill_from_system",	0x1e },	\
	{ "PAPI_l2_dcr",	"DC_refill_from_L2",		0xe },	\
	{ "PAPI_l2_dcw",	"DC_refill_from_L2",		0x10 },	\
	{ "PAPI_l2_ich",	"IC_refill_from_L2",		0x0 },	\
	{ "PAPI_l2_icm",	"IC_refill_from_system",	0x0 },	\
	{ "PAPI_l2_ldm",	"DC_refill_from_system",	0xe },	\
	{ "PAPI_l2_stm",	"DC_refill_from_system",	0x10 },	\
	{ "PAPI_res_stl",	"FR_dispatch_stalls",		0x0 },	\
	{ "PAPI_stl_icy",	"FR_nothing_to_dispatch",	0x0 },	\
	{ "PAPI_hw_int",	"FR_taken_hardware_intrs",	0x0 }

#define	OPT_cmn_generic_events						\
	{ "PAPI_tlb_dm",	"DC_dtlb_L1_miss_L2_miss",	0x0 },	\
	{ "PAPI_tlb_im",	"IC_itlb_L1_miss_L2_miss",	0x0 },	\
	{ "PAPI_fp_ins",	"FR_retired_fpu_instr",		0xd },	\
	{ "PAPI_vec_ins",	"FR_retired_fpu_instr",		0x4 }

#define	AMD_FAMILY_10h_generic_events					\
	{ "PAPI_tlb_dm",	"DC_dtlb_L1_miss_L2_miss",	0x7 },	\
	{ "PAPI_tlb_im",	"IC_itlb_L1_miss_L2_miss",	0x3 },	\
	{ "PAPI_l3_dcr",	"L3_read_req",			0xf1 }, \
	{ "PAPI_l3_icr",	"L3_read_req",			0xf2 }, \
	{ "PAPI_l3_tcr",	"L3_read_req",			0xf7 }, \
	{ "PAPI_l3_stm",	"L3_miss",			0xf4 }, \
	{ "PAPI_l3_ldm",	"L3_miss",			0xf3 }, \
	{ "PAPI_l3_tcm",	"L3_miss",			0xf7 }

static const amd_event_t family_f_events[] = {
	AMD_cmn_events,
	AMD_FAMILY_f_events,
	EV_END
};

static const amd_event_t family_10h_events[] = {
	AMD_cmn_events,
	AMD_FAMILY_10h_events,
	EV_END
};

static const amd_event_t family_11h_events[] = {
	AMD_cmn_events,
	AMD_FAMILY_11h_events,
	EV_END
};

static const amd_generic_event_t opt_generic_events[] = {
	AMD_cmn_generic_events,
	OPT_cmn_generic_events,
	GEN_EV_END
};

static const amd_generic_event_t family_10h_generic_events[] = {
	AMD_cmn_generic_events,
	AMD_FAMILY_10h_generic_events,
	GEN_EV_END
};

/*
 * For Family 17h and Family 19h, the cpcgen utility generates all of our events
 * including ones that need specific unit codes, therefore we leave all unit
 * codes out of these. Zen 1, Zen 2, and Zen 3 have different event sets that
 * they support.
 */
static const amd_generic_event_t family_17h_zen1_papi_events[] = {
	{ "PAPI_br_cn",		"ExRetCond" },
	{ "PAPI_br_ins",	"ExRetBrn" },
	{ "PAPI_fpu_idl",	"FpSchedEmpty" },
	{ "PAPI_tot_cyc",	"LsNotHaltedCyc" },
	{ "PAPI_tot_ins",	"ExRetInstr" },
	{ "PAPI_tlb_dm",	"LsL1DTlbMiss" },
	{ "PAPI_tlb_im",	"BpL1TlbMissL2Miss" },
	GEN_EV_END
};

static const amd_generic_event_t family_17h_zen2_papi_events[] = {
	{ "PAPI_br_cn",		"ExRetCond" },
	{ "PAPI_br_ins",	"ExRetBrn" },
	{ "PAPI_tot_cyc",	"LsNotHaltedCyc" },
	{ "PAPI_tot_ins",	"ExRetInstr" },
	{ "PAPI_tlb_dm",	"LsL1DTlbMiss" },
	{ "PAPI_tlb_im",	"BpL1TlbMissL2Miss" },
	GEN_EV_END
};

static const amd_generic_event_t family_19h_zen3_papi_events[] = {
	{ "PAPI_br_cn",		"ExRetCond" },
	{ "PAPI_br_ins",	"ExRetBrn" },
	{ "PAPI_tot_cyc",	"LsNotHaltedCyc" },
	{ "PAPI_tot_ins",	"ExRetInstr" },
	{ "PAPI_tlb_dm",	"LsL1DTlbMiss" },
	{ "PAPI_tlb_im",	"BpL1TlbMissL2TlbMiss" },
	GEN_EV_END
};

static const amd_generic_event_t family_19h_zen4_papi_events[] = {
	{ "PAPI_br_cn",		"ExRetCond" },
	{ "PAPI_br_ins",	"ExRetBrn" },
	{ "PAPI_tot_cyc",	"LsNotHaltedCyc" },
	{ "PAPI_tot_ins",	"ExRetInstr" },
	{ "PAPI_tlb_dm",	"LsL1DTlbMiss" },
	{ "PAPI_tlb_im",	"BpL1TlbMissL2TlbMiss" },
	GEN_EV_END
};

static const amd_generic_event_t family_1ah_zen5_papi_events[] = {
	{ "PAPI_br_cn",		"Retired_Conditional_Branch_Instructions" },
	{ "PAPI_br_ins",	"Retired_Branch_Instructions" },
	{ "PAPI_br_msp",
		"Retired_Conditional_Branch_Instructions_Mispredicted" },
	{ "PAPI_br_ucn",	"Retired_Unconditional_Branch_Instructions" },
	{ "PAPI_tot_cyc",	"Cycles_Not_in_Halt" },
	{ "PAPI_tot_ins",	"Retired_Instructions" },
	{ "PAPI_hw_int",	"Interrupts_Taken" },
	{ "PAPI_tlb_sd",	"TLB_Flush_Events" },
	GEN_EV_END
};

static char	*evlist;
static size_t	evlist_sz;
static const amd_event_t *amd_events = NULL;
static uint_t amd_family, amd_model;
static const amd_generic_event_t *amd_generic_events = NULL;

static char amd_fam_f_rev_ae_bkdg[] = "See \"BIOS and Kernel Developer's "
"Guide for AMD Athlon 64 and AMD Opteron Processors\" (AMD publication 26094)";
static char amd_fam_f_NPT_bkdg[] = "See \"BIOS and Kernel Developer's Guide "
"for AMD NPT Family 0Fh Processors\" (AMD publication 32559)";
static char amd_fam_10h_bkdg[] = "See \"BIOS and Kernel Developer's Guide "
"(BKDG) For AMD Family 10h Processors\" (AMD publication 31116)";
static char amd_fam_11h_bkdg[] = "See \"BIOS and Kernel Developer's Guide "
"(BKDG) For AMD Family 11h Processors\" (AMD publication 41256)";
static char amd_fam_17h_zen1_reg[] = "See \"Open-Source Register Reference For "
"AMD Family 17h Processors Models 00h-2Fh\" (AMD publication 56255) and "
"amd_f17h_zen1_events(3CPC)";
static char amd_fam_17h_zen2_reg[] = "See \"Preliminary Processor Programming "
"Reference (PPR) for AMD Family 17h Model 31h, Revision B0 Processors\" "
"(AMD publication 55803), \"Processor Programming Reference (PPR) for AMD "
"Family 17h Model 71h, Revision B0 Processors\" (AMD publication 56176), and "
"amd_f17h_zen2_events(3CPC)";
static char amd_fam_19h_zen3_reg[] = "See \"Preliminary Processor Programming "
"Reference (PPR) for AMD Family 19h Model 01h, Revision B1 Processors Volume "
"1 of 2\" (AMD publication 55898), \"Processor Programming Reference (PPR) "
"for AMD Family 19h Model 21h, Revision B0 Processors\" (AMD publication "
"56214), and amd_f19h_zen3_events(3CPC)";
static char amd_fam_19h_zen4_reg[] = "See \"Processor Programming Reference "
"(PPR) for AMD Family 19h Model 11h, Revision B1 Processors Volume 1 of 6\" "
"(AMD publication 55901), \"Processor Programming Reference (PPR) for AMD "
"Family 19h Model 61h, Revision B1 Processors\" (AMD publication 56713), "
"\"Processor Programming Reference (PPR) for AMD Family 19h Model 70h, "
"Revision A0 Processors\" (AMD publication 57019), and "
"amd_f19h_zen4_events(3CPC)";
static char amd_fam_1ah_zen5_reg[] = "See \"Performance Monitor Counters "
"for AMD Family 1Ah Model 00h-Fh Processors\" (AMD publication 58550) and "
"amd_f1ah_zen5_events(3CPC)";

static char amd_pcbe_impl_name[64];
static char *amd_pcbe_cpuref;


#define	BITS(v, u, l)   \
	(((v) >> (l)) & ((1 << (1 + (u) - (l))) - 1))

static uint64_t
opt_pcbe_pes_addr(uint_t counter)
{
	ASSERT3U(counter, <, opd.opd_ncounters);
	return (PES_BASE_ADDR + counter);
}

static uint64_t
opt_pcbe_pes_ext_addr(uint_t counter)
{
	ASSERT3U(counter, <, opd.opd_ncounters);
	return (PES_EXT_BASE_ADDR + 2 * counter);
}

static uint64_t
opt_pcbe_pic_addr(uint_t counter)
{
	ASSERT3U(counter, <, opd.opd_ncounters);
	return (PIC_BASE_ADDR + counter);
}

static uint64_t
opt_pcbe_pic_ext_addr(uint_t counter)
{
	ASSERT3U(counter, <, opd.opd_ncounters);
	return (PIC_EXT_BASE_ADDR + 2 * counter);
}

static int
opt_pcbe_init(void)
{
	const amd_event_t		*evp;
	const amd_generic_event_t	*gevp;
	x86_uarchrev_t			uarchrev;

	amd_family = cpuid_getfamily(CPU);
	amd_model = cpuid_getmodel(CPU);
	uarchrev = cpuid_getuarchrev(CPU);

	/*
	 * Make sure this really _is_ an Opteron or Athlon 64 system. The kernel
	 * loads this module based on its name in the module directory, but it
	 * could have been renamed.
	 */
	if ((cpuid_getvendor(CPU) != X86_VENDOR_AMD || amd_family < 0xf) &&
	    cpuid_getvendor(CPU) != X86_VENDOR_HYGON)
		return (-1);

	if (amd_family == 0xf) {
		/* Some tools expect this string for family 0fh */
		(void) snprintf(amd_pcbe_impl_name, sizeof (amd_pcbe_impl_name),
		    "AMD Opteron & Athlon64");
	} else {
		(void) snprintf(amd_pcbe_impl_name, sizeof (amd_pcbe_impl_name),
		    "%s Family %02xh",
		    cpuid_getvendor(CPU) == X86_VENDOR_HYGON ? "Hygon" : "AMD",
		    amd_family);
	}

	/*
	 * Determine whether or not the extended counter set is supported on
	 * this processor.
	 */
	if (is_x86_feature(x86_featureset, X86FSET_AMD_PCEC)) {
		opd.opd_ncounters = OPT_PCBE_EXT_NCOUNTERS;
		opd.opd_pesf = opt_pcbe_pes_ext_addr;
		opd.opd_picf = opt_pcbe_pic_ext_addr;
	} else {
		opd.opd_ncounters = OPT_PCBE_DEF_NCOUNTERS;
		opd.opd_pesf = opt_pcbe_pes_addr;
		opd.opd_picf = opt_pcbe_pic_addr;
	}
	opd.opd_cmask = (1 << opd.opd_ncounters) - 1;

	/*
	 * Figure out processor revision here and assign appropriate
	 * event configuration.
	 */
	switch (uarchrev_uarch(uarchrev)) {
	case X86_UARCH_AMD_LEGACY:
		switch (amd_family) {
		case 0xf: {
			x86_chiprev_t rev;

			rev = cpuid_getchiprev(CPU);

			if (chiprev_at_least(rev,
			    X86_CHIPREV_AMD_LEGACY_F_REV_F)) {
				amd_pcbe_cpuref = amd_fam_f_NPT_bkdg;
			} else {
				amd_pcbe_cpuref = amd_fam_f_rev_ae_bkdg;
			}
			amd_events = family_f_events;
			amd_generic_events = opt_generic_events;
			break;
		}
		case 0x10:
			amd_pcbe_cpuref = amd_fam_10h_bkdg;
			amd_events = family_10h_events;
			amd_generic_events = family_10h_generic_events;
			break;
		case 0x11:
			amd_pcbe_cpuref = amd_fam_11h_bkdg;
			amd_events = family_11h_events;
			amd_generic_events = opt_generic_events;
			break;
		default:
			return (-1);
		}
		break;
	case X86_UARCH_AMD_ZEN1:
	case X86_UARCH_AMD_ZENPLUS:
		amd_pcbe_cpuref = amd_fam_17h_zen1_reg;
		amd_events = opteron_pcbe_f17h_zen1_events;
		amd_generic_events = family_17h_zen1_papi_events;
		break;
	case X86_UARCH_AMD_ZEN2:
		amd_pcbe_cpuref = amd_fam_17h_zen2_reg;
		amd_events = opteron_pcbe_f17h_zen2_events;
		amd_generic_events = family_17h_zen2_papi_events;
		break;
	case X86_UARCH_AMD_ZEN3:
		amd_pcbe_cpuref = amd_fam_19h_zen3_reg;
		amd_events = opteron_pcbe_f19h_zen3_events;
		amd_generic_events = family_19h_zen3_papi_events;
		break;
	case X86_UARCH_AMD_ZEN4:
		amd_pcbe_cpuref = amd_fam_19h_zen4_reg;
		amd_events = opteron_pcbe_f19h_zen4_events;
		amd_generic_events = family_19h_zen4_papi_events;
		break;
	case X86_UARCH_AMD_ZEN5:
		amd_pcbe_cpuref = amd_fam_1ah_zen5_reg;
		amd_events = opteron_pcbe_f1ah_zen5_events;
		amd_generic_events = family_1ah_zen5_papi_events;
		break;
	default:
		/*
		 * Different families have different meanings on events and even
		 * worse (like family 15h), different constraints around
		 * programming these values.
		 */
		return (-1);
	}

	/*
	 * Construct event list.
	 *
	 * First pass:  Calculate size needed. We'll need an additional byte
	 *		for the NULL pointer during the last strcat.
	 *
	 * Second pass: Copy strings.
	 */
	for (evp = amd_events; evp->name != NULL; evp++)
		evlist_sz += strlen(evp->name) + 1;

	for (gevp = amd_generic_events; gevp->name != NULL; gevp++)
		evlist_sz += strlen(gevp->name) + 1;

	evlist = kmem_alloc(evlist_sz + 1, KM_SLEEP);
	evlist[0] = '\0';

	for (evp = amd_events; evp->name != NULL; evp++) {
		(void) strcat(evlist, evp->name);
		(void) strcat(evlist, ",");
	}

	for (gevp = amd_generic_events; gevp->name != NULL; gevp++) {
		(void) strcat(evlist, gevp->name);
		(void) strcat(evlist, ",");
	}

	/*
	 * Remove trailing comma.
	 */
	evlist[evlist_sz - 1] = '\0';

	return (0);
}

static uint_t
opt_pcbe_ncounters(void)
{
	return (opd.opd_ncounters);
}

static const char *
opt_pcbe_impl_name(void)
{
	return (amd_pcbe_impl_name);
}

static const char *
opt_pcbe_cpuref(void)
{

	return (amd_pcbe_cpuref);
}

/*ARGSUSED*/
static char *
opt_pcbe_list_events(uint_t picnum)
{
	return (evlist);
}

static char *
opt_pcbe_list_attrs(void)
{
	return ("edge,pc,inv,cmask,umask");
}

static const amd_generic_event_t *
find_generic_event(char *name)
{
	const amd_generic_event_t	*gevp;

	for (gevp = amd_generic_events; gevp->name != NULL; gevp++)
		if (strcmp(name, gevp->name) == 0)
			return (gevp);

	return (NULL);
}

static const amd_event_t *
find_event(char *name)
{
	const amd_event_t	*evp;

	for (evp = amd_events; evp->name != NULL; evp++)
		if (strcmp(name, evp->name) == 0)
			return (evp);

	return (NULL);
}

/*ARGSUSED*/
static uint64_t
opt_pcbe_event_coverage(char *event)
{
	/*
	 * Check whether counter event is supported
	 */
	if (find_event(event) == NULL && find_generic_event(event) == NULL)
		return (0);

	/*
	 * Fortunately, all counters can count all events.
	 */
	return (opd.opd_cmask);
}

static uint64_t
opt_pcbe_overflow_bitmap(void)
{
	/*
	 * Unfortunately, this chip cannot detect which counter overflowed, so
	 * we must act as if they all did.
	 */
	return (opd.opd_cmask);
}

/*ARGSUSED*/
static int
opt_pcbe_configure(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
    uint_t nattrs, kcpc_attr_t *attrs, void **data, void *token)
{
	opt_pcbe_config_t		*cfg;
	const amd_event_t		*evp;
	amd_event_t			ev_raw = { "raw", 0};
	const amd_generic_event_t	*gevp;
	int				i;
	uint64_t			evsel = 0, evsel_tmp = 0;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		cfg = *data;
		cfg->opt_rawpic = preset & MASK48;
		return (0);
	}

	if (picnum >= opd.opd_ncounters)
		return (CPC_INVALID_PICNUM);

	if ((evp = find_event(event)) == NULL) {
		if ((gevp = find_generic_event(event)) != NULL) {
			evp = find_event(gevp->event);
			ASSERT(evp != NULL);

			if (nattrs > 0)
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);

			evsel |= gevp->umask << OPT_PES_UMASK_SHIFT;
		} else {
			long tmp;

			/*
			 * If ddi_strtol() likes this event, use it as a raw
			 * event code.
			 */
			if (ddi_strtol(event, NULL, 0, &tmp) != 0)
				return (CPC_INVALID_EVENT);

			ev_raw.emask = tmp;
			evp = &ev_raw;
		}
	}

	/*
	 * Configuration of EventSelect register. While on some families
	 * certain bits might not be supported (e.g. Guest/Host on family
	 * 11h), setting these bits is harmless
	 */

	/* Set GuestOnly bit to 0 and HostOnly bit to 1 */
	evsel &= ~OPT_PES_HOST;
	evsel &= ~OPT_PES_GUEST;

	/* Set bits [35:32] for extended part of Event Select field */
	evsel_tmp = evp->emask & 0x0f00;
	evsel |= evsel_tmp << OPT_PES_EVSELHI_SHIFT;

	evsel |= evp->emask & 0x00ff;
	evsel |= evp->unit << OPT_PES_UMASK_SHIFT;

	if (flags & CPC_COUNT_USER)
		evsel |= OPT_PES_USR;
	if (flags & CPC_COUNT_SYSTEM)
		evsel |= OPT_PES_OS;
	if (flags & CPC_OVF_NOTIFY_EMT)
		evsel |= OPT_PES_INT;

	for (i = 0; i < nattrs; i++) {
		if (strcmp(attrs[i].ka_name, "edge") == 0) {
			if (attrs[i].ka_val != 0)
				evsel |= OPT_PES_EDGE;
		} else if (strcmp(attrs[i].ka_name, "pc") == 0) {
			if (attrs[i].ka_val != 0)
				evsel |= OPT_PES_PC;
		} else if (strcmp(attrs[i].ka_name, "inv") == 0) {
			if (attrs[i].ka_val != 0)
				evsel |= OPT_PES_INV;
		} else if (strcmp(attrs[i].ka_name, "cmask") == 0) {
			if ((attrs[i].ka_val | OPT_PES_CMASK_MASK) !=
			    OPT_PES_CMASK_MASK)
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			evsel |= attrs[i].ka_val << OPT_PES_CMASK_SHIFT;
		} else if (strcmp(attrs[i].ka_name, "umask") == 0) {
			if ((attrs[i].ka_val | OPT_PES_UMASK_MASK) !=
			    OPT_PES_UMASK_MASK)
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			evsel |= attrs[i].ka_val << OPT_PES_UMASK_SHIFT;
		} else
			return (CPC_INVALID_ATTRIBUTE);
	}

	cfg = kmem_alloc(sizeof (*cfg), KM_SLEEP);

	cfg->opt_picno = picnum;
	cfg->opt_evsel = evsel;
	cfg->opt_rawpic = preset & MASK48;

	*data = cfg;
	return (0);
}

static void
opt_pcbe_program(void *token)
{
	opt_pcbe_config_t	*cfgs[OPT_PCBE_EXT_NCOUNTERS] = { &nullcfgs[0],
						&nullcfgs[1], &nullcfgs[2],
						&nullcfgs[3], &nullcfgs[4],
						&nullcfgs[5] };
	opt_pcbe_config_t	*pcfg = NULL;
	int			i;
	ulong_t			curcr4 = getcr4();

	/*
	 * Allow nonprivileged code to read the performance counters if desired.
	 */
	if (kcpc_allow_nonpriv(token))
		setcr4(curcr4 | CR4_PCE);
	else
		setcr4(curcr4 & ~CR4_PCE);

	/*
	 * Query kernel for all configs which will be co-programmed.
	 */
	do {
		pcfg = (opt_pcbe_config_t *)kcpc_next_config(token, pcfg, NULL);

		if (pcfg != NULL) {
			ASSERT(pcfg->opt_picno < opd.opd_ncounters);
			cfgs[pcfg->opt_picno] = pcfg;
		}
	} while (pcfg != NULL);

	/*
	 * Program in two loops. The first configures and presets the counter,
	 * and the second loop enables the counters. This ensures that the
	 * counters are all enabled as closely together in time as possible.
	 */

	for (i = 0; i < opd.opd_ncounters; i++) {
		wrmsr(opd.opd_pesf(i), cfgs[i]->opt_evsel);
		wrmsr(opd.opd_picf(i), cfgs[i]->opt_rawpic);
	}

	for (i = 0; i < opd.opd_ncounters; i++) {
		wrmsr(opd.opd_pesf(i), cfgs[i]->opt_evsel |
		    (uint64_t)(uintptr_t)OPT_PES_ENABLE);
	}
}

static void
opt_pcbe_allstop(void)
{
	int		i;

	for (i = 0; i < opd.opd_ncounters; i++)
		wrmsr(opd.opd_pesf(i), 0ULL);

	/*
	 * Disable non-privileged access to the counter registers.
	 */
	setcr4(getcr4() & ~CR4_PCE);
}

static void
opt_pcbe_sample(void *token)
{
	opt_pcbe_config_t	*cfgs[OPT_PCBE_EXT_NCOUNTERS] = { NULL, NULL,
						NULL, NULL, NULL, NULL };
	opt_pcbe_config_t	*pcfg = NULL;
	int			i;
	uint64_t		curpic[OPT_PCBE_EXT_NCOUNTERS];
	uint64_t		*addrs[OPT_PCBE_EXT_NCOUNTERS];
	uint64_t		*tmp;
	int64_t			diff;

	for (i = 0; i < opd.opd_ncounters; i++)
		curpic[i] = rdmsr(opd.opd_picf(i));

	/*
	 * Query kernel for all configs which are co-programmed.
	 */
	do {
		pcfg = (opt_pcbe_config_t *)kcpc_next_config(token, pcfg, &tmp);

		if (pcfg != NULL) {
			ASSERT3U(pcfg->opt_picno, <, opd.opd_ncounters);
			cfgs[pcfg->opt_picno] = pcfg;
			addrs[pcfg->opt_picno] = tmp;
		}
	} while (pcfg != NULL);

	for (i = 0; i < opd.opd_ncounters; i++) {
		if (cfgs[i] == NULL)
			continue;

		diff = (curpic[i] - cfgs[i]->opt_rawpic) & MASK48;
		*addrs[i] += diff;
		DTRACE_PROBE4(opt__pcbe__sample, int, i, uint64_t, *addrs[i],
		    uint64_t, curpic[i], uint64_t, cfgs[i]->opt_rawpic);
		cfgs[i]->opt_rawpic = *addrs[i] & MASK48;
	}
}

static void
opt_pcbe_free(void *config)
{
	kmem_free(config, sizeof (opt_pcbe_config_t));
}


static struct modlpcbe modlpcbe = {
	&mod_pcbeops,
	"AMD Performance Counters",
	&opt_pcbe_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modlpcbe,
};

int
_init(void)
{
	int ret;

	if (opt_pcbe_init() != 0)
		return (ENOTSUP);

	if ((ret = mod_install(&modl)) != 0)
		kmem_free(evlist, evlist_sz + 1);

	return (ret);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modl)) == 0)
		kmem_free(evlist, evlist_sz + 1);
	return (ret);
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&modl, mi));
}
