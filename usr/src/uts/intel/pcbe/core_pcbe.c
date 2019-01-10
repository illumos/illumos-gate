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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
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
 * Performance Counter Back-End for Intel processors supporting Architectural
 * Performance Monitoring.
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
#include <sys/cred.h>
#include <sys/policy.h>

#include "core_pcbe_table.h"
#include <core_pcbe_cpcgen.h>

static int core_pcbe_init(void);
static uint_t core_pcbe_ncounters(void);
static const char *core_pcbe_impl_name(void);
static const char *core_pcbe_cpuref(void);
static char *core_pcbe_list_events(uint_t picnum);
static char *core_pcbe_list_attrs(void);
static uint64_t core_pcbe_event_coverage(char *event);
static uint64_t core_pcbe_overflow_bitmap(void);
static int core_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void core_pcbe_program(void *token);
static void core_pcbe_allstop(void);
static void core_pcbe_sample(void *token);
static void core_pcbe_free(void *config);

#define	FALSE	0
#define	TRUE	1

/* Counter Type */
#define	CORE_GPC	0	/* General-Purpose Counter (GPC) */
#define	CORE_FFC	1	/* Fixed-Function Counter (FFC) */

/* MSR Addresses */
#define	GPC_BASE_PMC		0x00c1	/* First GPC */
#define	GPC_BASE_PES		0x0186	/* First GPC Event Select register */
#define	FFC_BASE_PMC		0x0309	/* First FFC */
#define	PERF_FIXED_CTR_CTRL	0x038d	/* Used to enable/disable FFCs */
#define	PERF_GLOBAL_STATUS	0x038e	/* Overflow status register */
#define	PERF_GLOBAL_CTRL	0x038f	/* Used to enable/disable counting */
#define	PERF_GLOBAL_OVF_CTRL	0x0390	/* Used to clear overflow status */

/*
 * Processor Event Select register fields
 */
#define	CORE_USR	(1ULL << 16)	/* Count while not in ring 0 */
#define	CORE_OS		(1ULL << 17)	/* Count while in ring 0 */
#define	CORE_EDGE	(1ULL << 18)	/* Enable edge detection */
#define	CORE_PC		(1ULL << 19)	/* Enable pin control */
#define	CORE_INT	(1ULL << 20)	/* Enable interrupt on overflow */
#define	CORE_EN		(1ULL << 22)	/* Enable counting */
#define	CORE_INV	(1ULL << 23)	/* Invert the CMASK */
#define	CORE_ANYTHR	(1ULL << 21)	/* Count event for any thread on core */

#define	CORE_UMASK_SHIFT	8
#define	CORE_UMASK_MASK		0xffu
#define	CORE_CMASK_SHIFT	24
#define	CORE_CMASK_MASK		0xffu

/*
 * Fixed-function counter attributes
 */
#define	CORE_FFC_OS_EN	(1ULL << 0)	/* Count while not in ring 0 */
#define	CORE_FFC_USR_EN	(1ULL << 1)	/* Count while in ring 1 */
#define	CORE_FFC_ANYTHR	(1ULL << 2)	/* Count event for any thread on core */
#define	CORE_FFC_PMI	(1ULL << 3)	/* Enable interrupt on overflow */

/*
 * Number of bits for specifying each FFC's attributes in the control register
 */
#define	CORE_FFC_ATTR_SIZE	4

/*
 * CondChgd and OvfBuffer fields of global status and overflow control registers
 */
#define	CONDCHGD	(1ULL << 63)
#define	OVFBUFFER	(1ULL << 62)
#define	MASK_CONDCHGD_OVFBUFFER	(CONDCHGD | OVFBUFFER)

#define	ALL_STOPPED	0ULL

#define	BITMASK_XBITS(x)	((1ull << (x)) - 1ull)

/*
 * Only the lower 32-bits can be written to in the general-purpose
 * counters.  The higher bits are extended from bit 31; all ones if
 * bit 31 is one and all zeros otherwise.
 *
 * The fixed-function counters do not have this restriction.
 */
#define	BITS_EXTENDED_FROM_31	(BITMASK_XBITS(width_gpc) & ~BITMASK_XBITS(31))

#define	WRMSR(msr, value)						\
	wrmsr((msr), (value));						\
	DTRACE_PROBE2(wrmsr, uint64_t, (msr), uint64_t, (value));

#define	RDMSR(msr, value)						\
	(value) = rdmsr((msr));						\
	DTRACE_PROBE2(rdmsr, uint64_t, (msr), uint64_t, (value));

typedef struct core_pcbe_config {
	uint64_t	core_rawpic;
	uint64_t	core_ctl;	/* Event Select bits */
	uint64_t	core_pmc;	/* Counter register address */
	uint64_t	core_pes;	/* Event Select register address */
	uint_t		core_picno;
	uint8_t		core_pictype;	/* CORE_GPC or CORE_FFC */
} core_pcbe_config_t;

pcbe_ops_t core_pcbe_ops = {
	PCBE_VER_1,			/* pcbe_ver */
	CPC_CAP_OVERFLOW_INTERRUPT | CPC_CAP_OVERFLOW_PRECISE,	/* pcbe_caps */
	core_pcbe_ncounters,		/* pcbe_ncounters */
	core_pcbe_impl_name,		/* pcbe_impl_name */
	core_pcbe_cpuref,		/* pcbe_cpuref */
	core_pcbe_list_events,		/* pcbe_list_events */
	core_pcbe_list_attrs,		/* pcbe_list_attrs */
	core_pcbe_event_coverage,	/* pcbe_event_coverage */
	core_pcbe_overflow_bitmap,	/* pcbe_overflow_bitmap */
	core_pcbe_configure,		/* pcbe_configure */
	core_pcbe_program,		/* pcbe_program */
	core_pcbe_allstop,		/* pcbe_allstop */
	core_pcbe_sample,		/* pcbe_sample */
	core_pcbe_free			/* pcbe_free */
};

struct nametable_core_uarch {
	const char	*name;
	uint64_t	restricted_bits;
	uint8_t		event_num;
};

/*
 * Counting an event for all cores or all bus agents requires cpc_cpu privileges
 */
#define	ALL_CORES	(1ULL << 15)
#define	ALL_AGENTS	(1ULL << 13)

struct generic_events {
	const char	*name;
	uint8_t		event_num;
	uint8_t		umask;
};

static const struct generic_events cmn_generic_events[] = {
	{ "PAPI_tot_cyc", 0x3c, 0x00 }, /* cpu_clk_unhalted.thread_p/core */
	{ "PAPI_tot_ins", 0xc0, 0x00 }, /* inst_retired.any_p		  */
	{ "PAPI_br_ins",  0xc4, 0x0c }, /* br_inst_retired.taken	  */
	{ "PAPI_br_msp",  0xc5, 0x00 }, /* br_inst_retired.mispred	  */
	{ "PAPI_br_ntk",  0xc4, 0x03 },
				/* br_inst_retired.pred_not_taken|pred_taken */
	{ "PAPI_br_prc",  0xc4, 0x05 },
				/* br_inst_retired.pred_not_taken|pred_taken */
	{ "PAPI_hw_int",  0xc8, 0x00 }, /* hw_int_rvc			  */
	{ "PAPI_tot_iis", 0xaa, 0x01 }, /* macro_insts.decoded		  */
	{ "PAPI_l1_dca",  0x43, 0x01 }, /* l1d_all_ref			  */
	{ "PAPI_l1_icm",  0x81, 0x00 }, /* l1i_misses			  */
	{ "PAPI_l1_icr",  0x80, 0x00 }, /* l1i_reads			  */
	{ "PAPI_l1_tcw",  0x41, 0x0f }, /* l1d_cache_st.mesi		  */
	{ "PAPI_l2_stm",  0x2a, 0x41 }, /* l2_st.self.i_state		  */
	{ "PAPI_l2_tca",  0x2e, 0x4f }, /* l2_rqsts.self.demand.mesi	  */
	{ "PAPI_l2_tch",  0x2e, 0x4e }, /* l2_rqsts.mes			  */
	{ "PAPI_l2_tcm",  0x2e, 0x41 }, /* l2_rqsts.self.demand.i_state   */
	{ "PAPI_l2_tcw",  0x2a, 0x4f }, /* l2_st.self.mesi		  */
	{ "PAPI_ld_ins",  0xc0, 0x01 }, /* inst_retired.loads		  */
	{ "PAPI_lst_ins", 0xc0, 0x03 }, /* inst_retired.loads|stores	  */
	{ "PAPI_sr_ins",  0xc0, 0x02 }, /* inst_retired.stores		  */
	{ "PAPI_tlb_dm",  0x08, 0x01 }, /* dtlb_misses.any		  */
	{ "PAPI_tlb_im",  0x82, 0x12 }, /* itlb.small_miss|large_miss	  */
	{ "PAPI_tlb_tl",  0x0c, 0x03 }, /* page_walks			  */
	{ "",		  NT_END, 0  }
};

static const struct generic_events generic_events_pic0[] = {
	{ "PAPI_l1_dcm",  0xcb, 0x01 }, /* mem_load_retired.l1d_miss */
	{ "",		  NT_END, 0  }
};

/*
 * The events listed in the following table can be counted on all
 * general-purpose counters on processors that are of Penryn and Merom Family
 */
static const struct nametable_core_uarch cmn_gpc_events_core_uarch[] = {
	/* Alphabetical order of event name */

	{ "baclears",			0x0,	0xe6 },
	{ "bogus_br",			0x0,	0xe4 },
	{ "br_bac_missp_exec",		0x0,	0x8a },

	{ "br_call_exec",		0x0,	0x92 },
	{ "br_call_missp_exec",		0x0,	0x93 },
	{ "br_cnd_exec",		0x0,	0x8b },

	{ "br_cnd_missp_exec",		0x0,	0x8c },
	{ "br_ind_call_exec",		0x0,	0x94 },
	{ "br_ind_exec",		0x0,	0x8d },

	{ "br_ind_missp_exec",		0x0,	0x8e },
	{ "br_inst_decoded",		0x0,	0xe0 },
	{ "br_inst_exec",		0x0,	0x88 },

	{ "br_inst_retired",		0x0,	0xc4 },
	{ "br_inst_retired_mispred",	0x0,	0xc5 },
	{ "br_missp_exec",		0x0,	0x89 },

	{ "br_ret_bac_missp_exec",	0x0,	0x91 },
	{ "br_ret_exec",		0x0,	0x8f },
	{ "br_ret_missp_exec",		0x0,	0x90 },

	{ "br_tkn_bubble_1",		0x0,	0x97 },
	{ "br_tkn_bubble_2",		0x0,	0x98 },
	{ "bus_bnr_drv",		ALL_AGENTS,	0x61 },

	{ "bus_data_rcv",		ALL_CORES,	0x64 },
	{ "bus_drdy_clocks",		ALL_AGENTS,	0x62 },
	{ "bus_hit_drv",		ALL_AGENTS,	0x7a },

	{ "bus_hitm_drv",		ALL_AGENTS,	0x7b },
	{ "bus_io_wait",		ALL_CORES,	0x7f },
	{ "bus_lock_clocks",		ALL_CORES | ALL_AGENTS,	0x63 },

	{ "bus_request_outstanding",	ALL_CORES | ALL_AGENTS,	0x60 },
	{ "bus_trans_any",		ALL_CORES | ALL_AGENTS,	0x70 },
	{ "bus_trans_brd",		ALL_CORES | ALL_AGENTS,	0x65 },

	{ "bus_trans_burst",		ALL_CORES | ALL_AGENTS,	0x6e },
	{ "bus_trans_def",		ALL_CORES | ALL_AGENTS,	0x6d },
	{ "bus_trans_ifetch",		ALL_CORES | ALL_AGENTS,	0x68 },

	{ "bus_trans_inval",		ALL_CORES | ALL_AGENTS,	0x69 },
	{ "bus_trans_io",		ALL_CORES | ALL_AGENTS,	0x6c },
	{ "bus_trans_mem",		ALL_CORES | ALL_AGENTS,	0x6f },

	{ "bus_trans_p",		ALL_CORES | ALL_AGENTS,	0x6b },
	{ "bus_trans_pwr",		ALL_CORES | ALL_AGENTS,	0x6a },
	{ "bus_trans_rfo",		ALL_CORES | ALL_AGENTS,	0x66 },

	{ "bus_trans_wb",		ALL_CORES | ALL_AGENTS,	0x67 },
	{ "busq_empty",			ALL_CORES,	0x7d },
	{ "cmp_snoop",			ALL_CORES,	0x78 },

	{ "cpu_clk_unhalted",		0x0,	0x3c },
	{ "cycles_int",			0x0,	0xc6 },
	{ "cycles_l1i_mem_stalled",	0x0,	0x86 },

	{ "dtlb_misses",		0x0,	0x08 },
	{ "eist_trans",			0x0,	0x3a },
	{ "esp",			0x0,	0xab },

	{ "ext_snoop",			ALL_AGENTS,	0x77 },
	{ "fp_mmx_trans",		0x0,	0xcc },
	{ "hw_int_rcv",			0x0,	0xc8 },

	{ "ild_stall",			0x0,	0x87 },
	{ "inst_queue",			0x0,	0x83 },
	{ "inst_retired",		0x0,	0xc0 },

	{ "itlb",			0x0,	0x82 },
	{ "itlb_miss_retired",		0x0,	0xc9 },
	{ "l1d_all_ref",		0x0,	0x43 },

	{ "l1d_cache_ld",		0x0,	0x40 },
	{ "l1d_cache_lock",		0x0,	0x42 },
	{ "l1d_cache_st",		0x0,	0x41 },

	{ "l1d_m_evict",		0x0,	0x47 },
	{ "l1d_m_repl",			0x0,	0x46 },
	{ "l1d_pend_miss",		0x0,	0x48 },

	{ "l1d_prefetch",		0x0,	0x4e },
	{ "l1d_repl",			0x0,	0x45 },
	{ "l1d_split",			0x0,	0x49 },

	{ "l1i_misses",			0x0,	0x81 },
	{ "l1i_reads",			0x0,	0x80 },
	{ "l2_ads",			ALL_CORES,	0x21 },

	{ "l2_dbus_busy_rd",		ALL_CORES,	0x23 },
	{ "l2_ifetch",			ALL_CORES,	0x28 },
	{ "l2_ld",			ALL_CORES,	0x29 },

	{ "l2_lines_in",		ALL_CORES,	0x24 },
	{ "l2_lines_out",		ALL_CORES,	0x26 },
	{ "l2_lock",			ALL_CORES,	0x2b },

	{ "l2_m_lines_in",		ALL_CORES,	0x25 },
	{ "l2_m_lines_out",		ALL_CORES,	0x27 },
	{ "l2_no_req",			ALL_CORES,	0x32 },

	{ "l2_reject_busq",		ALL_CORES,	0x30 },
	{ "l2_rqsts",			ALL_CORES,	0x2e },
	{ "l2_st",			ALL_CORES,	0x2a },

	{ "load_block",			0x0,	0x03 },
	{ "load_hit_pre",		0x0,	0x4c },
	{ "machine_nukes",		0x0,	0xc3 },

	{ "macro_insts",		0x0,	0xaa },
	{ "memory_disambiguation",	0x0,	0x09 },
	{ "misalign_mem_ref",		0x0,	0x05 },
	{ "page_walks",			0x0,	0x0c },

	{ "pref_rqsts_dn",		0x0,	0xf8 },
	{ "pref_rqsts_up",		0x0,	0xf0 },
	{ "rat_stalls",			0x0,	0xd2 },

	{ "resource_stalls",		0x0,	0xdc },
	{ "rs_uops_dispatched",		0x0,	0xa0 },
	{ "seg_reg_renames",		0x0,	0xd5 },

	{ "seg_rename_stalls",		0x0,	0xd4 },
	{ "segment_reg_loads",		0x0,	0x06 },
	{ "simd_assist",		0x0,	0xcd },

	{ "simd_comp_inst_retired",	0x0,	0xca },
	{ "simd_inst_retired",		0x0,	0xc7 },
	{ "simd_instr_retired",		0x0,	0xce },

	{ "simd_sat_instr_retired",	0x0,	0xcf },
	{ "simd_sat_uop_exec",		0x0,	0xb1 },
	{ "simd_uop_type_exec",		0x0,	0xb3 },

	{ "simd_uops_exec",		0x0,	0xb0 },
	{ "snoop_stall_drv",		ALL_CORES | ALL_AGENTS,	0x7e },
	{ "sse_pre_exec",		0x0,	0x07 },

	{ "sse_pre_miss",		0x0,	0x4b },
	{ "store_block",		0x0,	0x04 },
	{ "thermal_trip",		0x0,	0x3b },

	{ "uops_retired",		0x0,	0xc2 },
	{ "x87_ops_retired",		0x0,	0xc1 },
	{ "",				0x0,	NT_END }
};

/*
 * If any of the pic specific events require privileges, make sure to add a
 * check in configure_gpc() to find whether an event hard-coded as a number by
 * the user has any privilege requirements
 */
static const struct nametable_core_uarch pic0_events[] = {
	/* Alphabetical order of event name */

	{ "cycles_div_busy",		0x0,	0x14 },
	{ "fp_comp_ops_exe",		0x0,	0x10 },
	{ "idle_during_div",		0x0,	0x18 },

	{ "mem_load_retired",		0x0,	0xcb },
	{ "rs_uops_dispatched_port",	0x0,	0xa1 },
	{ "",				0x0,	NT_END }
};

static const struct nametable_core_uarch pic1_events[] = {
	/* Alphabetical order of event name */

	{ "delayed_bypass",	0x0,	0x19 },
	{ "div",		0x0,	0x13 },
	{ "fp_assist",		0x0,	0x11 },

	{ "mul",		0x0,	0x12 },
	{ "",			0x0,	NT_END }
};

/* FFC entries must be in order */
static char *ffc_names_non_htt[] = {
	"instr_retired.any",
	"cpu_clk_unhalted.core",
	"cpu_clk_unhalted.ref",
	NULL
};

static char *ffc_names_htt[] = {
	"instr_retired.any",
	"cpu_clk_unhalted.thread",
	"cpu_clk_unhalted.ref",
	NULL
};

static char *ffc_genericnames[] = {
	"PAPI_tot_ins",
	"PAPI_tot_cyc",
	"",
	NULL
};

static char	**ffc_names = NULL;
static char	**ffc_allnames = NULL;
static char	**gpc_names = NULL;
static uint32_t	versionid;
static uint64_t	num_gpc;
static uint64_t	width_gpc;
static uint64_t	mask_gpc;
static uint64_t	num_ffc;
static uint64_t	width_ffc;
static uint64_t	mask_ffc;
static uint_t	total_pmc;
static uint64_t	control_ffc;
static uint64_t	control_gpc;
static uint64_t	control_mask;
static uint32_t	arch_events_vector;

#define	IMPL_NAME_LEN 100
static char core_impl_name[IMPL_NAME_LEN];

static const char *core_cpuref =
	"See https://download.01.org/perfmon/index/ or Chapers 18 and 19 " \
	"of the \"Intel 64 and IA-32 Architectures Software Developer's " \
	"Manual Volume 3: System Programming Guide\" Order Number: " \
	"325384-062US, March 2017.";


/* Architectural events */
#define	ARCH_EVENTS_COMMON					\
	{ 0xc0, 0x00, C_ALL, "inst_retired.any_p" },		\
	{ 0x3c, 0x01, C_ALL, "cpu_clk_unhalted.ref_p" },	\
	{ 0x2e, 0x4f, C_ALL, "longest_lat_cache.reference" },	\
	{ 0x2e, 0x41, C_ALL, "longest_lat_cache.miss" },	\
	{ 0xc4, 0x00, C_ALL, "br_inst_retired.all_branches" },	\
	{ 0xc5, 0x00, C_ALL, "br_misp_retired.all_branches" }

static const struct events_table_t arch_events_table_non_htt[] = {
	{ 0x3c, 0x00, C_ALL, "cpu_clk_unhalted.core" },
	ARCH_EVENTS_COMMON
};

static const struct events_table_t arch_events_table_htt[] = {
	{ 0x3c, 0x00, C_ALL, "cpu_clk_unhalted.thread_p" },
	ARCH_EVENTS_COMMON
};

static char *arch_genevents_table[] = {
	"PAPI_tot_cyc", /* cpu_clk_unhalted.thread_p/core */
	"PAPI_tot_ins", /* inst_retired.any_p		  */
	"",		/* cpu_clk_unhalted.ref_p	  */
	"",		/* longest_lat_cache.reference	  */
	"",		/* longest_lat_cache.miss	  */
	"",		/* br_inst_retired.all_branches	  */
	"",		/* br_misp_retired.all_branches	  */
};

static const struct events_table_t *arch_events_table = NULL;
static uint64_t known_arch_events;
static uint64_t known_ffc_num;
static const struct events_table_t *events_table = NULL;

/*
 * Initialize string containing list of supported general-purpose counter
 * events for processors of Penryn and Merom Family
 */
static void
pcbe_init_core_uarch()
{
	const struct nametable_core_uarch	*n;
	const struct generic_events		*k;
	const struct nametable_core_uarch	*picspecific_events;
	const struct generic_events		*picspecific_genericevents;
	size_t			common_size;
	size_t			size;
	uint64_t		i;

	gpc_names = kmem_alloc(num_gpc * sizeof (char *), KM_SLEEP);

	/* Calculate space needed to save all the common event names */
	common_size = 0;
	for (n = cmn_gpc_events_core_uarch; n->event_num != NT_END; n++) {
		common_size += strlen(n->name) + 1;
	}

	for (k = cmn_generic_events; k->event_num != NT_END; k++) {
		common_size += strlen(k->name) + 1;
	}

	for (i = 0; i < num_gpc; i++) {
		size = 0;
		picspecific_genericevents = NULL;

		switch (i) {
			case 0:
				picspecific_events = pic0_events;
				picspecific_genericevents = generic_events_pic0;
				break;
			case 1:
				picspecific_events = pic1_events;
				break;
			default:
				picspecific_events = NULL;
				break;
		}
		if (picspecific_events != NULL) {
			for (n = picspecific_events;
			    n->event_num != NT_END;
			    n++) {
				size += strlen(n->name) + 1;
			}
		}
		if (picspecific_genericevents != NULL) {
			for (k = picspecific_genericevents;
			    k->event_num != NT_END; k++) {
				size += strlen(k->name) + 1;
			}
		}

		gpc_names[i] =
		    kmem_alloc(size + common_size + 1, KM_SLEEP);

		gpc_names[i][0] = '\0';
		if (picspecific_events != NULL) {
			for (n = picspecific_events;
			    n->event_num != NT_END; n++) {
				(void) strcat(gpc_names[i], n->name);
				(void) strcat(gpc_names[i], ",");
			}
		}
		if (picspecific_genericevents != NULL) {
			for (k = picspecific_genericevents;
			    k->event_num != NT_END; k++) {
				(void) strcat(gpc_names[i], k->name);
				(void) strcat(gpc_names[i], ",");
			}
		}
		for (n = cmn_gpc_events_core_uarch; n->event_num != NT_END;
		    n++) {
			(void) strcat(gpc_names[i], n->name);
			(void) strcat(gpc_names[i], ",");
		}
		for (k = cmn_generic_events; k->event_num != NT_END; k++) {
			(void) strcat(gpc_names[i], k->name);
			(void) strcat(gpc_names[i], ",");
		}

		/*
		 * Remove trailing comma.
		 */
		gpc_names[i][common_size + size - 1] = '\0';
	}
}

static int
core_pcbe_init(void)
{
	struct cpuid_regs	cp;
	size_t			size;
	uint64_t		i;
	uint64_t		j;
	uint64_t		arch_events_vector_length;
	size_t			arch_events_string_length;
	uint_t			model;

	if (cpuid_getvendor(CPU) != X86_VENDOR_Intel)
		return (-1);

	/* Obtain Basic CPUID information */
	cp.cp_eax = 0x0;
	(void) __cpuid_insn(&cp);

	/* No Architectural Performance Monitoring Leaf returned by CPUID */
	if (cp.cp_eax < 0xa) {
		return (-1);
	}

	/* Obtain the Architectural Performance Monitoring Leaf */
	cp.cp_eax = 0xa;
	(void) __cpuid_insn(&cp);

	versionid = cp.cp_eax & 0xFF;

	/*
	 * Fixed-Function Counters (FFC)
	 *
	 * All Family 6 Model 15 and Model 23 processors have fixed-function
	 * counters.  These counters were made Architectural with
	 * Family 6 Model 15 Stepping 9.
	 */
	switch (versionid) {

		case 0:
			return (-1);

		case 2:
			num_ffc = cp.cp_edx & 0x1F;
			width_ffc = (cp.cp_edx >> 5) & 0xFF;

			/*
			 * Some processors have an errata (AW34) where
			 * versionid is reported as 2 when actually 1.
			 * In this case, fixed-function counters are
			 * model-specific as in Version 1.
			 */
			if (num_ffc != 0) {
				break;
			}
			/* FALLTHROUGH */
		case 1:
			num_ffc = 3;
			width_ffc = 40;
			versionid = 1;
			break;

		default:
			num_ffc = cp.cp_edx & 0x1F;
			width_ffc = (cp.cp_edx >> 5) & 0xFF;
			break;
	}


	if (num_ffc >= 64)
		return (-1);

	/* Set HTT-specific names of architectural & FFC events */
	if (is_x86_feature(x86_featureset, X86FSET_HTT)) {
		ffc_names = ffc_names_htt;
		arch_events_table = arch_events_table_htt;
		known_arch_events =
		    sizeof (arch_events_table_htt) /
		    sizeof (struct events_table_t);
		known_ffc_num =
		    sizeof (ffc_names_htt) / sizeof (char *);
	} else {
		ffc_names = ffc_names_non_htt;
		arch_events_table = arch_events_table_non_htt;
		known_arch_events =
		    sizeof (arch_events_table_non_htt) /
		    sizeof (struct events_table_t);
		known_ffc_num =
		    sizeof (ffc_names_non_htt) / sizeof (char *);
	}

	if (num_ffc >= known_ffc_num) {
		/*
		 * The system seems to have more fixed-function counters than
		 * what this PCBE is able to handle correctly.  Default to the
		 * maximum number of fixed-function counters that this driver
		 * is aware of.
		 */
		num_ffc = known_ffc_num - 1;
	}

	mask_ffc = BITMASK_XBITS(width_ffc);
	control_ffc = BITMASK_XBITS(num_ffc);

	/*
	 * General Purpose Counters (GPC)
	 */
	num_gpc = (cp.cp_eax >> 8) & 0xFF;
	width_gpc = (cp.cp_eax >> 16) & 0xFF;

	if (num_gpc >= 64)
		return (-1);

	mask_gpc = BITMASK_XBITS(width_gpc);

	control_gpc = BITMASK_XBITS(num_gpc);

	control_mask = (control_ffc << 32) | control_gpc;

	total_pmc = num_gpc + num_ffc;
	if (total_pmc > 64) {
		/* Too wide for the overflow bitmap */
		return (-1);
	}

	/* FFC names */
	ffc_allnames = kmem_alloc(num_ffc * sizeof (char *), KM_SLEEP);
	for (i = 0; i < num_ffc; i++) {
		ffc_allnames[i] = kmem_alloc(
		    strlen(ffc_names[i]) + strlen(ffc_genericnames[i]) + 2,
		    KM_SLEEP);

		ffc_allnames[i][0] = '\0';
		(void) strcat(ffc_allnames[i], ffc_names[i]);

		/* Check if this ffc has a generic name */
		if (strcmp(ffc_genericnames[i], "") != 0) {
			(void) strcat(ffc_allnames[i], ",");
			(void) strcat(ffc_allnames[i], ffc_genericnames[i]);
		}
	}

	/* GPC events for Family 6 Models 15, 23 and 29 only */
	if ((cpuid_getfamily(CPU) == 6) &&
	    ((cpuid_getmodel(CPU) == 15) || (cpuid_getmodel(CPU) == 23) ||
	    (cpuid_getmodel(CPU) == 29))) {
		(void) snprintf(core_impl_name, IMPL_NAME_LEN,
		    "Core Microarchitecture");
		pcbe_init_core_uarch();
		return (0);
	}

	(void) snprintf(core_impl_name, IMPL_NAME_LEN,
	    "Intel Arch PerfMon v%d on Family %d Model %d",
	    versionid, cpuid_getfamily(CPU), cpuid_getmodel(CPU));

	/*
	 * Architectural events
	 */
	arch_events_vector_length = (cp.cp_eax >> 24) & 0xFF;

	ASSERT(known_arch_events == arch_events_vector_length);

	/*
	 * To handle the case where a new performance monitoring setup is run
	 * on a non-debug kernel
	 */
	if (known_arch_events > arch_events_vector_length) {
		known_arch_events = arch_events_vector_length;
	} else {
		arch_events_vector_length = known_arch_events;
	}

	arch_events_vector = cp.cp_ebx &
	    BITMASK_XBITS(arch_events_vector_length);

	/*
	 * Process architectural and non-architectural events using GPC
	 */
	if (num_gpc > 0) {

		gpc_names = kmem_alloc(num_gpc * sizeof (char *), KM_SLEEP);

		/* Calculate space required for the architectural gpc events */
		arch_events_string_length = 0;
		for (i = 0; i < known_arch_events; i++) {
			if (((1U << i) & arch_events_vector) == 0) {
				arch_events_string_length +=
				    strlen(arch_events_table[i].name) + 1;
				if (strcmp(arch_genevents_table[i], "") != 0) {
					arch_events_string_length +=
					    strlen(arch_genevents_table[i]) + 1;
				}
			}
		}

		/* Non-architectural events list */
		model = cpuid_getmodel(CPU);
		events_table = core_cpcgen_table(model);

		for (i = 0; i < num_gpc; i++) {

			/*
			 * Determine length of all supported event names
			 * (architectural + non-architectural)
			 */
			size = arch_events_string_length;
			for (j = 0; events_table != NULL &&
			    events_table[j].eventselect != NT_END;
			    j++) {
				if (C(i) & events_table[j].supported_counters) {
					size += strlen(events_table[j].name) +
					    1;
				}
			}

			/* Allocate memory for this pics list */
			gpc_names[i] = kmem_alloc(size + 1, KM_SLEEP);
			gpc_names[i][0] = '\0';
			if (size == 0) {
				continue;
			}

			/*
			 * Create the list of all supported events
			 * (architectural + non-architectural)
			 */
			for (j = 0; j < known_arch_events; j++) {
				if (((1U << j) & arch_events_vector) == 0) {
					(void) strcat(gpc_names[i],
					    arch_events_table[j].name);
					(void) strcat(gpc_names[i], ",");
					if (strcmp(
					    arch_genevents_table[j], "")
					    != 0) {
						(void) strcat(gpc_names[i],
						    arch_genevents_table[j]);
						(void) strcat(gpc_names[i],
						    ",");
					}
				}
			}

			for (j = 0; events_table != NULL &&
			    events_table[j].eventselect != NT_END;
			    j++) {
				if (C(i) & events_table[j].supported_counters) {
					(void) strcat(gpc_names[i],
					    events_table[j].name);
					(void) strcat(gpc_names[i], ",");
				}
			}

			/* Remove trailing comma */
			gpc_names[i][size - 1] = '\0';
		}
	}

	return (0);
}

static uint_t core_pcbe_ncounters()
{
	return (total_pmc);
}

static const char *core_pcbe_impl_name(void)
{
	return (core_impl_name);
}

static const char *core_pcbe_cpuref(void)
{
	return (core_cpuref);
}

static char *core_pcbe_list_events(uint_t picnum)
{
	ASSERT(picnum < cpc_ncounters);

	if (picnum < num_gpc) {
		return (gpc_names[picnum]);
	} else {
		return (ffc_allnames[picnum - num_gpc]);
	}
}

static char *core_pcbe_list_attrs(void)
{
	if (versionid >= 3) {
		return ("edge,inv,umask,cmask,anythr");
	} else {
		return ("edge,pc,inv,umask,cmask");
	}
}

static const struct nametable_core_uarch *
find_gpcevent_core_uarch(char *name,
    const struct nametable_core_uarch *nametable)
{
	const struct nametable_core_uarch *n;
	int compare_result = -1;

	for (n = nametable; n->event_num != NT_END; n++) {
		compare_result = strcmp(name, n->name);
		if (compare_result <= 0) {
			break;
		}
	}

	if (compare_result == 0) {
		return (n);
	}

	return (NULL);
}

static const struct generic_events *
find_generic_events(char *name, const struct generic_events *table)
{
	const struct generic_events *n;

	for (n = table; n->event_num != NT_END; n++) {
		if (strcmp(name, n->name) == 0) {
			return (n);
		};
	}

	return (NULL);
}

static const struct events_table_t *
find_gpcevent(char *name)
{
	int i;

	/* Search architectural events */
	for (i = 0; i < known_arch_events; i++) {
		if (strcmp(name, arch_events_table[i].name) == 0 ||
		    strcmp(name, arch_genevents_table[i]) == 0) {
			if (((1U << i) & arch_events_vector) == 0) {
				return (&arch_events_table[i]);
			}
		}
	}

	/* Search non-architectural events */
	if (events_table != NULL) {
		for (i = 0; events_table[i].eventselect != NT_END; i++) {
			if (strcmp(name, events_table[i].name) == 0) {
				return (&events_table[i]);
			}
		}
	}

	return (NULL);
}

static uint64_t
core_pcbe_event_coverage(char *event)
{
	uint64_t bitmap;
	uint64_t bitmask;
	const struct events_table_t *n;
	int i;

	bitmap = 0;

	/* Is it an event that a GPC can track? */
	if (versionid >= 3) {
		n = find_gpcevent(event);
		if (n != NULL) {
			bitmap |= (n->supported_counters &
			    BITMASK_XBITS(num_gpc));
		}
	} else {
		if (find_generic_events(event, cmn_generic_events) != NULL) {
			bitmap |= BITMASK_XBITS(num_gpc);
		} if (find_generic_events(event, generic_events_pic0) != NULL) {
			bitmap |= 1ULL;
		} else if (find_gpcevent_core_uarch(event,
		    cmn_gpc_events_core_uarch) != NULL) {
			bitmap |= BITMASK_XBITS(num_gpc);
		} else if (find_gpcevent_core_uarch(event, pic0_events) !=
		    NULL) {
			bitmap |= 1ULL;
		} else if (find_gpcevent_core_uarch(event, pic1_events) !=
		    NULL) {
			bitmap |= 1ULL << 1;
		}
	}

	/* Check if the event can be counted in the fixed-function counters */
	if (num_ffc > 0) {
		bitmask = 1ULL << num_gpc;
		for (i = 0; i < num_ffc; i++) {
			if (strcmp(event, ffc_names[i]) == 0) {
				bitmap |= bitmask;
			} else if (strcmp(event, ffc_genericnames[i]) == 0) {
				bitmap |= bitmask;
			}
			bitmask = bitmask << 1;
		}
	}

	return (bitmap);
}

static uint64_t
core_pcbe_overflow_bitmap(void)
{
	uint64_t interrupt_status;
	uint64_t intrbits_ffc;
	uint64_t intrbits_gpc;
	extern int kcpc_hw_overflow_intr_installed;
	uint64_t overflow_bitmap;

	RDMSR(PERF_GLOBAL_STATUS, interrupt_status);
	WRMSR(PERF_GLOBAL_OVF_CTRL, interrupt_status);

	interrupt_status = interrupt_status & control_mask;
	intrbits_ffc = (interrupt_status >> 32) & control_ffc;
	intrbits_gpc = interrupt_status & control_gpc;
	overflow_bitmap = (intrbits_ffc << num_gpc) | intrbits_gpc;

	ASSERT(kcpc_hw_overflow_intr_installed);
	(*kcpc_hw_enable_cpc_intr)();

	return (overflow_bitmap);
}

static int
check_cpc_securitypolicy(core_pcbe_config_t *conf,
    const struct nametable_core_uarch *n)
{
	if (conf->core_ctl & n->restricted_bits) {
		if (secpolicy_cpc_cpu(crgetcred()) != 0) {
			return (CPC_ATTR_REQUIRES_PRIVILEGE);
		}
	}
	return (0);
}

static int
configure_gpc(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
    uint_t nattrs, kcpc_attr_t *attrs, void **data)
{
	core_pcbe_config_t	conf;
	const struct nametable_core_uarch	*n;
	const struct generic_events *k = NULL;
	const struct nametable_core_uarch	*m;
	const struct nametable_core_uarch	*picspecific_events;
	struct nametable_core_uarch	nt_raw = { "", 0x0, 0x0 };
	uint_t			i;
	long			event_num;
	const struct events_table_t *eventcode;

	if (((preset & BITS_EXTENDED_FROM_31) != 0) &&
	    ((preset & BITS_EXTENDED_FROM_31) !=
	    BITS_EXTENDED_FROM_31)) {

		/*
		 * Bits beyond bit-31 in the general-purpose counters can only
		 * be written to by extension of bit 31.  We cannot preset
		 * these bits to any value other than all 1s or all 0s.
		 */
		return (CPC_ATTRIBUTE_OUT_OF_RANGE);
	}

	if (versionid >= 3) {
		eventcode = find_gpcevent(event);
		if (eventcode != NULL) {
			if ((C(picnum) & eventcode->supported_counters) == 0) {
				return (CPC_PIC_NOT_CAPABLE);
			}
			if (nattrs > 0 &&
			    (strncmp("PAPI_", event, 5) == 0)) {
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			}
			conf.core_ctl = eventcode->eventselect;
			conf.core_ctl |= eventcode->unitmask <<
			    CORE_UMASK_SHIFT;
		} else {
			/* Event specified as raw event code */
			if (ddi_strtol(event, NULL, 0, &event_num) != 0) {
				return (CPC_INVALID_EVENT);
			}
			conf.core_ctl = event_num & 0xFF;
		}
	} else {
		if ((k = find_generic_events(event, cmn_generic_events)) !=
		    NULL ||
		    (picnum == 0 &&
		    (k = find_generic_events(event, generic_events_pic0)) !=
		    NULL)) {
			if (nattrs > 0) {
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			}
			conf.core_ctl = k->event_num;
			conf.core_ctl |= k->umask << CORE_UMASK_SHIFT;
		} else {
			/* Not a generic event */

			n = find_gpcevent_core_uarch(event,
			    cmn_gpc_events_core_uarch);
			if (n == NULL) {
				switch (picnum) {
					case 0:
						picspecific_events =
						    pic0_events;
						break;
					case 1:
						picspecific_events =
						    pic1_events;
						break;
					default:
						picspecific_events = NULL;
						break;
				}
				if (picspecific_events != NULL) {
					n = find_gpcevent_core_uarch(event,
					    picspecific_events);
				}
			}
			if (n == NULL) {

				/*
				 * Check if this is a case where the event was
				 * specified directly by its event number
				 * instead of its name string.
				 */
				if (ddi_strtol(event, NULL, 0, &event_num) !=
				    0) {
					return (CPC_INVALID_EVENT);
				}

				event_num = event_num & 0xFF;

				/*
				 * Search the event table to find out if the
				 * event specified has an privilege
				 * requirements.  Currently none of the
				 * pic-specific counters have any privilege
				 * requirements.  Hence only the table
				 * cmn_gpc_events_core_uarch is searched.
				 */
				for (m = cmn_gpc_events_core_uarch;
				    m->event_num != NT_END;
				    m++) {
					if (event_num == m->event_num) {
						break;
					}
				}
				if (m->event_num == NT_END) {
					nt_raw.event_num = (uint8_t)event_num;
					n = &nt_raw;
				} else {
					n = m;
				}
			}
			conf.core_ctl = n->event_num; /* Event Select */
		}
	}


	conf.core_picno = picnum;
	conf.core_pictype = CORE_GPC;
	conf.core_rawpic = preset & mask_gpc;

	conf.core_pes = GPC_BASE_PES + picnum;
	conf.core_pmc = GPC_BASE_PMC + picnum;

	for (i = 0; i < nattrs; i++) {
		if (strncmp(attrs[i].ka_name, "umask", 6) == 0) {
			if ((attrs[i].ka_val | CORE_UMASK_MASK) !=
			    CORE_UMASK_MASK) {
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			}
			/* Clear out the default umask */
			conf.core_ctl &= ~ (CORE_UMASK_MASK <<
			    CORE_UMASK_SHIFT);
			/* Use the user provided umask */
			conf.core_ctl |= attrs[i].ka_val <<
			    CORE_UMASK_SHIFT;
		} else  if (strncmp(attrs[i].ka_name, "edge", 6) == 0) {
			if (attrs[i].ka_val != 0)
				conf.core_ctl |= CORE_EDGE;
		} else if (strncmp(attrs[i].ka_name, "inv", 4) == 0) {
			if (attrs[i].ka_val != 0)
				conf.core_ctl |= CORE_INV;
		} else if (strncmp(attrs[i].ka_name, "cmask", 6) == 0) {
			if ((attrs[i].ka_val | CORE_CMASK_MASK) !=
			    CORE_CMASK_MASK) {
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			}
			conf.core_ctl |= attrs[i].ka_val <<
			    CORE_CMASK_SHIFT;
		} else if (strncmp(attrs[i].ka_name, "anythr", 7) ==
		    0) {
			if (versionid < 3)
				return (CPC_INVALID_ATTRIBUTE);
			if (secpolicy_cpc_cpu(crgetcred()) != 0) {
				return (CPC_ATTR_REQUIRES_PRIVILEGE);
			}
			if (attrs[i].ka_val != 0)
				conf.core_ctl |= CORE_ANYTHR;
		} else {
			return (CPC_INVALID_ATTRIBUTE);
		}
	}

	if (flags & CPC_COUNT_USER)
		conf.core_ctl |= CORE_USR;
	if (flags & CPC_COUNT_SYSTEM)
		conf.core_ctl |= CORE_OS;
	if (flags & CPC_OVF_NOTIFY_EMT)
		conf.core_ctl |= CORE_INT;
	conf.core_ctl |= CORE_EN;

	if (versionid < 3 && k == NULL) {
		if (check_cpc_securitypolicy(&conf, n) != 0) {
			return (CPC_ATTR_REQUIRES_PRIVILEGE);
		}
	}

	*data = kmem_alloc(sizeof (core_pcbe_config_t), KM_SLEEP);
	*((core_pcbe_config_t *)*data) = conf;

	return (0);
}

static int
configure_ffc(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
    uint_t nattrs, kcpc_attr_t *attrs, void **data)
{
	core_pcbe_config_t	*conf;
	uint_t			i;

	if (picnum - num_gpc >= num_ffc) {
		return (CPC_INVALID_PICNUM);
	}

	if ((strcmp(ffc_names[picnum-num_gpc], event) != 0) &&
	    (strcmp(ffc_genericnames[picnum-num_gpc], event) != 0)) {
		return (CPC_INVALID_EVENT);
	}

	if ((versionid < 3) && (nattrs != 0)) {
		return (CPC_INVALID_ATTRIBUTE);
	}

	conf = kmem_alloc(sizeof (core_pcbe_config_t), KM_SLEEP);
	conf->core_ctl = 0;

	for (i = 0; i < nattrs; i++) {
		if (strncmp(attrs[i].ka_name, "anythr", 7) == 0) {
			if (secpolicy_cpc_cpu(crgetcred()) != 0) {
				kmem_free(conf, sizeof (core_pcbe_config_t));
				return (CPC_ATTR_REQUIRES_PRIVILEGE);
			}
			if (attrs[i].ka_val != 0) {
				conf->core_ctl |= CORE_FFC_ANYTHR;
			}
		} else {
			kmem_free(conf, sizeof (core_pcbe_config_t));
			return (CPC_INVALID_ATTRIBUTE);
		}
	}

	conf->core_picno = picnum;
	conf->core_pictype = CORE_FFC;
	conf->core_rawpic = preset & mask_ffc;
	conf->core_pmc = FFC_BASE_PMC + (picnum - num_gpc);

	/* All fixed-function counters have the same control register */
	conf->core_pes = PERF_FIXED_CTR_CTRL;

	if (flags & CPC_COUNT_USER)
		conf->core_ctl |= CORE_FFC_USR_EN;
	if (flags & CPC_COUNT_SYSTEM)
		conf->core_ctl |= CORE_FFC_OS_EN;
	if (flags & CPC_OVF_NOTIFY_EMT)
		conf->core_ctl |= CORE_FFC_PMI;

	*data = conf;
	return (0);
}

/*ARGSUSED*/
static int
core_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token)
{
	int			ret;
	core_pcbe_config_t	*conf;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		conf = *data;
		ASSERT(conf->core_pictype == CORE_GPC ||
		    conf->core_pictype == CORE_FFC);
		if (conf->core_pictype == CORE_GPC)
			conf->core_rawpic = preset & mask_gpc;
		else /* CORE_FFC */
			conf->core_rawpic = preset & mask_ffc;
		return (0);
	}

	if (picnum >= total_pmc) {
		return (CPC_INVALID_PICNUM);
	}

	if (picnum < num_gpc) {
		ret = configure_gpc(picnum, event, preset, flags,
		    nattrs, attrs, data);
	} else {
		ret = configure_ffc(picnum, event, preset, flags,
		    nattrs, attrs, data);
	}
	return (ret);
}

static void
core_pcbe_program(void *token)
{
	core_pcbe_config_t	*cfg;
	uint64_t		perf_global_ctrl;
	uint64_t		perf_fixed_ctr_ctrl;
	uint64_t		curcr4;

	core_pcbe_allstop();

	curcr4 = getcr4();
	if (kcpc_allow_nonpriv(token))
		/* Allow RDPMC at any ring level */
		setcr4(curcr4 | CR4_PCE);
	else
		/* Allow RDPMC only at ring 0 */
		setcr4(curcr4 & ~CR4_PCE);

	/* Clear any overflow indicators before programming the counters */
	WRMSR(PERF_GLOBAL_OVF_CTRL, MASK_CONDCHGD_OVFBUFFER | control_mask);

	cfg = NULL;
	perf_global_ctrl = 0;
	perf_fixed_ctr_ctrl = 0;
	cfg = (core_pcbe_config_t *)kcpc_next_config(token, cfg, NULL);
	while (cfg != NULL) {
		ASSERT(cfg->core_pictype == CORE_GPC ||
		    cfg->core_pictype == CORE_FFC);

		if (cfg->core_pictype == CORE_GPC) {
			/*
			 * General-purpose counter registers have write
			 * restrictions where only the lower 32-bits can be
			 * written to.  The rest of the relevant bits are
			 * written to by extension from bit 31 (all ZEROS if
			 * bit-31 is ZERO and all ONE if bit-31 is ONE).  This
			 * makes it possible to write to the counter register
			 * only values that have all ONEs or all ZEROs in the
			 * higher bits.
			 */
			if (((cfg->core_rawpic & BITS_EXTENDED_FROM_31) == 0) ||
			    ((cfg->core_rawpic & BITS_EXTENDED_FROM_31) ==
			    BITS_EXTENDED_FROM_31)) {
				/*
				 * Straighforward case where the higher bits
				 * are all ZEROs or all ONEs.
				 */
				WRMSR(cfg->core_pmc,
				    (cfg->core_rawpic & mask_gpc));
			} else {
				/*
				 * The high order bits are not all the same.
				 * We save what is currently in the registers
				 * and do not write to it.  When we want to do
				 * a read from this register later (in
				 * core_pcbe_sample()), we subtract the value
				 * we save here to get the actual event count.
				 *
				 * NOTE: As a result, we will not get overflow
				 * interrupts as expected.
				 */
				RDMSR(cfg->core_pmc, cfg->core_rawpic);
				cfg->core_rawpic = cfg->core_rawpic & mask_gpc;
			}
			WRMSR(cfg->core_pes, cfg->core_ctl);
			perf_global_ctrl |= 1ull << cfg->core_picno;
		} else {
			/*
			 * Unlike the general-purpose counters, all relevant
			 * bits of fixed-function counters can be written to.
			 */
			WRMSR(cfg->core_pmc, cfg->core_rawpic & mask_ffc);

			/*
			 * Collect the control bits for all the
			 * fixed-function counters and write it at one shot
			 * later in this function
			 */
			perf_fixed_ctr_ctrl |= cfg->core_ctl <<
			    ((cfg->core_picno - num_gpc) * CORE_FFC_ATTR_SIZE);
			perf_global_ctrl |=
			    1ull << (cfg->core_picno - num_gpc + 32);
		}

		cfg = (core_pcbe_config_t *)
		    kcpc_next_config(token, cfg, NULL);
	}

	/* Enable all the counters */
	WRMSR(PERF_FIXED_CTR_CTRL, perf_fixed_ctr_ctrl);
	WRMSR(PERF_GLOBAL_CTRL, perf_global_ctrl);
}

static void
core_pcbe_allstop(void)
{
	/* Disable all the counters together */
	WRMSR(PERF_GLOBAL_CTRL, ALL_STOPPED);

	setcr4(getcr4() & ~CR4_PCE);
}

static void
core_pcbe_sample(void *token)
{
	uint64_t		*daddr;
	uint64_t		curpic;
	core_pcbe_config_t	*cfg;
	uint64_t			counter_mask;

	cfg = (core_pcbe_config_t *)kcpc_next_config(token, NULL, &daddr);
	while (cfg != NULL) {
		ASSERT(cfg->core_pictype == CORE_GPC ||
		    cfg->core_pictype == CORE_FFC);

		curpic = rdmsr(cfg->core_pmc);

		DTRACE_PROBE4(core__pcbe__sample,
		    uint64_t, cfg->core_pmc,
		    uint64_t, curpic,
		    uint64_t, cfg->core_rawpic,
		    uint64_t, *daddr);

		if (cfg->core_pictype == CORE_GPC) {
			counter_mask = mask_gpc;
		} else {
			counter_mask = mask_ffc;
		}
		curpic = curpic & counter_mask;
		if (curpic >= cfg->core_rawpic) {
			*daddr += curpic - cfg->core_rawpic;
		} else {
			/* Counter overflowed since our last sample */
			*daddr += counter_mask - (cfg->core_rawpic - curpic) +
			    1;
		}
		cfg->core_rawpic = *daddr & counter_mask;

		cfg =
		    (core_pcbe_config_t *)kcpc_next_config(token, cfg, &daddr);
	}
}

static void
core_pcbe_free(void *config)
{
	kmem_free(config, sizeof (core_pcbe_config_t));
}

static struct modlpcbe core_modlpcbe = {
	&mod_pcbeops,
	"Core Performance Counters",
	&core_pcbe_ops
};

static struct modlinkage core_modl = {
	MODREV_1,
	&core_modlpcbe,
};

int
_init(void)
{
	if (core_pcbe_init() != 0) {
		return (ENOTSUP);
	}
	return (mod_install(&core_modl));
}

int
_fini(void)
{
	return (mod_remove(&core_modl));
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&core_modl, mi));
}
