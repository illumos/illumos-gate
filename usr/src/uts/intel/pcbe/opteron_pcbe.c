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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Performance Counter Back-End for AMD Opteron and AMD Athlon 64 processors.
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
 * Define offsets and masks for the fields in the Performance
 * Event-Select (PES) registers.
 */
#define	OPT_PES_HOST_SHIFT	41
#define	OPT_PES_GUEST_SHIFT	40
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

opt_pcbe_config_t nullcfgs[4] = {
	{ 0, 0, 0 },
	{ 1, 0, 0 },
	{ 2, 0, 0 },
	{ 3, 0, 0 }
};

typedef struct _amd_event {
	char		*name;
	uint16_t	emask;		/* Event mask setting */
	uint8_t		umask_valid;	/* Mask of unreserved UNIT_MASK bits */
} amd_event_t;

/*
 * Base MSR addresses for the PerfEvtSel registers and the counters themselves.
 * Add counter number to base address to get corresponding MSR address.
 */
#define	PES_BASE_ADDR	0xC0010000
#define	PIC_BASE_ADDR	0xC0010004

#define	MASK48		0xFFFFFFFFFFFF

#define	EV_END {NULL, 0, 0}

#define	AMD_cmn_events							\
	{ "FP_dispatched_fpu_ops",			0x0, 0x3F },	\
	{ "FP_cycles_no_fpu_ops_retired",		0x1, 0x0 },	\
	{ "FP_dispatched_fpu_ops_ff",			0x2, 0x0 },	\
	{ "LS_seg_reg_load",				0x20, 0x7F },	\
	{ "LS_uarch_resync_self_modify",		0x21, 0x0 },	\
	{ "LS_uarch_resync_snoop",			0x22, 0x0 },	\
	{ "LS_buffer_2_full",				0x23, 0x0 },	\
	{ "LS_retired_cflush",				0x26, 0x0 },	\
	{ "LS_retired_cpuid",				0x27, 0x0 },	\
	{ "DC_access",					0x40, 0x0 },	\
	{ "DC_miss",					0x41, 0x0 },	\
	{ "DC_refill_from_L2",				0x42, 0x1F },	\
	{ "DC_refill_from_system",			0x43, 0x1F },	\
	{ "DC_misaligned_data_ref",			0x47, 0x0 },	\
	{ "DC_uarch_late_cancel_access",		0x48, 0x0 },	\
	{ "DC_uarch_early_cancel_access",		0x49, 0x0 },	\
	{ "DC_dispatched_prefetch_instr",		0x4B, 0x7 },	\
	{ "DC_dcache_accesses_by_locks",		0x4C, 0x2 },	\
	{ "BU_memory_requests",				0x65, 0x83},	\
	{ "BU_data_prefetch",				0x67, 0x3 },	\
	{ "BU_cpu_clk_unhalted",			0x76, 0x0 },	\
	{ "IC_fetch",					0x80, 0x0 },	\
	{ "IC_miss",					0x81, 0x0 },	\
	{ "IC_refill_from_L2",				0x82, 0x0 },	\
	{ "IC_refill_from_system",			0x83, 0x0 },	\
	{ "IC_itlb_L1_miss_L2_hit",			0x84, 0x0 },	\
	{ "IC_uarch_resync_snoop",			0x86, 0x0 },	\
	{ "IC_instr_fetch_stall",			0x87, 0x0 },	\
	{ "IC_return_stack_hit",			0x88, 0x0 },	\
	{ "IC_return_stack_overflow",			0x89, 0x0 },	\
	{ "FR_retired_x86_instr_w_excp_intr",		0xC0, 0x0 },	\
	{ "FR_retired_uops",				0xC1, 0x0 },	\
	{ "FR_retired_branches_w_excp_intr",		0xC2, 0x0 },	\
	{ "FR_retired_branches_mispred",		0xC3, 0x0 },	\
	{ "FR_retired_taken_branches",			0xC4, 0x0 },	\
	{ "FR_retired_taken_branches_mispred",		0xC5, 0x0 },	\
	{ "FR_retired_far_ctl_transfer",		0xC6, 0x0 },	\
	{ "FR_retired_resyncs",				0xC7, 0x0 },	\
	{ "FR_retired_near_rets",			0xC8, 0x0 },	\
	{ "FR_retired_near_rets_mispred",		0xC9, 0x0 },	\
	{ "FR_retired_taken_branches_mispred_addr_miscomp",	0xCA, 0x0 },\
	{ "FR_retired_fastpath_double_op_instr",	0xCC, 0x7 },	\
	{ "FR_intr_masked_cycles",			0xCD, 0x0 },	\
	{ "FR_intr_masked_while_pending_cycles",	0xCE, 0x0 },	\
	{ "FR_taken_hardware_intrs",			0xCF, 0x0 },	\
	{ "FR_nothing_to_dispatch",			0xD0, 0x0 },	\
	{ "FR_dispatch_stalls",				0xD1, 0x0 },	\
	{ "FR_dispatch_stall_branch_abort_to_retire",	0xD2, 0x0 },	\
	{ "FR_dispatch_stall_serialization",		0xD3, 0x0 },	\
	{ "FR_dispatch_stall_segment_load",		0xD4, 0x0 },	\
	{ "FR_dispatch_stall_reorder_buffer_full",	0xD5, 0x0 },	\
	{ "FR_dispatch_stall_resv_stations_full",	0xD6, 0x0 },	\
	{ "FR_dispatch_stall_fpu_full",			0xD7, 0x0 },	\
	{ "FR_dispatch_stall_ls_full",			0xD8, 0x0 },	\
	{ "FR_dispatch_stall_waiting_all_quiet",	0xD9, 0x0 },	\
	{ "FR_dispatch_stall_far_ctl_trsfr_resync_branch_pend",	0xDA, 0x0 },\
	{ "FR_fpu_exception",				0xDB, 0xF },	\
	{ "FR_num_brkpts_dr0",				0xDC, 0x0 },	\
	{ "FR_num_brkpts_dr1",				0xDD, 0x0 },	\
	{ "FR_num_brkpts_dr2",				0xDE, 0x0 },	\
	{ "FR_num_brkpts_dr3",				0xDF, 0x0 },	\
	{ "NB_mem_ctrlr_bypass_counter_saturation",	0xE4, 0xF }

#define	OPT_events							\
	{ "LS_locked_operation",			0x24, 0x7 },	\
	{ "DC_copyback",				0x44, 0x1F },	\
	{ "DC_dtlb_L1_miss_L2_hit",			0x45, 0x0 },	\
	{ "DC_dtlb_L1_miss_L2_miss",			0x46, 0x0 },	\
	{ "DC_1bit_ecc_error_found",			0x4A, 0x3 },	\
	{ "BU_system_read_responses",			0x6C, 0x7 },	\
	{ "BU_quadwords_written_to_system",		0x6D, 0x1 },	\
	{ "BU_internal_L2_req",				0x7D, 0x1F },	\
	{ "BU_fill_req_missed_L2",			0x7E, 0x7 },	\
	{ "BU_fill_into_L2",				0x7F, 0x1 },	\
	{ "IC_itlb_L1_miss_L2_miss",			0x85, 0x0 },	\
	{ "FR_retired_fpu_instr",			0xCB, 0xF },	\
	{ "NB_mem_ctrlr_page_access",			0xE0, 0x7 },	\
	{ "NB_mem_ctrlr_page_table_overflow",		0xE1, 0x0 },	\
	{ "NB_mem_ctrlr_turnaround",			0xE3, 0x7 },	\
	{ "NB_ECC_errors",				0xE8, 0x80},	\
	{ "NB_sized_commands",				0xEB, 0x7F },	\
	{ "NB_probe_result",				0xEC, 0x7F},	\
	{ "NB_gart_events",				0xEE, 0x7 },	\
	{ "NB_ht_bus0_bandwidth",			0xF6, 0xF },	\
	{ "NB_ht_bus1_bandwidth",			0xF7, 0xF },	\
	{ "NB_ht_bus2_bandwidth",			0xF8, 0xF }

#define	OPT_RevD_events							\
	{ "NB_sized_blocks",				0xE5, 0x3C }

#define	OPT_RevE_events							\
	{ "NB_cpu_io_to_mem_io",			0xE9, 0xFF},	\
	{ "NB_cache_block_commands",			0xEA, 0x3D}

#define	AMD_FAMILY_10h_cmn_events					\
	{ "FP_retired_sse_ops",				0x3,   0x7F},	\
	{ "FP_retired_move_ops",			0x4,   0xF},	\
	{ "FP_retired_serialize_ops",			0x5,   0xF},	\
	{ "FP_serialize_ops_cycles",			0x6,   0x3},	\
	{ "DC_copyback",				0x44,  0x7F },	\
	{ "DC_dtlb_L1_miss_L2_hit",			0x45,  0x3 },	\
	{ "DC_dtlb_L1_miss_L2_miss",			0x46,  0x7 },	\
	{ "DC_1bit_ecc_error_found",			0x4A,  0xF },	\
	{ "DC_dtlb_L1_hit",				0x4D,  0x7 },	\
	{ "BU_system_read_responses",			0x6C,  0x17 },	\
	{ "BU_octwords_written_to_system",		0x6D,  0x1 },	\
	{ "BU_internal_L2_req",				0x7D,  0x3F },	\
	{ "BU_fill_req_missed_L2",			0x7E,  0xF },	\
	{ "BU_fill_into_L2",				0x7F,  0x3 },	\
	{ "IC_itlb_L1_miss_L2_miss",			0x85,  0x3 },	\
	{ "IC_eviction",				0x8B,  0x0 },	\
	{ "IC_cache_lines_invalidate",			0x8C,  0xF },	\
	{ "IC_itlb_reload",				0x99,  0x0 },	\
	{ "IC_itlb_reload_aborted",			0x9A,  0x0 },	\
	{ "FR_retired_mmx_sse_fp_instr",		0xCB,  0x7 },	\
	{ "NB_mem_ctrlr_page_access",			0xE0,  0xFF },	\
	{ "NB_mem_ctrlr_page_table_overflow",		0xE1,  0x3 },	\
	{ "NB_mem_ctrlr_turnaround",			0xE3,  0x3F },	\
	{ "NB_thermal_status",				0xE8,  0x7C},	\
	{ "NB_sized_commands",				0xEB,  0x3F },	\
	{ "NB_probe_results_upstream_req",		0xEC,  0xFF},	\
	{ "NB_gart_events",				0xEE,  0xFF },	\
	{ "NB_ht_bus0_bandwidth",			0xF6,  0xBF },	\
	{ "NB_ht_bus1_bandwidth",			0xF7,  0xBF },	\
	{ "NB_ht_bus2_bandwidth",			0xF8,  0xBF },	\
	{ "NB_ht_bus3_bandwidth",			0x1F9, 0xBF },	\
	{ "LS_locked_operation",			0x24,  0xF },	\
	{ "LS_cancelled_store_to_load_fwd_ops",		0x2A,  0x7 },	\
	{ "LS_smi_received",				0x2B,  0x0 },	\
	{ "LS_ineffective_prefetch",			0x52,  0x9 },	\
	{ "LS_global_tlb_flush",			0x54,  0x0 },	\
	{ "NB_mem_ctrlr_dram_cmd_slots_missed",		0xE2,  0x3 },	\
	{ "NB_mem_ctrlr_req",				0x1F0, 0xFF },	\
	{ "CB_cpu_to_dram_req_to_target",		0x1E0, 0xFF },	\
	{ "CB_io_to_dram_req_to_target",		0x1E1, 0xFF },	\
	{ "CB_cpu_read_cmd_latency_to_target_0_to_3",	0x1E2, 0xFF },	\
	{ "CB_cpu_read_cmd_req_to_target_0_to_3",	0x1E3, 0xFF },	\
	{ "CB_cpu_read_cmd_latency_to_target_4_to_7",	0x1E4, 0xFF },	\
	{ "CB_cpu_read_cmd_req_to_target_4_to_7",	0x1E5, 0xFF },	\
	{ "CB_cpu_cmd_latency_to_target_0_to_7",	0x1E6, 0xFF },	\
	{ "CB_cpu_req_to_target_0_to_7",		0x1E7, 0xFF },	\
	{ "L3_read_req",				0x4E0, 0xF7 },	\
	{ "L3_miss",					0x4E1, 0xF7 },	\
	{ "L3_l2_eviction_l3_fill",			0x4E2, 0xFF },	\
	{ "L3_eviction",				0x4E3, 0xF  }

static amd_event_t opt_events[] = {
	AMD_cmn_events,
	OPT_events,
	EV_END
};

static amd_event_t opt_events_rev_D[] = {
	AMD_cmn_events,
	OPT_events,
	OPT_RevD_events,
	EV_END
};

static amd_event_t opt_events_rev_E[] = {
	AMD_cmn_events,
	OPT_events,
	OPT_RevD_events,
	OPT_RevE_events,
	EV_END
};

static amd_event_t family_10h_events[] = {
	AMD_cmn_events,
	OPT_RevE_events,
	AMD_FAMILY_10h_cmn_events,
	EV_END
};

static char	*evlist;
static size_t	evlist_sz;
static amd_event_t *amd_events = NULL;
static uint_t amd_family;

#define	BITS(v, u, l)   \
	(((v) >> (l)) & ((1 << (1 + (u) - (l))) - 1))

#define	OPTERON_FAMILY	0xf
#define	AMD_FAMILY_10H	0x10

static int
opt_pcbe_init(void)
{
	amd_event_t		*evp;
	uint32_t		rev;

	amd_family = cpuid_getfamily(CPU);

	/*
	 * Make sure this really _is_ an Opteron or Athlon 64 system. The kernel
	 * loads this module based on its name in the module directory, but it
	 * could have been renamed.
	 */
	if (cpuid_getvendor(CPU) != X86_VENDOR_AMD ||
	    (amd_family != OPTERON_FAMILY && amd_family != AMD_FAMILY_10H))
		return (-1);

	/*
	 * Figure out processor revision here and assign appropriate
	 * event configuration.
	 */

	rev = cpuid_getchiprev(CPU);

	if (amd_family == OPTERON_FAMILY) {
		if (!X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_D)) {
			amd_events = opt_events;
		} else if X86_CHIPREV_MATCH(rev, X86_CHIPREV_AMD_F_REV_D) {
			amd_events = opt_events_rev_D;
		} else if (X86_CHIPREV_MATCH(rev, X86_CHIPREV_AMD_F_REV_E) ||
		    X86_CHIPREV_MATCH(rev, X86_CHIPREV_AMD_F_REV_F) ||
		    X86_CHIPREV_MATCH(rev, X86_CHIPREV_AMD_F_REV_G)) {
			amd_events = opt_events_rev_E;
		} else {
			amd_events = opt_events;
		}
	} else {
		amd_events = family_10h_events;
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

	evlist = kmem_alloc(evlist_sz + 1, KM_SLEEP);
	evlist[0] = '\0';

	for (evp = amd_events; evp->name != NULL; evp++) {
		(void) strcat(evlist, evp->name);
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
	return (4);
}

static const char *
opt_pcbe_impl_name(void)
{
	if (amd_family == OPTERON_FAMILY) {
		return ("AMD Opteron & Athlon64");
	} else if (amd_family == AMD_FAMILY_10H) {
		return ("AMD Family 10h");
	} else {
		return ("Unknown AMD processor");
	}
}

static const char *
opt_pcbe_cpuref(void)
{
	if (amd_family == OPTERON_FAMILY) {
		return ("See Chapter 10 of the \"BIOS and Kernel Developer's"
		" Guide for the AMD Athlon 64 and AMD Opteron Processors,\" "
		"AMD publication #26094");
	} else if (amd_family == AMD_FAMILY_10H) {
		return ("See section 3.15 of the \"BIOS and Kernel "
		"Developer's Guide (BKDG) For AMD Family 10h Processors,\" "
		"AMD publication #31116");
	} else {
		return ("Unknown AMD processor");
	}
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

/*ARGSUSED*/
static uint64_t
opt_pcbe_event_coverage(char *event)
{
	/*
	 * Fortunately, all counters can count all events.
	 */
	return (0xF);
}

static uint64_t
opt_pcbe_overflow_bitmap(void)
{
	/*
	 * Unfortunately, this chip cannot detect which counter overflowed, so
	 * we must act as if they all did.
	 */
	return (0xF);
}

static amd_event_t *
find_event(char *name)
{
	amd_event_t	*evp;

	for (evp = amd_events; evp->name != NULL; evp++)
		if (strcmp(name, evp->name) == 0)
			return (evp);

	return (NULL);
}

/*ARGSUSED*/
static int
opt_pcbe_configure(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
    uint_t nattrs, kcpc_attr_t *attrs, void **data, void *token)
{
	opt_pcbe_config_t	*cfg;
	amd_event_t		*evp;
	amd_event_t		ev_raw = { "raw", 0, 0xFF };
	int			i;
	uint64_t		evsel = 0, evsel_tmp = 0;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		cfg = *data;
		cfg->opt_rawpic = preset & MASK48;
		return (0);
	}

	if (picnum >= 4)
		return (CPC_INVALID_PICNUM);

	if ((evp = find_event(event)) == NULL) {
		long tmp;

		/*
		 * If ddi_strtol() likes this event, use it as a raw event code.
		 */
		if (ddi_strtol(event, NULL, 0, &tmp) != 0)
			return (CPC_INVALID_EVENT);

		ev_raw.emask = tmp;
		evp = &ev_raw;
	}

	/*
	 * Configuration of EventSelect register for family 10h processors.
	 */
	if (amd_family == AMD_FAMILY_10H) {

		/* Set GuestOnly bit to 0 and HostOnly bit to 1 */
		evsel &= ~OPT_PES_HOST;
		evsel &= ~OPT_PES_GUEST;

		/* Set bits [35:32] for extended part of Event Select field */
		evsel_tmp = evp->emask & 0x0f00;
		evsel |= evsel_tmp << 24;
	}

	evsel |= evp->emask & 0x00ff;

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
			if ((attrs[i].ka_val | evp->umask_valid) !=
			    evp->umask_valid)
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
	opt_pcbe_config_t	*cfgs[4] = { &nullcfgs[0], &nullcfgs[1],
						&nullcfgs[2], &nullcfgs[3] };
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
			ASSERT(pcfg->opt_picno < 4);
			cfgs[pcfg->opt_picno] = pcfg;
		}
	} while (pcfg != NULL);

	/*
	 * Program in two loops. The first configures and presets the counter,
	 * and the second loop enables the counters. This ensures that the
	 * counters are all enabled as closely together in time as possible.
	 */

	for (i = 0; i < 4; i++) {
		wrmsr(PES_BASE_ADDR + i, cfgs[i]->opt_evsel);
		wrmsr(PIC_BASE_ADDR + i, cfgs[i]->opt_rawpic);
	}

	for (i = 0; i < 4; i++) {
		wrmsr(PES_BASE_ADDR + i, cfgs[i]->opt_evsel |
		    (uint64_t)(uintptr_t)OPT_PES_ENABLE);
	}
}

static void
opt_pcbe_allstop(void)
{
	int		i;

	for (i = 0; i < 4; i++)
		wrmsr(PES_BASE_ADDR + i, 0ULL);

	/*
	 * Disable non-privileged access to the counter registers.
	 */
	setcr4(getcr4() & ~CR4_PCE);
}

static void
opt_pcbe_sample(void *token)
{
	opt_pcbe_config_t	*cfgs[4] = { NULL, NULL, NULL, NULL };
	opt_pcbe_config_t	*pcfg = NULL;
	int			i;
	uint64_t		curpic[4];
	uint64_t		*addrs[4];
	uint64_t		*tmp;
	int64_t			diff;

	for (i = 0; i < 4; i++)
		curpic[i] = rdmsr(PIC_BASE_ADDR + i);

	/*
	 * Query kernel for all configs which are co-programmed.
	 */
	do {
		pcfg = (opt_pcbe_config_t *)kcpc_next_config(token, pcfg, &tmp);

		if (pcfg != NULL) {
			ASSERT(pcfg->opt_picno < 4);
			cfgs[pcfg->opt_picno] = pcfg;
			addrs[pcfg->opt_picno] = tmp;
		}
	} while (pcfg != NULL);

	for (i = 0; i < 4; i++) {
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
	"AMD Performance Counters v%I%",
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
