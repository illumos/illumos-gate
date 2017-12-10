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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
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
 * Performance Counter Back-End for Pentium 4.
 */

#include <sys/cpuvar.h>
#include <sys/param.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/inttypes.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/x86_archext.h>
#include <sys/modctl.h>
#include <sys/sdt.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/privregs.h>

static int p4_pcbe_init(void);
static uint_t p4_pcbe_ncounters(void);
static const char *p4_pcbe_impl_name(void);
static const char *p4_pcbe_cpuref(void);
static char *p4_pcbe_list_events(uint_t picnum);
static char *p4_pcbe_list_attrs(void);
static uint64_t p4_pcbe_event_coverage(char *event);
static uint64_t p4_pcbe_overflow_bitmap(void);
static int p4_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void p4_pcbe_program(void *token);
static void p4_pcbe_allstop(void);
static void p4_pcbe_sample(void *token);
static void p4_pcbe_free(void *config);

extern int cpuid_get_clogid(cpu_t *);

static pcbe_ops_t p4_pcbe_ops = {
	PCBE_VER_1,
	CPC_CAP_OVERFLOW_INTERRUPT | CPC_CAP_OVERFLOW_PRECISE,
	p4_pcbe_ncounters,
	p4_pcbe_impl_name,
	p4_pcbe_cpuref,
	p4_pcbe_list_events,
	p4_pcbe_list_attrs,
	p4_pcbe_event_coverage,
	p4_pcbe_overflow_bitmap,
	p4_pcbe_configure,
	p4_pcbe_program,
	p4_pcbe_allstop,
	p4_pcbe_sample,
	p4_pcbe_free
};

/*
 * P4 Configuration Flags.
 */
#define	P4_THIS_USR	0x1 /* HTT: Measure usr events on this logical CPU */
#define	P4_THIS_SYS	0x2 /* HTT: Measure os events on this logical CPU */
#define	P4_SIBLING_USR	0x4 /* HTT: Measure os events on other logical CPU */
#define	P4_SIBLING_SYS	0x8 /* HTT: Measure usr events on other logical CPU */
#define	P4_PMI		0x10 /* HTT: Set PMI bit for local logical CPU */

typedef struct _p4_pcbe_config {
	uint8_t		p4_flags;
	uint8_t		p4_picno;	/* From 0 to 18 */
	uint8_t		p4_escr_ndx;	/* Which ESCR to use */
	uint32_t	p4_escr;	/* Value to program in selected ESCR */
	uint32_t	p4_cccr;	/* Value to program in counter's CCCR */
	uint64_t	p4_rawpic;
} p4_pcbe_config_t;

typedef uint32_t cntr_map_t;

typedef struct _p4_escr {
	int		pe_num;
	uint32_t	pe_addr;
	uint32_t	pe_map; /* bitmap of counters; bit 1 means ctr 0 */
} p4_escr_t;

#define	MASK40			UINT64_C(0xffffffffff)

/*
 * CCCR field definitions.
 *
 * Note that the Intel Developer's Manual states that the reserved field at
 * bit location 16 and 17 must be set to 11. (??)
 */
#define	CCCR_ENABLE_SHIFT	12
#define	CCCR_ESCR_SEL_SHIFT	13
#define	CCCR_ACTV_THR_SHIFT	16
#define	CCCR_COMPARE_SHIFT	18
#define	CCCR_COMPLEMENT_SHIFT	19
#define	CCCR_THRESHOLD_SHIFT	20
#define	CCCR_EDGE_SHIFT		24
#define	CCCR_OVF_PMI_SHIFT	26
#define	CCCR_OVF_PMI_T0_SHIFT	26
#define	CCCR_OVF_PMI_T1_SHIFT	27
#define	CCCR_OVF_SHIFT		31
#define	CCCR_ACTV_THR_MASK	0x3
#define	CCCR_THRESHOLD_MAX	0xF
#define	CCCR_ENABLE		(1U << CCCR_ENABLE_SHIFT)
#define	CCCR_COMPARE		(1U << CCCR_COMPARE_SHIFT)
#define	CCCR_COMPLEMENT		(1U << CCCR_COMPLEMENT_SHIFT)
#define	CCCR_EDGE		(1U << CCCR_EDGE_SHIFT)
#define	CCCR_OVF_PMI		(1U << CCCR_OVF_PMI_SHIFT)
#define	CCCR_OVF_PMI_T0		(1U << CCCR_OVF_PMI_T0_SHIFT)
#define	CCCR_OVF_PMI_T1		(1U << CCCR_OVF_PMI_T1_SHIFT)
#define	CCCR_INIT		CCCR_ENABLE
#define	CCCR_OVF		(1U << CCCR_OVF_SHIFT)

#define	ESCR_EVSEL_SHIFT	25
#define	ESCR_EVMASK_SHIFT	9
#define	ESCR_TAG_VALUE_SHIFT	5
#define	ESCR_TAG_VALUE_MAX	0xF
#define	ESCR_TAG_ENABLE_SHIFT	4
#define	ESCR_USR_SHIFT		2
#define	ESCR_OS_SHIFT		3
#define	ESCR_USR		(1U << ESCR_USR_SHIFT)
#define	ESCR_OS			(1U << ESCR_OS_SHIFT)
#define	ESCR_TAG_ENABLE		(1U << ESCR_TAG_ENABLE_SHIFT)

/*
 * HyperThreaded ESCR fields.
 */
#define	ESCR_T0_OS_SHIFT	3
#define	ESCR_T0_USR_SHIFT	2
#define	ESCR_T1_OS_SHIFT	1
#define	ESCR_T1_USR_SHIFT	0
#define	ESCR_T0_OS		(1U << ESCR_T0_OS_SHIFT)
#define	ESCR_T0_USR		(1U << ESCR_T0_USR_SHIFT)
#define	ESCR_T1_OS		(1U << ESCR_T1_OS_SHIFT)
#define	ESCR_T1_USR		(1U << ESCR_T1_USR_SHIFT)

/*
 * ESCRs are grouped by counter; each group of ESCRs is associated with a
 * distinct group of counters. Use these macros to fill in the table below.
 */
#define	BPU0_map	(0x1 | 0x2)		/* Counters 0 and 1 */
#define	BPU2_map	(0x4 | 0x8)		/* Counters 2 and 3 */
#define	MS0_map		(0x10 | 0x20)		/* Counters 4 and 5 */
#define	MS2_map		(0x40 | 0x80)		/* Counters 6 and 7 */
#define	FLAME0_map	(0x100 | 0x200)		/* Counters 8 and 9 */
#define	FLAME2_map	(0x400 | 0x800)		/* Counters 10 and 11 */
#define	IQ0_map		(0x1000 | 0x2000 | 0x10000) /* Counters 12, 13, 16 */
#define	IQ2_map		(0x4000 | 0x8000 | 0x20000) /* Counters 14, 15, 17 */

/*
 * Table describing the 45 Event Selection and Control Registers (ESCRs).
 */
const p4_escr_t p4_escrs[] = {
#define	BPU0 (1)
	{ 0, 0x3B2, BPU0_map },		/* 0 */
#define	IS0 (1ULL << 1)
	{ 1, 0x3B4, BPU0_map },		/* 1 */
#define	MOB0 (1ULL << 2)
	{ 2, 0x3AA, BPU0_map },		/* 2 */
#define	ITLB0 (1ULL << 3)
	{ 3, 0x3B6, BPU0_map },		/* 3 */
#define	PMH0 (1ULL << 4)
	{ 4, 0x3AC, BPU0_map },		/* 4 */
#define	IX0 (1ULL << 5)
	{ 5, 0x3C8, BPU0_map },		/* 5 */
#define	FSB0 (1ULL << 6)
	{ 6, 0x3A2, BPU0_map },		/* 6 */
#define	BSU0 (1ULL << 7)
	{ 7, 0x3A0, BPU0_map },		/* 7 */
#define	BPU1 (1ULL << 8)
	{ 0, 0x3B3, BPU2_map },		/* 8 */
#define	IS1 (1ULL << 9)
	{ 1, 0x3B5, BPU2_map },		/* 9 */
#define	MOB1 (1ULL << 10)
	{ 2, 0x3AB, BPU2_map },		/* 10 */
#define	ITLB1 (1ULL << 11)
	{ 3, 0x3B7, BPU2_map },		/* 11 */
#define	PMH1 (1ULL << 12)
	{ 4, 0x3AD, BPU2_map },		/* 12 */
#define	IX1 (1ULL << 13)
	{ 5, 0x3C9, BPU2_map },		/* 13 */
#define	FSB1 (1ULL << 14)
	{ 6, 0x3A3, BPU2_map },		/* 14 */
#define	BSU1 (1ULL << 15)
	{ 7, 0x3A1, BPU2_map },		/* 15 */
#define	MS0 (1ULL << 16)
	{ 0, 0x3C0, MS0_map },		/* 16 */
#define	TC0 (1ULL << 17)
	{ 1, 0x3C4, MS0_map },		/* 17 */
#define	TBPU0 (1ULL << 18)
	{ 2, 0x3C2, MS0_map },		/* 18 */
#define	MS1 (1ULL << 19)
	{ 0, 0x3C1, MS2_map },		/* 19 */
#define	TC1 (1ULL << 20)
	{ 1, 0x3C5, MS2_map },		/* 20 */
#define	TBPU1 (1ULL << 21)
	{ 2, 0x3C3, MS2_map },		/* 21 */
#define	FLAME0 (1ULL << 22)
	{ 0, 0x3A6, FLAME0_map },	/* 22 */
#define	FIRM0 (1ULL << 23)
	{ 1, 0x3A4, FLAME0_map },	/* 23 */
#define	SAAT0 (1ULL << 24)
	{ 2, 0x3AE, FLAME0_map },	/* 24 */
#define	U2L0 (1ULL << 25)
	{ 3, 0x3B0, FLAME0_map },	/* 25 */
#define	DAC0 (1ULL << 26)
	{ 5, 0x3A8, FLAME0_map },	/* 26 */
#define	FLAME1 (1ULL << 27)
	{ 0, 0x3A7, FLAME2_map },	/* 27 */
#define	FIRM1 (1ULL << 28)
	{ 1, 0x3A5, FLAME2_map },	/* 28 */
#define	SAAT1 (1ULL << 29)
	{ 2, 0x3AF, FLAME2_map },	/* 29 */
#define	U2L1 (1ULL << 30)
	{ 3, 0x3B1, FLAME2_map },	/* 30 */
#define	DAC1 (1ULL << 31)
	{ 5, 0x3A9, FLAME2_map },	/* 31 */
#define	IQ0 (1ULL << 32)
	{ 0, 0x3BA, IQ0_map },		/* 32 */
#define	ALF0 (1ULL << 33)
	{ 1, 0x3CA, IQ0_map },		/* 33 */
#define	RAT0 (1ULL << 34)
	{ 2, 0x3BC, IQ0_map },		/* 34 */
#define	SSU0 (1ULL << 35)
	{ 3, 0x3BE, IQ0_map },		/* 35 */
#define	CRU0 (1ULL << 36)
	{ 4, 0x3B8, IQ0_map },		/* 36 */
#define	CRU2 (1ULL << 37)
	{ 5, 0x3CC, IQ0_map },		/* 37 */
#define	CRU4 (1ULL << 38)
	{ 6, 0x3E0, IQ0_map },		/* 38 */
#define	IQ1 (1ULL << 39)
	{ 0, 0x3BB, IQ2_map },		/* 39 */
#define	ALF1 (1ULL << 40)
	{ 1, 0x3CB, IQ2_map },		/* 40 */
#define	RAT1 (1ULL << 41)
	{ 2, 0x3BD, IQ2_map },		/* 41 */
#define	CRU1 (1ULL << 42)
	{ 4, 0x3B9, IQ2_map },		/* 42 */
#define	CRU3 (1ULL << 43)
	{ 5, 0x3CD, IQ2_map },		/* 43 */
#define	CRU5 (1ULL << 44)
	{ 6, 0x3E1, IQ2_map }		/* 44 */
};

#define	ESCR_MAX_INDEX 44

typedef struct _p4_ctr {
	uint32_t	pc_caddr;	/* counter MSR address */
	uint32_t	pc_ctladdr;	/* counter's CCCR MSR address */
	uint64_t	pc_map;		/* bitmap of ESCRs controlling ctr */
} p4_ctr_t;

const p4_ctr_t p4_ctrs[18] = {
{ /* BPU_COUNTER0 */ 0x300, 0x360, BSU0|FSB0|MOB0|PMH0|BPU0|IS0|ITLB0|IX0},
{ /* BPU_COUNTER1 */ 0x301, 0x361, BSU0|FSB0|MOB0|PMH0|BPU0|IS0|ITLB0|IX0},
{ /* BPU_COUNTER2 */ 0x302, 0x362, BSU1|FSB1|MOB1|PMH1|BPU1|IS1|ITLB1|IX1},
{ /* BPU_COUNTER3 */ 0x303, 0x363, BSU1|FSB1|MOB1|PMH1|BPU1|IS1|ITLB1|IX1},
{ /* MS_COUNTER0 */  0x304, 0x364, MS0|TBPU0|TC0 },
{ /* MS_COUNTER1 */  0x305, 0x365, MS0|TBPU0|TC0 },
{ /* MS_COUNTER2 */  0x306, 0x366, MS1|TBPU1|TC1 },
{ /* MS_COUNTER3 */  0x307, 0x367, MS1|TBPU1|TC1 },
{ /* FLAME_COUNTER0 */ 0x308, 0x368, FIRM0|FLAME0|DAC0|SAAT0|U2L0 },
{ /* FLAME_COUNTER1 */ 0x309, 0x369, FIRM0|FLAME0|DAC0|SAAT0|U2L0 },
{ /* FLAME_COUNTER2 */ 0x30A, 0x36A, FIRM1|FLAME1|DAC1|SAAT1|U2L1 },
{ /* FLAME_COUNTER3 */ 0x30B, 0x36B, FIRM1|FLAME1|DAC1|SAAT1|U2L1 },
{ /* IQ_COUNTER0 */  0x30C, 0x36C, CRU0|CRU2|CRU4|IQ0|RAT0|SSU0|ALF0 },
{ /* IQ_COUNTER1 */  0x30D, 0x36D, CRU0|CRU2|CRU4|IQ0|RAT0|SSU0|ALF0 },
{ /* IQ_COUNTER2 */  0x30E, 0x36E, CRU1|CRU3|CRU5|IQ1|RAT1|ALF1 },
{ /* IQ_COUNTER3 */  0x30F, 0x36F, CRU1|CRU3|CRU5|IQ1|RAT1|ALF1 },
{ /* IQ_COUNTER4 */  0x310, 0x370, CRU0|CRU2|CRU4|IQ0|RAT0|SSU0|ALF0 },
{ /* IQ_COUNTER5 */  0x311, 0x371, CRU1|CRU3|CRU5|IQ1|RAT1|ALF1 }
};

typedef struct _p4_event {
	char		*pe_name;	/* Name of event according to docs */
	uint64_t	pe_escr_map;	/* Bitmap of ESCRs capable of event */
	uint32_t	pe_escr_mask;	/* permissible ESCR event mask */
	uint8_t		pe_ev;		/* ESCR event select value */
	uint16_t	pe_cccr;	/* CCCR select value */
	uint32_t	pe_ctr_mask;	/* Bitmap of capable counters */
} p4_event_t;

typedef struct _p4_generic_event {
	char		*name;
	char		*event;
	uint16_t	emask;
	uint32_t	ctr_mask;
} p4_generic_event_t;

#define	C(n) (1 << n)
#define	GEN_EVT_END { NULL, NULL, 0x0, 0x0 }

p4_event_t p4_events[] = {
{ "branch_retired", CRU2|CRU3, 0xF, 0x6, 0x5, C(12)|C(13)|C(14)|C(15)|C(16) },
{ "mispred_branch_retired", CRU0|CRU1, 0x1, 0x3, 0x4,
	C(12)|C(13)|C(14)|C(15)|C(16) },
{ "TC_deliver_mode", TC0|TC1, 0xFF, 0x1, 0x1, C(4)|C(5)|C(6)|C(7) },
{ "BPU_fetch_request", BPU0|BPU1, 0x1, 0x3, 0x0, C(0)|C(1)|C(2)|C(3) },
{ "ITLB_reference", ITLB0|ITLB1, 0x7, 0x18, 0x3, C(0)|C(1)|C(2)|C(3) },
{ "memory_cancel", DAC0|DAC1, 0x6, 0x2, 0x5, C(8)|C(9)|C(10)|C(11) },
{ "memory_complete", SAAT0|SAAT1, 0x3, 0x8, 0x2, C(8)|C(9)|C(10)|C(11) },
{ "load_port_replay", SAAT0|SAAT1, 0x1, 0x4, 0x2, C(8)|C(9)|C(10)|C(11) },
{ "store_port_replay", SAAT0|SAAT1, 0x1, 0x5, 0x2, C(8)|C(9)|C(10)|C(11) },
{ "MOB_load_replay", MOB0|MOB1, 0x35, 0x3, 0x2, C(0)|C(1)|C(2)|C(3) },
{ "page_walk_type", PMH0|PMH1, 0x3, 0x1, 0x4, C(0)|C(1)|C(2)|C(3) },
{ "BSQ_cache_reference", BSU0|BSU1, 0x73F, 0xC, 0x7, C(0)|C(1)|C(2)|C(3) },
{ "IOQ_allocation", FSB0, 0xEFFF, 0x3, 0x6, C(0)|C(1) },
{ "IOQ_active_entries", FSB1, 0xEFFF, 0x1A, 0x6, C(2)|C(3) },
{ "FSB_data_activity", FSB0|FSB1, 0x3F, 0x17, 0x6, C(0)|C(1)|C(2)|C(3) },
{ "BSQ_allocation", BSU0, 0x3FEF, 0x5, 0x7, C(0)|C(1) },
{ "bsq_active_entries", BSU1, 0x3FEF, 0x6, 0x7, C(2)|C(3) },
{ "x87_assist", CRU2|CRU3, 0x1F, 0x3, 0x5, C(12)|C(13)|C(14)|C(15)|C(16)|C(17)},
{ "SSE_input_assist", FIRM0|FIRM1, 0x8000, 0x34, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "packed_SP_uop", FIRM0|FIRM1, 0x8000, 0x8, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "packed_DP_uop", FIRM0|FIRM1, 0x8000, 0xC, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "scalar_SP_uop", FIRM0|FIRM1, 0x8000, 0xA, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "scalar_DP_uop", FIRM0|FIRM1, 0x8000, 0xE, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "64bit_MMX_uop", FIRM0|FIRM1, 0x8000, 0x2, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "128bit_MMX_uop", FIRM0|FIRM1, 0x8000, 0x1A, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "x87_FP_uop", FIRM0|FIRM1, 0x8000, 0x4, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "x87_SIMD_moves_uop", FIRM0|FIRM1, 0x18, 0x2E, 0x1, C(8)|C(9)|C(10)|C(11) },
{ "machine_clear", CRU2|CRU3, 0xD, 0x2, 0x5,
	C(12)|C(13)|C(14)|C(15)|C(16)|C(17)},
{ "global_power_events", FSB0|FSB1, 0x1, 0x13, 0x6, C(0)|C(1)|C(2)|C(3) },
{ "tc_ms_xfer", MS0|MS1, 0x1, 0x5, 0x0, C(4)|C(5)|C(6)|C(7) },
{ "uop_queue_writes", MS0|MS1, 0x7, 0x9, 0x0, C(4)|C(5)|C(6)|C(7) },
{ "front_end_event", CRU2|CRU3, 0x3, 0x8, 0x5,
	C(12)|C(13)|C(14)|C(15)|C(16)|C(17)},
{ "execution_event", CRU2|CRU3, 0xFF, 0xC, 0x5,
	C(12)|C(13)|C(14)|C(15)|C(16)|C(17)},
{ "replay_event", CRU2|CRU3, 0x3, 0x9, 0x5,
	C(12)|C(13)|C(14)|C(15)|C(16)|C(17)},
{ "instr_retired", CRU0|CRU1, 0xF, 0x2, 0x4,
	C(12)|C(13)|C(14)|C(15)|C(16)|C(17)},
{ "uops_retired", CRU0|CRU1, 0x3, 0x1, 0x4,
	C(12)|C(13)|C(14)|C(15)|C(16)|C(17)},
{ "uop_type", RAT0|RAT1, 0x3, 0x2, 0x2, C(12)|C(13)|C(14)|C(15)|C(16)|C(17)},
{ "retired_mispred_branch_type", TBPU0|TBPU1, 0x1F, 0x5, 0x2,
	C(4)|C(5)|C(6)|C(7)},
{ "retired_branch_type", TBPU0|TBPU1, 0x1F, 0x4, 0x2, C(4)|C(5)|C(6)|C(7) },
{ NULL, 0, 0, 0, 0 }
};

static p4_generic_event_t p4_generic_events[] = {
{ "PAPI_br_msp", "branch_retired", 0xa, C(12)|C(13)|C(14)|C(15)|C(16) },
{ "PAPI_br_ins", "branch_retired", 0xf, C(12)|C(13)|C(14)|C(15)|C(16) },
{ "PAPI_br_tkn", "branch_retired", 0xc, C(12)|C(13)|C(14)|C(15)|C(16) },
{ "PAPI_br_ntk", "branch_retired", 0x3, C(12)|C(13)|C(14)|C(15)|C(16) },
{ "PAPI_br_prc", "branch_retired", 0x5, C(12)|C(13)|C(14)|C(15)|C(16) },
{ "PAPI_tot_ins", "instr_retired", 0x3, C(12)|C(13)|C(14)|C(15)|C(16)|C(17) },
{ "PAPI_tot_cyc", "global_power_events", 0x1, C(0)|C(1)|C(2)|C(3) },
{ "PAPI_tlb_dm", "page_walk_type", 0x1, C(0)|C(1)|C(2)|C(3) },
{ "PAPI_tlb_im", "page_walk_type", 0x2, C(0)|C(1)|C(2)|C(3) },
{ "PAPI_tlb_tm", "page_walk_type", 0x3, C(0)|C(1)|C(2)|C(3) },
{ "PAPI_l1_icm", "BPU_fetch_request", 0x1, C(0)|C(1)|C(2)|C(3) },
{ "PAPI_l2_ldm", "BSQ_cache_reference", 0x100, C(0)|C(1)|C(2)|C(3) },
{ "PAPI_l2_stm", "BSQ_cache_reference", 0x400, C(0)|C(1)|C(2)|C(3) },
{ "PAPI_l2_tcm", "BSQ_cache_reference", 0x500, C(0)|C(1)|C(2)|C(3) },
GEN_EVT_END
};

/*
 * Indicates whether the "rdpmc" instruction is available on this processor.
 */
static int p4_rdpmc_avail = 0;
static char *p4_eventlist[18];

/*
 * If set, this processor has HyperThreading.
 */
static int p4_htt = 0;

#define	P4_FAMILY	0xF

static int
p4_pcbe_init(void)
{
	int			i;
	size_t			size;
	p4_event_t		*ev;
	p4_generic_event_t	*gevp;

	/*
	 * If we're not running on a P4, refuse to load.
	 */
	if (cpuid_getvendor(CPU) != X86_VENDOR_Intel ||
	    cpuid_getfamily(CPU) != P4_FAMILY)
		return (-1);

	/*
	 * Set up the event lists for each counter.
	 *
	 * First pass calculates the size of the event list, and the second
	 * pass copies each event name into the event list.
	 */
	for (i = 0; i < 18; i++) {
		size = 0;

		for (ev = p4_events; ev->pe_name != NULL; ev++) {
			if (ev->pe_ctr_mask & C(i))
				size += strlen(ev->pe_name) + 1;
		}

		for (gevp = p4_generic_events; gevp->name != NULL; gevp++) {
			if (gevp->ctr_mask & C(i))
				size += strlen(gevp->name) + 1;
		}

		/*
		 * We use 'size + 1' here to ensure room for the final
		 * strcat when it terminates the string.
		 */
		p4_eventlist[i] = (char *)kmem_alloc(size + 1, KM_SLEEP);
		*p4_eventlist[i] = '\0';

		for (ev = p4_events; ev->pe_name != NULL; ev++) {
			if (ev->pe_ctr_mask & C(i)) {
				(void) strcat(p4_eventlist[i], ev->pe_name);
				(void) strcat(p4_eventlist[i], ",");
			}
		}

		for (gevp = p4_generic_events; gevp->name != NULL; gevp++) {
			if (gevp->ctr_mask & C(i)) {
				(void) strcat(p4_eventlist[i], gevp->name);
				(void) strcat(p4_eventlist[i], ",");
			}
		}

		/*
		 * Remove trailing ','
		 */
		p4_eventlist[i][size - 1] = '\0';
	}

	if (is_x86_feature(x86_featureset, X86FSET_MMX))
		p4_rdpmc_avail = 1;
	/*
	 * The X86_HTT flag may disappear soon, so we'll isolate the impact of
	 * its demise to the following if().
	 */
	if (is_x86_feature(x86_featureset, X86FSET_HTT))
		p4_htt = 1;

	return (0);
}

static uint_t
p4_pcbe_ncounters(void)
{
	return (18);
}

static const char *
p4_pcbe_impl_name(void)
{
	if (p4_htt)
		return (PCBE_IMPL_NAME_P4HT);
	return ("Pentium 4");
}

static const char *
p4_pcbe_cpuref(void)
{
	return ("See Appendix A.1 of the \"IA-32 Intel Architecture Software " \
	    "Developer's Manual Volume 3: System Programming Guide,\" "	       \
	    "Order # 245472-012, 2003");
}

static char *
p4_pcbe_list_events(uint_t picnum)
{
	ASSERT(picnum >= 0 && picnum < 18);

	return (p4_eventlist[picnum]);
}

#define	P4_ATTRS "emask,tag,compare,complement,threshold,edge"

static char *
p4_pcbe_list_attrs(void)
{
	if (p4_htt)
		return (P4_ATTRS ",active_thread,count_sibling_usr,"
		    "count_sibling_sys");
	return (P4_ATTRS);
}

static p4_generic_event_t *
find_generic_event(char *name)
{
	p4_generic_event_t	*gevp;

	for (gevp = p4_generic_events; gevp->name != NULL; gevp++)
		if (strcmp(name, gevp->name) == 0)
			return (gevp);

	return (NULL);
}

static p4_event_t *
find_event(char *name)
{
	p4_event_t		*evp;

	for (evp = p4_events; evp->pe_name != NULL; evp++)
		if (strcmp(name, evp->pe_name) == 0)
			return (evp);

	return (NULL);
}

static uint64_t
p4_pcbe_event_coverage(char *event)
{
	p4_event_t		*ev;
	p4_generic_event_t	*gevp;

	if ((ev = find_event(event)) == NULL) {
		if ((gevp = find_generic_event(event)) != NULL)
			return (gevp->ctr_mask);
		else
			return (0);
	}

	return (ev->pe_ctr_mask);
}

static uint64_t
p4_pcbe_overflow_bitmap(void)
{
	extern int	kcpc_hw_overflow_intr_installed;
	uint64_t	ret = 0;
	int		i;

	/*
	 * The CCCR's OVF bit indicates that the corresponding counter has
	 * overflowed. It must be explicitly cleared by software, so it is
	 * safe to read the CCCR values here.
	 */
	for (i = 0; i < 18; i++) {
		if (rdmsr(p4_ctrs[i].pc_ctladdr) & CCCR_OVF)
			ret |= (1 << i);
	}

	/*
	 * Pentium 4 and Xeon turn off the CPC interrupt mask bit in the LVT at
	 * every overflow. Turn it back on here.
	 */
	ASSERT(kcpc_hw_overflow_intr_installed);
	(*kcpc_hw_enable_cpc_intr)();

	return (ret);
}

static int
p4_escr_inuse(p4_pcbe_config_t **cfgs, int escr_ndx)
{
	int i;

	for (i = 0; i < 18; i++) {
		if (cfgs[i] == NULL)
			continue;
		if (cfgs[i]->p4_escr_ndx == escr_ndx)
			return (1);
	}

	return (0);
}

static void
build_cfgs(p4_pcbe_config_t *cfgs[18], uint64_t *data[18], void *token)
{
	p4_pcbe_config_t	*cfg = NULL;
	uint64_t		*daddr;

	bzero(cfgs, 18 * sizeof (p4_pcbe_config_t *));

	do {
		cfg = (p4_pcbe_config_t *)kcpc_next_config(token, cfg, &daddr);

		if (cfg != NULL) {
			ASSERT(cfg->p4_picno < 18);
			cfgs[cfg->p4_picno] = cfg;
			if (data != NULL) {
				ASSERT(daddr != NULL);
				data[cfg->p4_picno] = daddr;
			}
		}
	} while (cfg != NULL);
}

/*
 * Programming a counter:
 *
 * Select event.
 * Choose an ESCR capable of counting that event.
 * Set up the ESCR with the desired parameters (usr, sys, tag).
 * Set up the CCCR to point to the selected ESCR.
 * Set the CCCR parameters (overflow, cascade, edge, etc).
 */
static int
p4_pcbe_configure(uint_t picnum, char *eventname, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token)
{
	p4_pcbe_config_t	*cfgs[18];
	p4_pcbe_config_t	*cfg;
	p4_event_t		*ev;
	p4_generic_event_t	*gevp;
	int			escr_ndx;
	int			i;
	uint16_t		emask = 0;
	uint8_t			tag;
	int			use_tag = 0;
	int			active_thread = 0x3; /* default is "any" */
	int			compare = 0;
	int			complement = 0;
	int			threshold = 0;
	int			edge = 0;
	int			sibling_usr = 0; /* count usr on other cpu */
	int			sibling_sys = 0; /* count sys on other cpu */
	int			invalid_attr = 0;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		cfg = *data;
		cfg->p4_rawpic = preset & MASK40;
		return (0);
	}

	if (picnum < 0 || picnum >= 18)
		return (CPC_INVALID_PICNUM);

	if ((ev	= find_event(eventname)) == NULL) {
		if ((gevp = find_generic_event(eventname)) != NULL) {
			ev = find_event(gevp->event);
			ASSERT(ev != NULL);

			/*
			 * For generic events a HTT processor is only allowed
			 * to specify the 'active_thread', 'count_sibling_usr'
			 * and 'count_sibling_sys' attributes.
			 */
			if (p4_htt)
				for (i = 0; i < nattrs; i++)
					if (strstr(P4_ATTRS,
					    attrs[i].ka_name) != NULL)
						invalid_attr = 1;

			if ((p4_htt && invalid_attr) ||
			    (!p4_htt && nattrs > 0))
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);

			emask = gevp->emask;
		} else {
			return (CPC_INVALID_EVENT);
		}
	}

	build_cfgs(cfgs, NULL, token);

	/*
	 * Find an ESCR capable of counting this event.
	 */
	for (escr_ndx = 0; escr_ndx < ESCR_MAX_INDEX; escr_ndx++) {
		if ((ev->pe_escr_map & (1ULL << escr_ndx)) &&
		    p4_escr_inuse(cfgs, escr_ndx) == 0)
			break;
	}

	/*
	 * All ESCRs capable of counting this event are already being
	 * used.
	 */
	if (escr_ndx == ESCR_MAX_INDEX)
		return (CPC_RESOURCE_UNAVAIL);

	/*
	 * At this point, ev points to the desired event and escr is the index
	 * of a capable and available ESCR.
	 *
	 * Now process and verify the attributes.
	 */
	for (i = 0; i < nattrs; i++) {
		if (strcmp("emask", attrs[i].ka_name) == 0) {
			if ((attrs[i].ka_val | ev->pe_escr_mask)
			    != ev->pe_escr_mask)
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			emask = attrs[i].ka_val;
			continue;
		} else if (strcmp("tag", attrs[i].ka_name) == 0) {
			if (attrs[i].ka_val > ESCR_TAG_VALUE_MAX)
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			tag = attrs[i].ka_val;
			use_tag = 1;
			continue;
		} else if (strcmp("compare", attrs[i].ka_name) == 0) {
			if (attrs[i].ka_val != 0)
				compare = 1;
			continue;
		} else if (strcmp("complement", attrs[i].ka_name) == 0) {
			if (attrs[i].ka_val != 0)
				complement = 1;
			continue;
		} else if (strcmp("threshold", attrs[i].ka_name) == 0) {
			if (attrs[i].ka_val > CCCR_THRESHOLD_MAX)
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			threshold = attrs[i].ka_val;
			continue;
		} else if (strcmp("edge", attrs[i].ka_name) == 0) {
			if (attrs[i].ka_val != 0)
				edge = 1;
			continue;
		}

		/*
		 * The remaining attributes are valid only on HyperThreaded P4s
		 * for processes with the "cpc_cpu" privilege.
		 */
		if (p4_htt == 0)
			return (CPC_INVALID_ATTRIBUTE);

		if (secpolicy_cpc_cpu(crgetcred()) != 0)
			return (CPC_ATTR_REQUIRES_PRIVILEGE);

		if (strcmp("active_thread", attrs[i].ka_name) == 0) {
			if ((attrs[i].ka_val | CCCR_ACTV_THR_MASK) !=
			    CCCR_ACTV_THR_MASK)
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			active_thread = (int)attrs[i].ka_val;
		} else if (strcmp("count_sibling_usr", attrs[i].ka_name) == 0) {
			if (attrs[i].ka_val != 0)
				sibling_usr = 1;
		} else if (strcmp("count_sibling_sys", attrs[i].ka_name) == 0) {
			if (attrs[i].ka_val != 0)
				sibling_sys = 1;
		} else
			return (CPC_INVALID_ATTRIBUTE);
	}

	/*
	 * Make sure the counter can count this event
	 */
	if ((ev->pe_ctr_mask & C(picnum)) == 0)
		return (CPC_PIC_NOT_CAPABLE);

	/*
	 * Find an ESCR that lines up with the event _and_ the counter.
	 */
	for (escr_ndx = 0; escr_ndx < ESCR_MAX_INDEX; escr_ndx++) {
		if ((ev->pe_escr_map & (1ULL << escr_ndx)) &&
		    (p4_escrs[escr_ndx].pe_map & (1 << picnum)) &&
		    p4_escr_inuse(cfgs, escr_ndx) == 0)
			break;
	}
	if (escr_ndx == ESCR_MAX_INDEX)
		return (CPC_RESOURCE_UNAVAIL);

	cfg = (p4_pcbe_config_t *)kmem_alloc(sizeof (p4_pcbe_config_t),
	    KM_SLEEP);

	cfg->p4_flags = 0;
	cfg->p4_picno = picnum;
	cfg->p4_escr_ndx = escr_ndx;
	cfg->p4_escr = (ev->pe_ev << ESCR_EVSEL_SHIFT) |
	    (emask << ESCR_EVMASK_SHIFT);

	if (use_tag == 1) {
		cfg->p4_escr |= tag << ESCR_TAG_VALUE_SHIFT;
		cfg->p4_escr |= ESCR_TAG_ENABLE;
	}

	if (p4_htt) {
		/*
		 * This is a HyperThreaded P4.  Since we don't know which
		 * logical CPU this configuration will eventually be programmed
		 * on, we can't yet decide which fields of the ESCR to select.
		 *
		 * Record the necessary information in the flags for later.
		 */
		if (flags & CPC_COUNT_USER)
			cfg->p4_flags |= P4_THIS_USR;
		if (flags & CPC_COUNT_SYSTEM)
			cfg->p4_flags |= P4_THIS_SYS;
		if (p4_htt && sibling_usr)
			cfg->p4_flags |= P4_SIBLING_USR;
		if (p4_htt && sibling_sys)
			cfg->p4_flags |= P4_SIBLING_SYS;
	} else {
		/*
		 * This is not HyperThreaded, so we can determine the exact
		 * ESCR value necessary now.
		 */
		if (flags & CPC_COUNT_USER)
			cfg->p4_escr |= ESCR_USR;
		if (flags & CPC_COUNT_SYSTEM)
			cfg->p4_escr |= ESCR_OS;
	}

	cfg->p4_rawpic = preset & MASK40;

	/*
	 * Even on non-HT P4s, Intel states the active_thread field (marked as
	 * "reserved" for the non-HT chips) must be set to all 1s.
	 */
	cfg->p4_cccr = CCCR_INIT | (active_thread << CCCR_ACTV_THR_SHIFT);
	if (compare)
		cfg->p4_cccr |= CCCR_COMPARE;
	if (complement)
		cfg->p4_cccr |= CCCR_COMPLEMENT;
	cfg->p4_cccr |= threshold << CCCR_THRESHOLD_SHIFT;
	if (edge)
		cfg->p4_cccr |= CCCR_EDGE;
	cfg->p4_cccr |= p4_escrs[cfg->p4_escr_ndx].pe_num
	    << CCCR_ESCR_SEL_SHIFT;
	if (flags & CPC_OVF_NOTIFY_EMT) {
		if (p4_htt)
			cfg->p4_flags |= P4_PMI;
		else {
			/*
			 * If the user has asked for notification of overflows,
			 * we automatically program the hardware to generate an
			 * interrupt on overflow.
			 *
			 * This can only be programmed now if this P4 doesn't
			 * have HyperThreading. If it does, we must wait until
			 * we know which logical CPU we'll be programming.
			 */
			cfg->p4_cccr |= CCCR_OVF_PMI;
		}
	}

	*data = cfg;

	return (0);
}

static void
p4_pcbe_program(void *token)
{
	int			i;
	uint64_t		cccr;
	p4_pcbe_config_t	*cfgs[18];

	p4_pcbe_allstop();

	build_cfgs(cfgs, NULL, token);

	if (p4_rdpmc_avail) {
		ulong_t curcr4 = getcr4();
		if (kcpc_allow_nonpriv(token))
			setcr4(curcr4 | CR4_PCE);
		else
			setcr4(curcr4 & ~CR4_PCE);
	}

	/*
	 * Ideally we would start all counters with a single operation, but in
	 * P4 each counter is enabled individually via its CCCR. To minimize the
	 * probe effect of enabling the counters, we do it in two passes: the
	 * first programs the counter and ESCR, and the second programs the
	 * CCCR (and thus enables the counter).
	 */
	if (p4_htt) {
		int	lid = cpuid_get_clogid(CPU); /* Logical ID of CPU */

		for (i = 0; i < 18; i++) {
			uint64_t escr;

			if (cfgs[i] == NULL)
				continue;
			escr = (uint64_t)cfgs[i]->p4_escr;

			if (cfgs[i]->p4_flags & P4_THIS_USR)
				escr |= (lid == 0) ? ESCR_T0_USR : ESCR_T1_USR;
			if (cfgs[i]->p4_flags & P4_THIS_SYS)
				escr |= (lid == 0) ? ESCR_T0_OS : ESCR_T1_OS;
			if (cfgs[i]->p4_flags & P4_SIBLING_USR)
				escr |= (lid == 0) ? ESCR_T1_USR : ESCR_T0_USR;
			if (cfgs[i]->p4_flags & P4_SIBLING_SYS)
				escr |= (lid == 0) ? ESCR_T1_OS : ESCR_T0_OS;

			wrmsr(p4_ctrs[i].pc_caddr, cfgs[i]->p4_rawpic);
			wrmsr(p4_escrs[cfgs[i]->p4_escr_ndx].pe_addr, escr);
		}

		for (i = 0; i < 18; i++) {
			if (cfgs[i] == NULL)
				continue;
			cccr = (uint64_t)cfgs[i]->p4_cccr;
			/*
			 * We always target the overflow interrupt at the
			 * logical CPU which is doing the counting.
			 */
			if (cfgs[i]->p4_flags & P4_PMI)
				cccr |= (lid == 0) ?
				    CCCR_OVF_PMI_T0 : CCCR_OVF_PMI_T1;
			wrmsr(p4_ctrs[i].pc_ctladdr, cccr);
		}
	} else {
		for (i = 0; i < 18; i++) {
			if (cfgs[i] == NULL)
				continue;
			wrmsr(p4_ctrs[i].pc_caddr, cfgs[i]->p4_rawpic);
			wrmsr(p4_escrs[cfgs[i]->p4_escr_ndx].pe_addr,
			    (uint64_t)cfgs[i]->p4_escr);
		}

		for (i = 0; i < 18; i++) {
			if (cfgs[i] == NULL)
				continue;
			wrmsr(p4_ctrs[i].pc_ctladdr,
			    (uint64_t)cfgs[i]->p4_cccr);
		}
	}
}

static void
p4_pcbe_allstop(void)
{
	int		i;

	for (i = 0; i < 18; i++)
		wrmsr(p4_ctrs[i].pc_ctladdr, 0ULL);

	setcr4(getcr4() & ~CR4_PCE);
}


static void
p4_pcbe_sample(void *token)
{
	p4_pcbe_config_t	*cfgs[18];
	uint64_t		*addrs[18];
	uint64_t		curpic[18];
	int64_t			diff;
	int			i;

	for (i = 0; i < 18; i++)
		curpic[i] = rdmsr(p4_ctrs[i].pc_caddr);

	build_cfgs(cfgs, addrs, token);

	for (i = 0; i < 18; i++) {
		if (cfgs[i] == NULL)
			continue;
		diff = curpic[i] - cfgs[i]->p4_rawpic;
		if (diff < 0)
			diff += (1ll << 40);
		*addrs[i] += diff;
		DTRACE_PROBE4(p4__pcbe__sample, int, i, uint64_t, *addrs[i],
		    uint64_t, curpic[i], uint64_t, cfgs[i]->p4_rawpic);
		cfgs[i]->p4_rawpic = *addrs[i] & MASK40;
	}
}

static void
p4_pcbe_free(void *config)
{
	kmem_free(config, sizeof (p4_pcbe_config_t));
}

static struct modlpcbe modlpcbe = {
	&mod_pcbeops,
	"Pentium 4 Performance Counters",
	&p4_pcbe_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modlpcbe,
};

int
_init(void)
{
	if (p4_pcbe_init() != 0)
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
