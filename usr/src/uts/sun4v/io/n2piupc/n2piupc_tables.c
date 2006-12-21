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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Tables to drive the N2 PIU performance counter driver.
 *
 * Please see n2piupc-tables.h for an explanation of how the table is put
 * together.
 */

#include <sys/types.h>
#include <sys/kstat.h>
#include "n2piupc_tables.h"
#include "n2piupc.h"
#include "n2piupc_biterr.h"

static n2piu_event_t imu_ctr_1_evts[] = {
	{ IMU01_S_EVT_NONE,			IMU01_EVT_NONE },
	{ IMU01_S_EVT_CLK,			IMU01_EVT_CLK },
	{ IMU01_S_EVT_TOTAL_MONDO,		IMU01_EVT_TOTAL_MONDO },
	{ IMU01_S_EVT_TOTAL_MSI,		IMU01_EVT_TOTAL_MSI },
	{ IMU01_S_EVT_NAK_MONDO,		IMU01_EVT_NAK_MONDO },
	{ IMU01_S_EVT_EQ_WR,			IMU01_EVT_EQ_WR },
	{ IMU01_S_EVT_EQ_MONDO,			IMU01_EVT_EQ_MONDO },
	{ COMMON_S_CLEAR_PIC,			IMU_CTR_EVT_MASK }
};

static n2piu_event_t imu_ctr_0_evts[] = {
	{ IMU01_S_EVT_NONE,			IMU01_EVT_NONE },
	{ IMU01_S_EVT_CLK,			IMU01_EVT_CLK },
	{ IMU01_S_EVT_TOTAL_MONDO,		IMU01_EVT_TOTAL_MONDO },
	{ IMU01_S_EVT_TOTAL_MSI,		IMU01_EVT_TOTAL_MSI },
	{ IMU01_S_EVT_NAK_MONDO,		IMU01_EVT_NAK_MONDO },
	{ IMU01_S_EVT_EQ_WR,			IMU01_EVT_EQ_WR },
	{ IMU01_S_EVT_EQ_MONDO,			IMU01_EVT_EQ_MONDO },
	{ COMMON_S_CLEAR_PIC,			IMU_CTR_EVT_MASK }
};

static n2piu_event_t mmu_ctr_1_evts[] = {
	{ MMU01_S_EVT_NONE,			MMU01_EVT_NONE },
	{ MMU01_S_EVT_CLK,			MMU01_EVT_CLK },
	{ MMU01_S_EVT_TRANS,			MMU01_EVT_TRANS },
	{ MMU01_S_EVT_STALL,			MMU01_EVT_STALL },
	{ MMU01_S_EVT_TRANS_MISS,		MMU01_EVT_TRANS_MISS },
	{ MMU01_S_EVT_TBLWLK_STALL,		MMU01_EVT_TBLWLK_STALL },
	{ MMU01_S_EVT_BYPASS_TRANSL,		MMU01_EVT_BYPASS_TRANSL },
	{ MMU01_S_EVT_TRANSL_TRANSL,		MMU01_EVT_TRANSL_TRANSL },
	{ MMU01_S_EVT_FLOW_CNTL_STALL,		MMU01_EVT_FLOW_CNTL_STALL },
	{ MMU01_S_EVT_FLUSH_CACHE_ENT,		MMU01_EVT_FLUSH_CACHE_ENT },
	{ COMMON_S_CLEAR_PIC,			MMU_CTR_EVT_MASK }
};

static n2piu_event_t mmu_ctr_0_evts[] = {
	{ MMU01_S_EVT_NONE,			MMU01_EVT_NONE },
	{ MMU01_S_EVT_CLK,			MMU01_EVT_CLK },
	{ MMU01_S_EVT_TRANS,			MMU01_EVT_TRANS },
	{ MMU01_S_EVT_STALL,			MMU01_EVT_STALL },
	{ MMU01_S_EVT_TRANS_MISS,		MMU01_EVT_TRANS_MISS },
	{ MMU01_S_EVT_TBLWLK_STALL,		MMU01_EVT_TBLWLK_STALL },
	{ MMU01_S_EVT_BYPASS_TRANSL,		MMU01_EVT_BYPASS_TRANSL },
	{ MMU01_S_EVT_TRANSL_TRANSL,		MMU01_EVT_TRANSL_TRANSL },
	{ MMU01_S_EVT_FLOW_CNTL_STALL,		MMU01_EVT_FLOW_CNTL_STALL },
	{ MMU01_S_EVT_FLUSH_CACHE_ENT,		MMU01_EVT_FLUSH_CACHE_ENT },
	{ COMMON_S_CLEAR_PIC,			MMU_CTR_EVT_MASK }
};

static n2piu_event_t peu_ctr_2_evts[] = {
	{ PEU2_S_EVT_NONE,			PEU2_EVT_NONE },
	{ PEU2_S_EVT_NONPST_CMPL_TIME,		PEU2_EVT_NONPST_CMPL_TIME },
	{ PEU2_S_EVT_XMIT_DATA,			PEU2_EVT_XMIT_DATA },
	{ PEU2_S_EVT_RCVD_DATA,			PEU2_EVT_RCVD_DATA },
	{ COMMON_S_CLEAR_PIC,			PEU_CTR_2_EVT_MASK }
};

static n2piu_event_t peu_ctr_1_evts[] = {
	{ PEU01_S_EVT_NONE,			PEU01_EVT_NONE },
	{ PEU01_S_EVT_CLK,			PEU01_EVT_CLK },
	{ PEU01_S_EVT_COMPL,			PEU01_EVT_COMPL },
	{ PEU01_S_EVT_XMT_POST_CR_UNAV,		PEU01_EVT_XMT_POST_CR_UNAV },
	{ PEU01_S_EVT_XMT_NPOST_CR_UNAV,	PEU01_EVT_XMT_NPOST_CR_UNAV },
	{ PEU01_S_EVT_XMT_CMPL_CR_UNAV,		PEU01_EVT_XMT_CMPL_CR_UNAV },
	{ PEU01_S_EVT_XMT_ANY_CR_UNAV,		PEU01_EVT_XMT_ANY_CR_UNAV },
	{ PEU01_S_EVT_RETRY_CR_UNAV,		PEU01_EVT_RETRY_CR_UNAV },
	{ PEU01_S_EVT_MEMRD_PKT_RCVD,		PEU01_EVT_MEMRD_PKT_RCVD },
	{ PEU01_S_EVT_MEMWR_PKT_RCVD,		PEU01_EVT_MEMWR_PKT_RCVD },
	{ PEU01_S_EVT_RCV_CR_THRESH,		PEU01_EVT_RCV_CR_THRESH },
	{ PEU01_S_EVT_RCV_PST_HDR_CR_EXH,	PEU01_EVT_RCV_PST_HDR_CR_EXH },
	{ PEU01_S_EVT_RCV_PST_DA_CR_MPS,	PEU01_EVT_RCV_PST_DA_CR_MPS },
	{ PEU01_S_EVT_RCV_NPST_HDR_CR_EXH,	PEU01_EVT_RCV_NPST_HDR_CR_EXH },
	{ PEU01_S_EVT_RCVR_L0S,			PEU01_EVT_RCVR_L0S },
	{ PEU01_S_EVT_RCVR_L0S_TRANS,		PEU01_EVT_RCVR_L0S_TRANS },
	{ PEU01_S_EVT_XMTR_L0S,			PEU01_EVT_XMTR_L0S },
	{ PEU01_S_EVT_XMTR_L0S_TRANS,		PEU01_EVT_XMTR_L0S_TRANS },
	{ PEU01_S_EVT_RCVR_ERR,			PEU01_EVT_RCVR_ERR },
	{ PEU01_S_EVT_BAD_TLP,			PEU01_EVT_BAD_TLP },
	{ PEU01_S_EVT_BAD_DLLP,			PEU01_EVT_BAD_DLLP },
	{ PEU01_S_EVT_REPLAY_ROLLOVER,		PEU01_EVT_REPLAY_ROLLOVER },
	{ PEU01_S_EVT_REPLAY_TMO,		PEU01_EVT_REPLAY_TMO },
	{ COMMON_S_CLEAR_PIC,			PEU_CTR_01_EVT_MASK }
};

static n2piu_event_t peu_ctr_0_evts[] = {
	{ PEU01_S_EVT_NONE,			PEU01_EVT_NONE },
	{ PEU01_S_EVT_CLK,			PEU01_EVT_CLK },
	{ PEU01_S_EVT_COMPL,			PEU01_EVT_COMPL },
	{ PEU01_S_EVT_XMT_POST_CR_UNAV,		PEU01_EVT_XMT_POST_CR_UNAV },
	{ PEU01_S_EVT_XMT_NPOST_CR_UNAV,	PEU01_EVT_XMT_NPOST_CR_UNAV },
	{ PEU01_S_EVT_XMT_CMPL_CR_UNAV,		PEU01_EVT_XMT_CMPL_CR_UNAV },
	{ PEU01_S_EVT_XMT_ANY_CR_UNAV,		PEU01_EVT_XMT_ANY_CR_UNAV },
	{ PEU01_S_EVT_RETRY_CR_UNAV,		PEU01_EVT_RETRY_CR_UNAV },
	{ PEU01_S_EVT_MEMRD_PKT_RCVD,		PEU01_EVT_MEMRD_PKT_RCVD },
	{ PEU01_S_EVT_MEMWR_PKT_RCVD,		PEU01_EVT_MEMWR_PKT_RCVD },
	{ PEU01_S_EVT_RCV_CR_THRESH,		PEU01_EVT_RCV_CR_THRESH },
	{ PEU01_S_EVT_RCV_PST_HDR_CR_EXH,	PEU01_EVT_RCV_PST_HDR_CR_EXH },
	{ PEU01_S_EVT_RCV_PST_DA_CR_MPS,	PEU01_EVT_RCV_PST_DA_CR_MPS },
	{ PEU01_S_EVT_RCV_NPST_HDR_CR_EXH,	PEU01_EVT_RCV_NPST_HDR_CR_EXH },
	{ PEU01_S_EVT_RCVR_L0S,			PEU01_EVT_RCVR_L0S },
	{ PEU01_S_EVT_RCVR_L0S_TRANS,		PEU01_EVT_RCVR_L0S_TRANS },
	{ PEU01_S_EVT_XMTR_L0S,			PEU01_EVT_XMTR_L0S },
	{ PEU01_S_EVT_XMTR_L0S_TRANS,		PEU01_EVT_XMTR_L0S_TRANS },
	{ PEU01_S_EVT_RCVR_ERR,			PEU01_EVT_RCVR_ERR },
	{ PEU01_S_EVT_BAD_TLP,			PEU01_EVT_BAD_TLP },
	{ PEU01_S_EVT_BAD_DLLP,			PEU01_EVT_BAD_DLLP },
	{ PEU01_S_EVT_REPLAY_ROLLOVER,		PEU01_EVT_REPLAY_ROLLOVER },
	{ PEU01_S_EVT_REPLAY_TMO,		PEU01_EVT_REPLAY_TMO },
	{ COMMON_S_CLEAR_PIC,			PEU_CTR_01_EVT_MASK }
};

static n2piu_event_t bterr_ctr_3_evts[] = {
	{ BTERR3_S_EVT_NONE,			BTERR3_EVT_ENC_NONE },
	{ BTERR3_S_EVT_ENC_ALL,			BTERR3_EVT_ENC_ALL },
	{ BTERR3_S_EVT_ENC_LANE_0,		BTERR3_EVT_ENC_LANE_0 },
	{ BTERR3_S_EVT_ENC_LANE_1,		BTERR3_EVT_ENC_LANE_1 },
	{ BTERR3_S_EVT_ENC_LANE_2,		BTERR3_EVT_ENC_LANE_2 },
	{ BTERR3_S_EVT_ENC_LANE_3,		BTERR3_EVT_ENC_LANE_3 },
	{ BTERR3_S_EVT_ENC_LANE_4,		BTERR3_EVT_ENC_LANE_4 },
	{ BTERR3_S_EVT_ENC_LANE_5,		BTERR3_EVT_ENC_LANE_5 },
	{ BTERR3_S_EVT_ENC_LANE_6,		BTERR3_EVT_ENC_LANE_6 },
	{ BTERR3_S_EVT_ENC_LANE_7,		BTERR3_EVT_ENC_LANE_7 },
	{ COMMON_S_CLEAR_PIC,			BTERR_CTR_3_EVT_MASK }
};

static n2piu_event_t bterr_ctr_2_evts[] = {
	{ BTERR2_S_EVT_PRE,			BTERR2_EVT_PRE },
	{ COMMON_S_CLEAR_PIC,			NONPROG_DUMMY_MASK }
};

static n2piu_event_t bterr_ctr_1_evts[] = {
	{ BTERR1_S_EVT_BTLP,			BTERR1_EVT_BTLP },
	{ COMMON_S_CLEAR_PIC,			NONPROG_DUMMY_MASK }
};

static n2piu_event_t bterr_ctr_0_evts[] = {
	{ BTERR0_S_EVT_RESET,			BTERR0_EVT_RESET },
	{ BTERR0_S_EVT_BDLLP,			BTERR0_EVT_BDLLP },
	{ COMMON_S_CLEAR_PIC,			BTERR_CTR_0_EVT_MASK }
};

static n2piu_regsel_fld_t imu_regsel_flds[] = {
	{ imu_ctr_0_evts, NUM_EVTS(imu_ctr_0_evts),
				IMU_CTR_EVT_MASK, IMU_CTR_0_EVT_OFF },
	{ imu_ctr_1_evts, NUM_EVTS(imu_ctr_1_evts),
				IMU_CTR_EVT_MASK, IMU_CTR_1_EVT_OFF }
};

static n2piu_regsel_fld_t mmu_regsel_flds[] = {
	{ mmu_ctr_0_evts, NUM_EVTS(mmu_ctr_0_evts),
				MMU_CTR_EVT_MASK, MMU_CTR_0_EVT_OFF },
	{ mmu_ctr_1_evts, NUM_EVTS(mmu_ctr_1_evts),
				MMU_CTR_EVT_MASK, MMU_CTR_1_EVT_OFF }
};

static n2piu_regsel_fld_t peu_regsel_flds[] = {
	{ peu_ctr_0_evts, NUM_EVTS(peu_ctr_0_evts),
				PEU_CTR_01_EVT_MASK, PEU_CTR_0_EVT_OFF },
	{ peu_ctr_1_evts, NUM_EVTS(peu_ctr_1_evts),
				PEU_CTR_01_EVT_MASK, PEU_CTR_1_EVT_OFF },
	{ peu_ctr_2_evts, NUM_EVTS(peu_ctr_2_evts),
				PEU_CTR_2_EVT_MASK, PEU_CTR_2_EVT_OFF }
};

static n2piu_regsel_fld_t bterr_regsel_flds[] = {
	{ bterr_ctr_0_evts, NUM_EVTS(bterr_ctr_0_evts),
				BTERR_CTR_ENABLE_MASK, BTERR_CTR_ENABLE_OFF },
	{ bterr_ctr_1_evts, NUM_EVTS(bterr_ctr_1_evts),
				NONPROG_DUMMY_MASK, NONPROG_DUMMY_OFF },
	{ bterr_ctr_2_evts, NUM_EVTS(bterr_ctr_2_evts),
				NONPROG_DUMMY_MASK, NONPROG_DUMMY_OFF },
	{ bterr_ctr_3_evts, NUM_EVTS(bterr_ctr_3_evts),
				BTERR_CTR_3_EVT_MASK, BTERR_CTR_3_EVT_OFF }
};

static n2piu_regsel_t imu_regsel = {
	HVIO_N2PIU_PERFREG_IMU_SEL,
	imu_regsel_flds,
	NUM_FLDS(imu_regsel_flds)
};

static n2piu_regsel_t mmu_regsel = {
	HVIO_N2PIU_PERFREG_MMU_SEL,
	mmu_regsel_flds,
	NUM_FLDS(mmu_regsel_flds)
};

static n2piu_regsel_t peu_regsel = {
	HVIO_N2PIU_PERFREG_PEU_SEL,
	peu_regsel_flds,
	NUM_FLDS(peu_regsel_flds)
};

static n2piu_regsel_t bit_err_regsel = {
	SW_N2PIU_BITERR_SEL,
	bterr_regsel_flds,
	NUM_FLDS(bterr_regsel_flds)
};

/* reg off, reg size, field mask */
static n2piu_cntr_t imu_cntrs[] = {
	{ HVIO_N2PIU_PERFREG_IMU_CNT0, FULL64BIT,
		HVIO_N2PIU_PERFREG_IMU_CNT0, 0ULL},
	{ HVIO_N2PIU_PERFREG_IMU_CNT1, FULL64BIT,
		HVIO_N2PIU_PERFREG_IMU_CNT1, 0ULL}
};

static n2piu_cntr_t mmu_cntrs[] = {
	{ HVIO_N2PIU_PERFREG_MMU_CNT0, FULL64BIT,
		HVIO_N2PIU_PERFREG_MMU_CNT0, 0ULL},
	{ HVIO_N2PIU_PERFREG_MMU_CNT1, FULL64BIT,
		HVIO_N2PIU_PERFREG_MMU_CNT1, 0ULL}
};

static n2piu_cntr_t peu_cntrs[] = {
	{ HVIO_N2PIU_PERFREG_PEU_CNT0, FULL64BIT,
		HVIO_N2PIU_PERFREG_PEU_CNT0, 0ULL},
	{ HVIO_N2PIU_PERFREG_PEU_CNT1, FULL64BIT,
		HVIO_N2PIU_PERFREG_PEU_CNT1, 0ULL},
	{ HVIO_N2PIU_PERFREG_PEU_CNT2, FULL64BIT,
		HVIO_N2PIU_PERFREG_PEU_CNT2, 0ULL}
};

static n2piu_cntr_t bit_err_cntrs[] = {
	{ SW_N2PIU_BITERR_CNT1_DATA, BE1_BAD_DLLP_MASK,
		SW_N2PIU_BITERR_CLR, BTERR_CTR_CLR},
	{ SW_N2PIU_BITERR_CNT1_DATA, BE1_BAD_TLP_MASK, NO_REGISTER, 0},
	{ SW_N2PIU_BITERR_CNT1_DATA, BE1_BAD_PRE_MASK, NO_REGISTER, 0},

	/* Note: this register is a layered SW-implemented register. */
	{ SW_N2PIU_BITERR_CNT2_DATA, BE2_8_10_MASK, NO_REGISTER, 0},
};

static n2piu_grp_t imu_grp = {
	"imu",
	&imu_regsel,
	imu_cntrs,
	NUM_CTRS(imu_cntrs),
	NULL		/* Name kstats pointer, filled in at runtime. */
};

static n2piu_grp_t mmu_grp = {
	"mmu",
	&mmu_regsel,
	mmu_cntrs,
	NUM_CTRS(mmu_cntrs),
	NULL		/* Name kstats pointer, filled in at runtime. */
};

static n2piu_grp_t peu_grp = {
	"peu",
	&peu_regsel,
	peu_cntrs,
	NUM_CTRS(peu_cntrs),
	NULL		/* Name kstats pointer, filled in at runtime. */
};

static n2piu_grp_t bit_err_grp = {
	"bterr",
	&bit_err_regsel,
	bit_err_cntrs,
	NUM_CTRS(bit_err_cntrs),
	NULL		/* Name kstats pointer, filled in at runtime. */
};

n2piu_grp_t *leaf_grps[] = {
	&imu_grp,
	&mmu_grp,
	&peu_grp,
	&bit_err_grp,
	NULL
};
