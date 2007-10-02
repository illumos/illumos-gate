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
 * sun4u Fire Error Handling
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/pcie.h>
#include <sys/pcie_impl.h>
#include "px_obj.h"
#include <px_regs.h>
#include <px_csr.h>
#include <sys/membar.h>
#include <sys/machcpuvar.h>
#include <sys/platform_module.h>
#include "pcie_pwr.h"
#include "px_lib4u.h"
#include "px_err.h"
#include "px_err_impl.h"
#include "oberon_regs.h"

uint64_t px_tlu_ue_intr_mask	= PX_ERR_EN_ALL;
uint64_t px_tlu_ue_log_mask	= PX_ERR_EN_ALL;
uint64_t px_tlu_ue_count_mask	= PX_ERR_EN_ALL;

uint64_t px_tlu_ce_intr_mask	= PX_ERR_MASK_NONE;
uint64_t px_tlu_ce_log_mask	= PX_ERR_MASK_NONE;
uint64_t px_tlu_ce_count_mask	= PX_ERR_MASK_NONE;

/*
 * Do not enable Link Interrupts
 */
uint64_t px_tlu_oe_intr_mask	= PX_ERR_EN_ALL & ~0x80000000800;
uint64_t px_tlu_oe_log_mask	= PX_ERR_EN_ALL & ~0x80000000800;
uint64_t px_tlu_oe_count_mask	= PX_ERR_EN_ALL;

uint64_t px_mmu_intr_mask	= PX_ERR_EN_ALL;
uint64_t px_mmu_log_mask	= PX_ERR_EN_ALL;
uint64_t px_mmu_count_mask	= PX_ERR_EN_ALL;

uint64_t px_imu_intr_mask	= PX_ERR_EN_ALL;
uint64_t px_imu_log_mask	= PX_ERR_EN_ALL;
uint64_t px_imu_count_mask	= PX_ERR_EN_ALL;

/*
 * (1ull << ILU_INTERRUPT_ENABLE_IHB_PE_S) |
 * (1ull << ILU_INTERRUPT_ENABLE_IHB_PE_P);
 */
uint64_t px_ilu_intr_mask	= (((uint64_t)0x10 << 32) | 0x10);
uint64_t px_ilu_log_mask	= (((uint64_t)0x10 << 32) | 0x10);
uint64_t px_ilu_count_mask	= PX_ERR_EN_ALL;

uint64_t px_ubc_intr_mask	= PX_ERR_EN_ALL;
uint64_t px_ubc_log_mask		= PX_ERR_EN_ALL;
uint64_t px_ubc_count_mask	= PX_ERR_EN_ALL;

uint64_t px_jbc_intr_mask	= PX_ERR_EN_ALL;
uint64_t px_jbc_log_mask		= PX_ERR_EN_ALL;
uint64_t px_jbc_count_mask	= PX_ERR_EN_ALL;

/*
 * LPU Intr Registers are reverse encoding from the registers above.
 * 1 = disable
 * 0 = enable
 *
 * Log and Count are however still the same.
 */
uint64_t px_lpul_intr_mask	= LPU_INTR_DISABLE;
uint64_t px_lpul_log_mask	= PX_ERR_EN_ALL;
uint64_t px_lpul_count_mask	= PX_ERR_EN_ALL;

uint64_t px_lpup_intr_mask	= LPU_INTR_DISABLE;
uint64_t px_lpup_log_mask	= PX_ERR_EN_ALL;
uint64_t px_lpup_count_mask	= PX_ERR_EN_ALL;

uint64_t px_lpur_intr_mask	= LPU_INTR_DISABLE;
uint64_t px_lpur_log_mask	= PX_ERR_EN_ALL;
uint64_t px_lpur_count_mask	= PX_ERR_EN_ALL;

uint64_t px_lpux_intr_mask	= LPU_INTR_DISABLE;
uint64_t px_lpux_log_mask	= PX_ERR_EN_ALL;
uint64_t px_lpux_count_mask	= PX_ERR_EN_ALL;

uint64_t px_lpus_intr_mask	= LPU_INTR_DISABLE;
uint64_t px_lpus_log_mask	= PX_ERR_EN_ALL;
uint64_t px_lpus_count_mask	= PX_ERR_EN_ALL;

uint64_t px_lpug_intr_mask	= LPU_INTR_DISABLE;
uint64_t px_lpug_log_mask	= PX_ERR_EN_ALL;
uint64_t px_lpug_count_mask	= PX_ERR_EN_ALL;

/*
 * JBC error bit table
 */
#define	JBC_BIT_DESC(bit, hdl, erpt) \
	JBC_INTERRUPT_STATUS_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_JBC_CLASS(bit) }, \
	{ JBC_INTERRUPT_STATUS_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_JBC_CLASS(bit)
px_err_bit_desc_t px_err_jbc_tbl[] = {
	/* JBC FATAL */
	{ JBC_BIT_DESC(MB_PEA,	hw_reset,	jbc_fatal) },
	{ JBC_BIT_DESC(CPE,	hw_reset,	jbc_fatal) },
	{ JBC_BIT_DESC(APE,	hw_reset,	jbc_fatal) },
	{ JBC_BIT_DESC(PIO_CPE,	hw_reset,	jbc_fatal) },
	{ JBC_BIT_DESC(JTCEEW,	hw_reset,	jbc_fatal) },
	{ JBC_BIT_DESC(JTCEEI,	hw_reset,	jbc_fatal) },
	{ JBC_BIT_DESC(JTCEER,	hw_reset,	jbc_fatal) },

	/* JBC MERGE */
	{ JBC_BIT_DESC(MB_PER,	jbc_merge,	jbc_merge) },
	{ JBC_BIT_DESC(MB_PEW,	jbc_merge,	jbc_merge) },

	/* JBC Jbusint IN */
	{ JBC_BIT_DESC(UE_ASYN,	panic,		jbc_in) },
	{ JBC_BIT_DESC(CE_ASYN,	no_error,	jbc_in) },
	{ JBC_BIT_DESC(JTE,	panic,		jbc_in) },
	{ JBC_BIT_DESC(JBE,	panic,		jbc_in) },
	{ JBC_BIT_DESC(JUE,	panic,		jbc_in) },
	{ JBC_BIT_DESC(ICISE,	panic,		jbc_in) },
	{ JBC_BIT_DESC(WR_DPE,	jbc_jbusint_in,	jbc_in) },
	{ JBC_BIT_DESC(RD_DPE,	jbc_jbusint_in,	jbc_in) },
	{ JBC_BIT_DESC(ILL_BMW,	panic,		jbc_in) },
	{ JBC_BIT_DESC(ILL_BMR,	panic,		jbc_in) },
	{ JBC_BIT_DESC(BJC,	panic,		jbc_in) },

	/* JBC Jbusint Out */
	{ JBC_BIT_DESC(IJP,	panic,		jbc_out) },

	/*
	 * JBC Dmcint ODCD
	 *
	 * Error bits which can be set via a bad PCItool access go through
	 * jbc_safe_acc instead.
	 */
	{ JBC_BIT_DESC(PIO_UNMAP_RD,	jbc_safe_acc,		jbc_odcd) },
	{ JBC_BIT_DESC(ILL_ACC_RD,	jbc_safe_acc,		jbc_odcd) },
	{ JBC_BIT_DESC(PIO_UNMAP,	jbc_safe_acc,		jbc_odcd) },
	{ JBC_BIT_DESC(PIO_DPE,		jbc_dmcint_odcd,	jbc_odcd) },
	{ JBC_BIT_DESC(PIO_CPE,		hw_reset,		jbc_odcd) },
	{ JBC_BIT_DESC(ILL_ACC,		jbc_safe_acc,		jbc_odcd) },

	/* JBC Dmcint IDC */
	{ JBC_BIT_DESC(UNSOL_RD,	no_panic,	jbc_idc) },
	{ JBC_BIT_DESC(UNSOL_INTR,	no_panic,	jbc_idc) },

	/* JBC CSR */
	{ JBC_BIT_DESC(EBUS_TO,		panic,		jbc_csr) }
};

#define	px_err_jbc_keys \
	(sizeof (px_err_jbc_tbl)) / (sizeof (px_err_bit_desc_t))

/*
 * UBC error bit table
 */
#define	UBC_BIT_DESC(bit, hdl, erpt) \
	UBC_INTERRUPT_STATUS_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_UBC_CLASS(bit) }, \
	{ UBC_INTERRUPT_STATUS_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_UBC_CLASS(bit)
px_err_bit_desc_t px_err_ubc_tbl[] = {
	/* UBC FATAL  */
	{ UBC_BIT_DESC(DMARDUEA,	no_panic,	ubc_fatal) },
	{ UBC_BIT_DESC(DMAWTUEA,	panic,		ubc_fatal) },
	{ UBC_BIT_DESC(MEMRDAXA,	panic,		ubc_fatal) },
	{ UBC_BIT_DESC(MEMWTAXA,	panic,		ubc_fatal) },
	{ UBC_BIT_DESC(DMARDUEB,	no_panic,	ubc_fatal) },
	{ UBC_BIT_DESC(DMAWTUEB,	panic,		ubc_fatal) },
	{ UBC_BIT_DESC(MEMRDAXB,	panic,		ubc_fatal) },
	{ UBC_BIT_DESC(MEMWTAXB,	panic,		ubc_fatal) },
	{ UBC_BIT_DESC(PIOWTUE,		panic,		ubc_fatal) },
	{ UBC_BIT_DESC(PIOWBEUE,	panic,		ubc_fatal) },
	{ UBC_BIT_DESC(PIORBEUE,	panic,		ubc_fatal) }
};

#define	px_err_ubc_keys \
	(sizeof (px_err_ubc_tbl)) / (sizeof (px_err_bit_desc_t))


char *ubc_class_eid_qualifier[] = {
	"-mem",
	"-channel",
	"-cpu",
	"-path"
};


/*
 * DMC error bit tables
 */
#define	IMU_BIT_DESC(bit, hdl, erpt) \
	IMU_INTERRUPT_STATUS_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_DMC_CLASS(bit) }, \
	{ IMU_INTERRUPT_STATUS_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_DMC_CLASS(bit)
px_err_bit_desc_t px_err_imu_tbl[] = {
	/* DMC IMU RDS */
	{ IMU_BIT_DESC(MSI_MAL_ERR,		panic,		imu_rds) },
	{ IMU_BIT_DESC(MSI_PAR_ERR,		panic,		imu_rds) },
	{ IMU_BIT_DESC(PMEACK_MES_NOT_EN,	panic,		imu_rds) },
	{ IMU_BIT_DESC(PMPME_MES_NOT_EN,	panic,		imu_rds) },
	{ IMU_BIT_DESC(FATAL_MES_NOT_EN,	panic,		imu_rds) },
	{ IMU_BIT_DESC(NONFATAL_MES_NOT_EN,	panic,		imu_rds) },
	{ IMU_BIT_DESC(COR_MES_NOT_EN,		panic,		imu_rds) },
	{ IMU_BIT_DESC(MSI_NOT_EN,		panic,		imu_rds) },

	/* DMC IMU SCS */
	{ IMU_BIT_DESC(EQ_NOT_EN,		panic,		imu_scs) },

	/* DMC IMU */
	{ IMU_BIT_DESC(EQ_OVER,			imu_eq_ovfl,	imu) }
};

#define	px_err_imu_keys (sizeof (px_err_imu_tbl)) / (sizeof (px_err_bit_desc_t))

/* mmu errors */
#define	MMU_BIT_DESC(bit, hdl, erpt) \
	MMU_INTERRUPT_STATUS_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_DMC_CLASS(bit) }, \
	{ MMU_INTERRUPT_STATUS_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_DMC_CLASS(bit)
px_err_bit_desc_t px_err_mmu_tbl[] = {
	/* DMC MMU TFAR/TFSR */
	{ MMU_BIT_DESC(BYP_ERR,		mmu_rbne,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(BYP_OOR,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TRN_ERR,		panic,		mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TRN_OOR,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TTE_INV,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TTE_PRT,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TTC_DPE,		mmu_parity,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TBW_DME,		panic,		mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TBW_UDE,		panic,		mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TBW_ERR,		panic,		mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TBW_DPE,		mmu_parity,	mmu_tfar_tfsr) },

	/* DMC MMU */
	{ MMU_BIT_DESC(TTC_CAE,		panic,		mmu) }
};
#define	px_err_mmu_keys (sizeof (px_err_mmu_tbl)) / (sizeof (px_err_bit_desc_t))


/*
 * PEC error bit tables
 */
#define	ILU_BIT_DESC(bit, hdl, erpt) \
	ILU_INTERRUPT_STATUS_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit) }, \
	{ ILU_INTERRUPT_STATUS_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit)
px_err_bit_desc_t px_err_ilu_tbl[] = {
	/* PEC ILU none */
	{ ILU_BIT_DESC(IHB_PE,		panic,		pec_ilu) }
};
#define	px_err_ilu_keys \
	(sizeof (px_err_ilu_tbl)) / (sizeof (px_err_bit_desc_t))

/*
 * PEC UE errors implementation is incomplete pending PCIE generic
 * fabric rules.  Must handle both PRIMARY and SECONDARY errors.
 */
/* pec ue errors */
#define	TLU_UC_BIT_DESC(bit, hdl, erpt) \
	TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit) }, \
	{ TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit)
#define	TLU_UC_OB_BIT_DESC(bit, hdl, erpt) \
	TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_OB_CLASS(bit) }, \
	{ TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit)
px_err_bit_desc_t px_err_tlu_ue_tbl[] = {
	/* PCI-E Receive Uncorrectable Errors */
	{ TLU_UC_BIT_DESC(UR,		pciex_ue,	pciex_rx_ue) },
	{ TLU_UC_BIT_DESC(UC,		pciex_ue,	pciex_rx_ue) },

	/* PCI-E Transmit Uncorrectable Errors */
	{ TLU_UC_OB_BIT_DESC(ECRC,	pciex_ue,	pciex_rx_ue) },
	{ TLU_UC_BIT_DESC(CTO,		pciex_ue,	pciex_tx_ue) },
	{ TLU_UC_BIT_DESC(ROF,		pciex_ue,	pciex_tx_ue) },

	/* PCI-E Rx/Tx Uncorrectable Errors */
	{ TLU_UC_BIT_DESC(MFP,		pciex_ue,	pciex_rx_tx_ue) },
	{ TLU_UC_BIT_DESC(PP,		pciex_ue,	pciex_rx_tx_ue) },

	/* Other PCI-E Uncorrectable Errors */
	{ TLU_UC_BIT_DESC(FCP,		pciex_ue,	pciex_ue) },
	{ TLU_UC_BIT_DESC(DLP,		pciex_ue,	pciex_ue) },
	{ TLU_UC_BIT_DESC(TE,		pciex_ue,	pciex_ue) },

	/* Not used */
	{ TLU_UC_BIT_DESC(CA,		pciex_ue,	do_not) }
};
#define	px_err_tlu_ue_keys \
	(sizeof (px_err_tlu_ue_tbl)) / (sizeof (px_err_bit_desc_t))


/*
 * PEC CE errors implementation is incomplete pending PCIE generic
 * fabric rules.
 */
/* pec ce errors */
#define	TLU_CE_BIT_DESC(bit, hdl, erpt) \
	TLU_CORRECTABLE_ERROR_STATUS_CLEAR_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit) }, \
	{ TLU_CORRECTABLE_ERROR_STATUS_CLEAR_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit)
px_err_bit_desc_t px_err_tlu_ce_tbl[] = {
	/* PCI-E Correctable Errors */
	{ TLU_CE_BIT_DESC(RTO,		pciex_ce,	pciex_ce) },
	{ TLU_CE_BIT_DESC(RNR,		pciex_ce,	pciex_ce) },
	{ TLU_CE_BIT_DESC(BDP,		pciex_ce,	pciex_ce) },
	{ TLU_CE_BIT_DESC(BTP,		pciex_ce,	pciex_ce) },
	{ TLU_CE_BIT_DESC(RE,		pciex_ce,	pciex_ce) }
};
#define	px_err_tlu_ce_keys \
	(sizeof (px_err_tlu_ce_tbl)) / (sizeof (px_err_bit_desc_t))


/* pec oe errors */
#define	TLU_OE_BIT_DESC(bit, hdl, erpt) \
	TLU_OTHER_EVENT_STATUS_CLEAR_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit) }, \
	{ TLU_OTHER_EVENT_STATUS_CLEAR_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_CLASS(bit)
#define	TLU_OE_OB_BIT_DESC(bit, hdl, erpt) \
	TLU_OTHER_EVENT_STATUS_CLEAR_ ## bit ## _P, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_OB_CLASS(bit) }, \
	{ TLU_OTHER_EVENT_STATUS_CLEAR_ ## bit ## _S, \
	0, \
	PX_ERR_BIT_HANDLE(hdl), \
	PX_ERPT_SEND(erpt), \
	PX_ERR_PEC_OB_CLASS(bit)
px_err_bit_desc_t px_err_tlu_oe_tbl[] = {
	/* TLU Other Event Status (receive only) */
	{ TLU_OE_BIT_DESC(MRC,		hw_reset,	pciex_rx_oe) },

	/* TLU Other Event Status (rx + tx) */
	{ TLU_OE_BIT_DESC(WUC,		wuc_ruc,	pciex_rx_tx_oe) },
	{ TLU_OE_BIT_DESC(RUC,		wuc_ruc,	pciex_rx_tx_oe) },
	{ TLU_OE_BIT_DESC(CRS,		no_panic,	pciex_rx_tx_oe) },

	/* TLU Other Event */
	{ TLU_OE_BIT_DESC(IIP,		panic,		pciex_oe) },
	{ TLU_OE_BIT_DESC(EDP,		panic,		pciex_oe) },
	{ TLU_OE_BIT_DESC(EHP,		panic,		pciex_oe) },
	{ TLU_OE_OB_BIT_DESC(TLUEITMO,	panic,		pciex_oe) },
	{ TLU_OE_BIT_DESC(LIN,		no_panic,	pciex_oe) },
	{ TLU_OE_BIT_DESC(LRS,		no_panic,	pciex_oe) },
	{ TLU_OE_BIT_DESC(LDN,		tlu_ldn,	pciex_oe) },
	{ TLU_OE_BIT_DESC(LUP,		tlu_lup,	pciex_oe) },
	{ TLU_OE_BIT_DESC(ERU,		panic,		pciex_oe) },
	{ TLU_OE_BIT_DESC(ERO,		panic,		pciex_oe) },
	{ TLU_OE_BIT_DESC(EMP,		panic,		pciex_oe) },
	{ TLU_OE_BIT_DESC(EPE,		panic,		pciex_oe) },
	{ TLU_OE_BIT_DESC(ERP,		panic,		pciex_oe) },
	{ TLU_OE_BIT_DESC(EIP,		panic,		pciex_oe) }
};

#define	px_err_tlu_oe_keys \
	(sizeof (px_err_tlu_oe_tbl)) / (sizeof (px_err_bit_desc_t))


/*
 * All the following tables below are for LPU Interrupts.  These interrupts
 * are *NOT* error interrupts, but event status interrupts.
 *
 * These events are probably of most interest to:
 * o Hotplug
 * o Power Management
 * o etc...
 *
 * There are also a few events that would be interresting for FMA.
 * Again none of the regiseters below state that an error has occured
 * or that data has been lost.  If anything, they give status that an
 * error is *about* to occur.  examples
 * o INT_SKP_ERR - indicates clock between fire and child is too far
 *		   off and is most unlikely able to compensate
 * o INT_TX_PAR_ERR - A parity error occured in ONE lane.  This is
 *		      HW recoverable, but will like end up as a future
 *		      fabric error as well.
 *
 * For now, we don't care about any of these errors and should be ignore,
 * but cleared.
 */

/* LPU Link Interrupt Table */
#define	LPUL_BIT_DESC(bit, hdl, erpt) \
	LPU_LINK_LAYER_INTERRUPT_AND_STATUS_INT_ ## bit, \
	0, \
	NULL, \
	NULL, \
	""
px_err_bit_desc_t px_err_lpul_tbl[] = {
	{ LPUL_BIT_DESC(LINK_ERR_ACT,	NULL,		NULL) }
};
#define	px_err_lpul_keys \
	(sizeof (px_err_lpul_tbl)) / (sizeof (px_err_bit_desc_t))

/* LPU Physical Interrupt Table */
#define	LPUP_BIT_DESC(bit, hdl, erpt) \
	LPU_PHY_LAYER_INTERRUPT_AND_STATUS_INT_ ## bit, \
	0, \
	NULL, \
	NULL, \
	""
px_err_bit_desc_t px_err_lpup_tbl[] = {
	{ LPUP_BIT_DESC(PHY_LAYER_ERR,	NULL,		NULL) }
};
#define	px_err_lpup_keys \
	(sizeof (px_err_lpup_tbl)) / (sizeof (px_err_bit_desc_t))

/* LPU Receive Interrupt Table */
#define	LPUR_BIT_DESC(bit, hdl, erpt) \
	LPU_RECEIVE_PHY_INTERRUPT_AND_STATUS_INT_ ## bit, \
	0, \
	NULL, \
	NULL, \
	""
px_err_bit_desc_t px_err_lpur_tbl[] = {
	{ LPUR_BIT_DESC(RCV_PHY,	NULL,		NULL) }
};
#define	px_err_lpur_keys \
	(sizeof (px_err_lpur_tbl)) / (sizeof (px_err_bit_desc_t))

/* LPU Transmit Interrupt Table */
#define	LPUX_BIT_DESC(bit, hdl, erpt) \
	LPU_TRANSMIT_PHY_INTERRUPT_AND_STATUS_INT_ ## bit, \
	0, \
	NULL, \
	NULL, \
	""
px_err_bit_desc_t px_err_lpux_tbl[] = {
	{ LPUX_BIT_DESC(UNMSK,		NULL,		NULL) }
};
#define	px_err_lpux_keys \
	(sizeof (px_err_lpux_tbl)) / (sizeof (px_err_bit_desc_t))

/* LPU LTSSM Interrupt Table */
#define	LPUS_BIT_DESC(bit, hdl, erpt) \
	LPU_LTSSM_INTERRUPT_AND_STATUS_INT_ ## bit, \
	0, \
	NULL, \
	NULL, \
	""
px_err_bit_desc_t px_err_lpus_tbl[] = {
	{ LPUS_BIT_DESC(ANY,		NULL,		NULL) }
};
#define	px_err_lpus_keys \
	(sizeof (px_err_lpus_tbl)) / (sizeof (px_err_bit_desc_t))

/* LPU Gigablaze Glue Interrupt Table */
#define	LPUG_BIT_DESC(bit, hdl, erpt) \
	LPU_GIGABLAZE_GLUE_INTERRUPT_AND_STATUS_INT_ ## bit, \
	0, \
	NULL, \
	NULL, \
	""
px_err_bit_desc_t px_err_lpug_tbl[] = {
	{ LPUG_BIT_DESC(GLOBL_UNMSK,	NULL,		NULL) }
};
#define	px_err_lpug_keys \
	(sizeof (px_err_lpug_tbl)) / (sizeof (px_err_bit_desc_t))


/* Mask and Tables */
#define	MnT6X(pre) \
	&px_ ## pre ## _intr_mask, \
	&px_ ## pre ## _log_mask, \
	&px_ ## pre ## _count_mask, \
	px_err_ ## pre ## _tbl, \
	px_err_ ## pre ## _keys, \
	PX_REG_XBC, \
	0

#define	MnT6(pre) \
	&px_ ## pre ## _intr_mask, \
	&px_ ## pre ## _log_mask, \
	&px_ ## pre ## _count_mask, \
	px_err_ ## pre ## _tbl, \
	px_err_ ## pre ## _keys, \
	PX_REG_CSR, \
	0

/* LPU Registers Addresses */
#define	LR4(pre) \
	NULL, \
	LPU_ ## pre ## _INTERRUPT_MASK, \
	LPU_ ## pre ## _INTERRUPT_AND_STATUS, \
	LPU_ ## pre ## _INTERRUPT_AND_STATUS

/* LPU Registers Addresses with Irregularities */
#define	LR4_FIXME(pre) \
	NULL, \
	LPU_ ## pre ## _INTERRUPT_MASK, \
	LPU_ ## pre ## _LAYER_INTERRUPT_AND_STATUS, \
	LPU_ ## pre ## _LAYER_INTERRUPT_AND_STATUS

/* TLU Registers Addresses */
#define	TR4(pre) \
	TLU_ ## pre ## _LOG_ENABLE, \
	TLU_ ## pre ## _INTERRUPT_ENABLE, \
	TLU_ ## pre ## _INTERRUPT_STATUS, \
	TLU_ ## pre ## _STATUS_CLEAR

/* Registers Addresses for JBC, UBC, MMU, IMU and ILU */
#define	R4(pre) \
	pre ## _ERROR_LOG_ENABLE, \
	pre ## _INTERRUPT_ENABLE, \
	pre ## _INTERRUPT_STATUS, \
	pre ## _ERROR_STATUS_CLEAR

/* Bits in chip_mask, set according to type. */
#define	CHP_O	BITMASK(PX_CHIP_OBERON)
#define	CHP_F	BITMASK(PX_CHIP_FIRE)
#define	CHP_FO	(CHP_F | CHP_O)

/*
 * Register error handling tables.
 * The ID Field (first field) is identified by an enum px_err_id_t.
 * It is located in px_err.h
 */
static const
px_err_reg_desc_t px_err_reg_tbl[] = {
	{ CHP_F,  MnT6X(jbc),	R4(JBC),		  "JBC Error"},
	{ CHP_O,  MnT6X(ubc),	R4(UBC),		  "UBC Error"},
	{ CHP_FO, MnT6(mmu),	R4(MMU),		  "MMU Error"},
	{ CHP_FO, MnT6(imu),	R4(IMU),		  "IMU Error"},
	{ CHP_FO, MnT6(tlu_ue),	TR4(UNCORRECTABLE_ERROR), "TLU UE"},
	{ CHP_FO, MnT6(tlu_ce),	TR4(CORRECTABLE_ERROR),	  "TLU CE"},
	{ CHP_FO, MnT6(tlu_oe),	TR4(OTHER_EVENT),	  "TLU OE"},
	{ CHP_FO, MnT6(ilu),	R4(ILU),		  "ILU Error"},
	{ CHP_F,  MnT6(lpul),	LR4(LINK_LAYER),	  "LPU Link Layer"},
	{ CHP_F,  MnT6(lpup),	LR4_FIXME(PHY),		  "LPU Phy Layer"},
	{ CHP_F,  MnT6(lpur),	LR4(RECEIVE_PHY),	  "LPU RX Phy Layer"},
	{ CHP_F,  MnT6(lpux),	LR4(TRANSMIT_PHY),	  "LPU TX Phy Layer"},
	{ CHP_F,  MnT6(lpus),	LR4(LTSSM),		  "LPU LTSSM"},
	{ CHP_F,  MnT6(lpug),	LR4(GIGABLAZE_GLUE),	  "LPU GigaBlaze Glue"},
};

#define	PX_ERR_REG_KEYS	(sizeof (px_err_reg_tbl)) / (sizeof (px_err_reg_tbl[0]))

typedef struct px_err_ss {
	uint64_t err_status[PX_ERR_REG_KEYS];
} px_err_ss_t;

static void px_err_snapshot(px_t *px_p, px_err_ss_t *ss, int block);
static int  px_err_erpt_and_clr(px_t *px_p, ddi_fm_error_t *derr,
    px_err_ss_t *ss);
static int  px_err_check_severity(px_t *px_p, ddi_fm_error_t *derr,
    int err, int caller);

/*
 * px_err_cb_intr:
 * Interrupt handler for the JBC/UBC block.
 * o lock
 * o create derr
 * o px_err_cmn_intr
 * o unlock
 * o handle error: fatal? fm_panic() : return INTR_CLAIMED)
 */
uint_t
px_err_cb_intr(caddr_t arg)
{
	px_fault_t	*px_fault_p = (px_fault_t *)arg;
	dev_info_t	*rpdip = px_fault_p->px_fh_dip;
	px_t		*px_p = DIP_TO_STATE(rpdip);
	int		err;
	ddi_fm_error_t	derr;

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;

	mutex_enter(&px_p->px_fm_mutex);
	px_p->px_fm_mutex_owner = curthread;

	err = px_err_cmn_intr(px_p, &derr, PX_INTR_CALL, PX_FM_BLOCK_HOST);
	(void) px_lib_intr_setstate(rpdip, px_fault_p->px_fh_sysino,
	    INTR_IDLE_STATE);

	px_p->px_fm_mutex_owner = NULL;
	mutex_exit(&px_p->px_fm_mutex);

	px_err_panic(err, PX_HB, PX_NO_ERROR);

	return (DDI_INTR_CLAIMED);
}

/*
 * px_err_dmc_pec_intr:
 * Interrupt handler for the DMC/PEC block.
 * o lock
 * o create derr
 * o px_err_cmn_intr(leaf, with out cb)
 * o pcie_scan_fabric (leaf)
 * o unlock
 * o handle error: fatal? fm_panic() : return INTR_CLAIMED)
 */
uint_t
px_err_dmc_pec_intr(caddr_t arg)
{
	px_fault_t	*px_fault_p = (px_fault_t *)arg;
	dev_info_t	*rpdip = px_fault_p->px_fh_dip;
	px_t		*px_p = DIP_TO_STATE(rpdip);
	int		rc_err, fab_err = PF_NO_PANIC;
	ddi_fm_error_t	derr;

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;

	mutex_enter(&px_p->px_fm_mutex);
	px_p->px_fm_mutex_owner = curthread;

	/* send ereport/handle/clear fire registers */
	rc_err = px_err_cmn_intr(px_p, &derr, PX_INTR_CALL, PX_FM_BLOCK_PCIE);

	/* Check all child devices for errors */
	if (!px_lib_is_in_drain_state(px_p)) {
		fab_err = pf_scan_fabric(rpdip, &derr, px_p->px_dq_p,
		    &px_p->px_dq_tail);
	}

	/* Set the interrupt state to idle */
	(void) px_lib_intr_setstate(rpdip, px_fault_p->px_fh_sysino,
	    INTR_IDLE_STATE);

	px_p->px_fm_mutex_owner = NULL;
	mutex_exit(&px_p->px_fm_mutex);

	px_err_panic(rc_err, PX_RC, fab_err);

	return (DDI_INTR_CLAIMED);
}

/*
 * Proper csr_base is responsibility of the caller. (Called from px_lib_dev_init
 * via px_err_reg_setup_all for pcie error registers;  called from
 * px_cb_add_intr for jbc/ubc from px_cb_attach.)
 *
 * Note: reg_id is passed in instead of reg_desc since this function is called
 * from px_lib4u.c, which doesn't know about the structure of the table.
 */
void
px_err_reg_enable(px_err_id_t reg_id, caddr_t csr_base)
{
	const px_err_reg_desc_t	*reg_desc_p = &px_err_reg_tbl[reg_id];
	uint64_t 		intr_mask = *reg_desc_p->intr_mask_p;
	uint64_t 		log_mask = *reg_desc_p->log_mask_p;

	/* Enable logs if it exists */
	if (reg_desc_p->log_addr != NULL)
		CSR_XS(csr_base, reg_desc_p->log_addr, log_mask);

	/*
	 * For readability you in code you set 1 to enable an interrupt.
	 * But in Fire it's backwards.  You set 1 to *disable* an intr.
	 * Reverse the user tunable intr mask field.
	 *
	 * Disable All Errors
	 * Clear All Errors
	 * Enable Errors
	 */
	CSR_XS(csr_base, reg_desc_p->enable_addr, 0);
	CSR_XS(csr_base, reg_desc_p->clear_addr, -1);
	CSR_XS(csr_base, reg_desc_p->enable_addr, intr_mask);
	DBG(DBG_ATTACH, NULL, "%s Mask: 0x%llx\n", reg_desc_p->msg,
	    CSR_XR(csr_base, reg_desc_p->enable_addr));
	DBG(DBG_ATTACH, NULL, "%s Status: 0x%llx\n", reg_desc_p->msg,
	    CSR_XR(csr_base, reg_desc_p->status_addr));
	DBG(DBG_ATTACH, NULL, "%s Clear: 0x%llx\n", reg_desc_p->msg,
	    CSR_XR(csr_base, reg_desc_p->clear_addr));
	if (reg_desc_p->log_addr != NULL) {
		DBG(DBG_ATTACH, NULL, "%s Log: 0x%llx\n", reg_desc_p->msg,
		    CSR_XR(csr_base, reg_desc_p->log_addr));
	}
}

void
px_err_reg_disable(px_err_id_t reg_id, caddr_t csr_base)
{
	const px_err_reg_desc_t	*reg_desc_p = &px_err_reg_tbl[reg_id];
	uint64_t		val = (reg_id >= PX_ERR_LPU_LINK) ? -1 : 0;

	if (reg_desc_p->log_addr != NULL)
		CSR_XS(csr_base, reg_desc_p->log_addr, val);
	CSR_XS(csr_base, reg_desc_p->enable_addr, val);
}

/*
 * Set up pcie error registers.
 */
void
px_err_reg_setup_pcie(uint8_t chip_mask, caddr_t csr_base, boolean_t enable)
{
	px_err_id_t		reg_id;
	const px_err_reg_desc_t	*reg_desc_p;
	void (*px_err_reg_func)(px_err_id_t, caddr_t);

	/*
	 * JBC or XBC are enabled during adding of common block interrupts,
	 * not done here.
	 */
	px_err_reg_func = (enable ? px_err_reg_enable : px_err_reg_disable);
	for (reg_id = 0; reg_id < PX_ERR_REG_KEYS; reg_id++) {
		reg_desc_p = &px_err_reg_tbl[reg_id];
		if ((reg_desc_p->chip_mask & chip_mask) &&
		    (reg_desc_p->reg_bank == PX_REG_CSR))
			px_err_reg_func(reg_id, csr_base);
	}
}

/*
 * px_err_cmn_intr:
 * Common function called by trap, mondo and fabric intr.
 * o Snap shot current fire registers
 * o check for safe access
 * o send ereport and clear snap shot registers
 * o create and queue RC info for later use in fabric scan.
 *   o RUC/WUC, PTLP, MMU Errors(CA), UR
 * o check severity of snap shot registers
 *
 * @param px_p		leaf in which to check access
 * @param derr		fm err data structure to be updated
 * @param caller	PX_TRAP_CALL | PX_INTR_CALL
 * @param block		PX_FM_BLOCK_HOST | PX_FM_BLOCK_PCIE | PX_FM_BLOCK_ALL
 * @return err		PX_NO_PANIC | PX_PANIC | PX_HW_RESET | PX_PROTECTED
 */
int
px_err_cmn_intr(px_t *px_p, ddi_fm_error_t *derr, int caller, int block)
{
	px_err_ss_t		ss = {0};
	int			err;

	ASSERT(MUTEX_HELD(&px_p->px_fm_mutex));

	/* check for safe access */
	px_err_safeacc_check(px_p, derr);

	/* snap shot the current fire registers */
	px_err_snapshot(px_p, &ss, block);

	/* send ereports/handle/clear registers */
	err = px_err_erpt_and_clr(px_p, derr, &ss);

	/* check for error severity */
	err = px_err_check_severity(px_p, derr, err, caller);

	/* Mark the On Trap Handle if an error occured */
	if (err != PX_NO_ERROR) {
		px_pec_t	*pec_p = px_p->px_pec_p;
		on_trap_data_t	*otd = pec_p->pec_ontrap_data;

		if ((otd != NULL) && (otd->ot_prot & OT_DATA_ACCESS))
			otd->ot_trap |= OT_DATA_ACCESS;
	}

	return (err);
}

/*
 * Static function
 */

/*
 * px_err_snapshot:
 * Take a current snap shot of all the fire error registers.  This includes
 * JBC/UBC, DMC, and PEC depending on the block flag
 *
 * @param px_p		leaf in which to take the snap shot.
 * @param ss		pre-allocated memory to store the snap shot.
 * @param chk_cb	boolean on whether to store jbc/ubc register.
 */
static void
px_err_snapshot(px_t *px_p, px_err_ss_t *ss_p, int block)
{
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t	xbc_csr_base = (caddr_t)pxu_p->px_address[PX_REG_XBC];
	caddr_t	pec_csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];
	caddr_t	csr_base;
	uint8_t chip_mask = 1 << PX_CHIP_TYPE(pxu_p);
	const px_err_reg_desc_t *reg_desc_p = px_err_reg_tbl;
	px_err_id_t reg_id;

	for (reg_id = 0; reg_id < PX_ERR_REG_KEYS; reg_id++, reg_desc_p++) {
		if (!(reg_desc_p->chip_mask & chip_mask))
			continue;

		if ((block & PX_FM_BLOCK_HOST) &&
		    (reg_desc_p->reg_bank == PX_REG_XBC))
			csr_base = xbc_csr_base;
		else if ((block & PX_FM_BLOCK_PCIE) &&
		    (reg_desc_p->reg_bank == PX_REG_CSR))
			csr_base = pec_csr_base;
		else {
			ss_p->err_status[reg_id] = 0;
			continue;
		}

		ss_p->err_status[reg_id] = CSR_XR(csr_base,
		    reg_desc_p->status_addr);
	}
}

/*
 * px_err_erpt_and_clr:
 * This function does the following thing to all the fire registers based
 * on an earlier snap shot.
 * o Send ereport
 * o Handle the error
 * o Clear the error
 *
 * @param px_p		leaf in which to take the snap shot.
 * @param derr		fm err in which the ereport is to be based on
 * @param ss_p		pre-allocated memory to store the snap shot.
 */
static int
px_err_erpt_and_clr(px_t *px_p, ddi_fm_error_t *derr, px_err_ss_t *ss_p)
{
	dev_info_t		*rpdip = px_p->px_dip;
	pxu_t			*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t			csr_base;
	const px_err_reg_desc_t	*err_reg_tbl;
	px_err_bit_desc_t	*err_bit_tbl;
	px_err_bit_desc_t	*err_bit_desc;

	uint64_t		*count_mask;
	uint64_t		clear_addr;
	uint64_t		ss_reg;

	int			(*err_handler)();
	int			(*erpt_handler)();
	int			reg_id, key;
	int			err = PX_NO_ERROR;
	int			biterr = 0;

	ASSERT(MUTEX_HELD(&px_p->px_fm_mutex));

	/* send erport/handle/clear JBC errors */
	for (reg_id = 0; reg_id < PX_ERR_REG_KEYS; reg_id++) {
		/* Get the correct register description table */
		err_reg_tbl = &px_err_reg_tbl[reg_id];

		/* Only look at enabled groups. */
		if (!(BIT_TST(err_reg_tbl->chip_mask, PX_CHIP_TYPE(pxu_p))))
			continue;

		/* Get the correct CSR BASE */
		csr_base = (caddr_t)pxu_p->px_address[err_reg_tbl->reg_bank];

		/* If there are no errors in this register, continue */
		ss_reg = ss_p->err_status[reg_id];
		if (!ss_reg)
			continue;

		/* Get pointers to masks and register addresses */
		count_mask = err_reg_tbl->count_mask_p;
		clear_addr = err_reg_tbl->clear_addr;

		/* Get the register BIT description table */
		err_bit_tbl = err_reg_tbl->err_bit_tbl;

		/* For each known bit in the register send erpt and handle */
		for (key = 0; key < err_reg_tbl->err_bit_keys; key++) {
			/*
			 * If the ss_reg is set for this bit,
			 * send ereport and handle
			 */
			err_bit_desc = &err_bit_tbl[key];
			if (!BIT_TST(ss_reg, err_bit_desc->bit))
				continue;

			/* Increment the counter if necessary */
			if (BIT_TST(*count_mask, err_bit_desc->bit)) {
				err_bit_desc->counter++;
			}

			/* Error Handle for this bit */
			err_handler = err_bit_desc->err_handler;
			if (err_handler) {
				biterr = err_handler(rpdip, csr_base, derr,
				    err_reg_tbl, err_bit_desc);
				err |= biterr;
			}

			/*
			 * Send the ereport if it's an UNEXPECTED err.
			 * This is the only place where PX_EXPECTED is utilized.
			 */
			erpt_handler = err_bit_desc->erpt_handler;
			if ((derr->fme_flag != DDI_FM_ERR_UNEXPECTED) ||
			    (biterr == PX_EXPECTED))
				continue;

			if (erpt_handler)
				(void) erpt_handler(rpdip, csr_base, ss_reg,
				    derr, err_bit_desc->bit,
				    err_bit_desc->class_name);
		}

		/* Clear the register and error */
		CSR_XS(csr_base, clear_addr, ss_reg);
	}

	return (err);
}

/*
 * px_err_check_severity:
 * Check the severity of the fire error based on an earlier snapshot
 *
 * @param px_p		leaf in which to take the snap shot.
 * @param derr		fm err in which the ereport is to be based on
 * @param err		fire register error status
 * @param caller	PX_TRAP_CALL | PX_INTR_CALL | PX_LIB_CALL
 */
static int
px_err_check_severity(px_t *px_p, ddi_fm_error_t *derr, int err, int caller)
{
	px_pec_t 	*pec_p = px_p->px_pec_p;
	boolean_t	is_safeacc = B_FALSE;

	/*
	 * Nothing to do if called with no error.
	 * The err could have already been set to PX_NO_PANIC, which means the
	 * system doesn't need to panic, but PEEK/POKE still failed.
	 */
	if (err == PX_NO_ERROR)
		return (err);

	/* Cautious access error handling  */
	switch (derr->fme_flag) {
	case DDI_FM_ERR_EXPECTED:
		if (caller == PX_TRAP_CALL) {
			/*
			 * for ddi_caut_get treat all events as nonfatal
			 * The trampoline will set err_ena = 0,
			 * err_status = NONFATAL.
			 */
			derr->fme_status = DDI_FM_NONFATAL;
			is_safeacc = B_TRUE;
		} else {
			/*
			 * For ddi_caut_put treat all events as nonfatal. Here
			 * we have the handle and can call ndi_fm_acc_err_set().
			 */
			derr->fme_status = DDI_FM_NONFATAL;
			ndi_fm_acc_err_set(pec_p->pec_acc_hdl, derr);
			is_safeacc = B_TRUE;
		}
		break;
	case DDI_FM_ERR_PEEK:
	case DDI_FM_ERR_POKE:
		/*
		 * For ddi_peek/poke treat all events as nonfatal.
		 */
		is_safeacc = B_TRUE;
		break;
	default:
		is_safeacc = B_FALSE;
	}

	/* re-adjust error status from safe access, forgive all errors */
	if (is_safeacc)
		return (PX_NO_PANIC);

	return (err);
}

/* predefined convenience functions */
/* ARGSUSED */
void
px_err_log_handle(dev_info_t *rpdip, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr, char *msg)
{
	DBG(DBG_ERR_INTR, rpdip,
	    "Bit %d, %s, at %s(0x%x) has occured %d times with a severity "
	    "of \"%s\"\n",
	    err_bit_descr->bit, err_bit_descr->class_name,
	    err_reg_descr->msg, err_reg_descr->status_addr,
	    err_bit_descr->counter, msg);
}

/* ARGSUSED */
int
px_err_hw_reset_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	if (px_log & PX_HW_RESET) {
		px_err_log_handle(rpdip, err_reg_descr, err_bit_descr,
		    "HW RESET");
	}

	return (PX_HW_RESET);
}

/* ARGSUSED */
int
px_err_panic_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	if (px_log & PX_PANIC) {
		px_err_log_handle(rpdip, err_reg_descr, err_bit_descr, "PANIC");
	}

	return (PX_PANIC);
}

/* ARGSUSED */
int
px_err_protected_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	if (px_log & PX_PROTECTED) {
		px_err_log_handle(rpdip, err_reg_descr, err_bit_descr,
		    "PROTECTED");
	}

	return (PX_PROTECTED);
}

/* ARGSUSED */
int
px_err_no_panic_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	if (px_log & PX_NO_PANIC) {
		px_err_log_handle(rpdip, err_reg_descr, err_bit_descr,
		    "NO PANIC");
	}

	return (PX_NO_PANIC);
}

/* ARGSUSED */
int
px_err_no_error_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	if (px_log & PX_NO_ERROR) {
		px_err_log_handle(rpdip, err_reg_descr, err_bit_descr,
		    "NO ERROR");
	}

	return (PX_NO_ERROR);
}

/* ARGSUSED */
PX_ERPT_SEND_DEC(do_not)
{
	return (PX_NO_ERROR);
}

/*
 * Search the px_cb_list_t embedded in the px_cb_t for the
 * px_t of the specified Leaf (leaf_id).  Return its associated dip.
 */
static dev_info_t *
px_err_search_cb(px_cb_t *px_cb_p, uint_t leaf_id)
{
	int		i;
	px_cb_list_t	*pxl_elemp;

	for (i = px_cb_p->attachcnt, pxl_elemp = px_cb_p->pxl; i > 0;
	    i--, pxl_elemp = pxl_elemp->next) {
		if ((((pxu_t *)pxl_elemp->pxp->px_plat_p)->portid &
		    OBERON_PORT_ID_LEAF_MASK) == leaf_id) {
			return (pxl_elemp->pxp->px_dip);
		}
	}
	return (NULL);
}

/* UBC FATAL - see io erpt doc, section 1.1 */
/* ARGSUSED */
PX_ERPT_SEND_DEC(ubc_fatal)
{
	char		buf[FM_MAX_CLASS];
	uint64_t	memory_ue_log, marked;
	char		unum[FM_MAX_CLASS];
	int		unum_length;
	uint64_t	device_id = 0;
	uint8_t		cpu_version = 0;
	nvlist_t	*resource = NULL;
	uint64_t	ubc_intr_status;
	px_t		*px_p;
	px_cb_t		*px_cb_p;
	dev_info_t	*actual_dip;

	unum[0] = '\0';
	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);

	memory_ue_log = CSR_XR(csr_base, UBC_MEMORY_UE_LOG);
	marked = (memory_ue_log >> UBC_MEMORY_UE_LOG_MARKED) &
	    UBC_MEMORY_UE_LOG_MARKED_MASK;

	if ((strstr(class_name, "ubc.piowtue") != NULL) ||
	    (strstr(class_name, "ubc.piowbeue") != NULL) ||
	    (strstr(class_name, "ubc.piorbeue") != NULL) ||
	    (strstr(class_name, "ubc.dmarduea") != NULL) ||
	    (strstr(class_name, "ubc.dmardueb") != NULL)) {
		int eid = (memory_ue_log >> UBC_MEMORY_UE_LOG_EID) &
		    UBC_MEMORY_UE_LOG_EID_MASK;
		(void) strncat(buf, ubc_class_eid_qualifier[eid],
		    FM_MAX_CLASS);

		if (eid == UBC_EID_MEM) {
			uint64_t phys_addr = memory_ue_log &
			    MMU_OBERON_PADDR_MASK;
			uint64_t offset = (uint64_t)-1;

			resource = fm_nvlist_create(NULL);
			if (&plat_get_mem_unum) {
				if ((plat_get_mem_unum(0,
				    phys_addr, 0, B_TRUE, 0, unum,
				    FM_MAX_CLASS, &unum_length)) != 0)
					unum[0] = '\0';
			}
			fm_fmri_mem_set(resource, FM_MEM_SCHEME_VERSION,
			    NULL, unum, NULL, offset);

		} else if (eid == UBC_EID_CPU) {
			int cpuid = (marked & UBC_MARKED_MAX_CPUID_MASK);
			char sbuf[21]; /* sizeof (UINT64_MAX) + '\0' */

			resource = fm_nvlist_create(NULL);
			cpu_version = cpunodes[cpuid].version;
			device_id = cpunodes[cpuid].device_id;
			(void) snprintf(sbuf, sizeof (sbuf), "%lX",
			    device_id);
			(void) fm_fmri_cpu_set(resource,
			    FM_CPU_SCHEME_VERSION, NULL, cpuid,
			    &cpu_version, sbuf);
		}
	}

	/*
	 * For most of the errors represented in the UBC Interrupt Status
	 * register, one can compute the dip of the actual Leaf that was
	 * involved in the error.  To do this, find the px_cb_t structure
	 * that is shared between a pair of Leaves (eg, LeafA and LeafB).
	 *
	 * If any of the error bits for LeafA are set in the hardware
	 * register, search the list of px_t's rooted in the px_cb_t for
	 * the one corresponding to LeafA.  If error bits for LeafB are set,
	 * search the list for LeafB's px_t.  The px_t references its
	 * associated dip.
	 */
	px_p = DIP_TO_STATE(rpdip);
	px_cb_p = ((pxu_t *)px_p->px_plat_p)->px_cb_p;

	/* read hardware register */
	ubc_intr_status = CSR_XR(csr_base, UBC_INTERRUPT_STATUS);

	if ((ubc_intr_status & UBC_INTERRUPT_STATUS_LEAFA) != 0) {
		/* then Leaf A is involved in the error */
		actual_dip = px_err_search_cb(px_cb_p, OBERON_PORT_ID_LEAF_A);
		ASSERT(actual_dip != NULL);
		rpdip = actual_dip;
	} else if ((ubc_intr_status & UBC_INTERRUPT_STATUS_LEAFB) != 0) {
		/* then Leaf B is involved in the error */
		actual_dip = px_err_search_cb(px_cb_p, OBERON_PORT_ID_LEAF_B);
		ASSERT(actual_dip != NULL);
		rpdip = actual_dip;
	} /* else error cannot be associated with a Leaf */

	if (resource) {
		ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, B_TRUE,
		    OBERON_UBC_ELE, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_ERROR_LOG_ENABLE),
		    OBERON_UBC_IE, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_INTERRUPT_ENABLE),
		    OBERON_UBC_IS, DATA_TYPE_UINT64, ubc_intr_status,
		    OBERON_UBC_ESS, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_ERROR_STATUS_SET),
		    OBERON_UBC_MUE, DATA_TYPE_UINT64, memory_ue_log,
		    OBERON_UBC_UNUM, DATA_TYPE_STRING, unum,
		    OBERON_UBC_DID, DATA_TYPE_UINT64, device_id,
		    OBERON_UBC_CPUV, DATA_TYPE_UINT32, cpu_version,
		    OBERON_UBC_RESOURCE, DATA_TYPE_NVLIST, resource,
		    NULL);
		fm_nvlist_destroy(resource, FM_NVA_FREE);
	} else {
		ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, B_TRUE,
		    OBERON_UBC_ELE, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_ERROR_LOG_ENABLE),
		    OBERON_UBC_IE, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_INTERRUPT_ENABLE),
		    OBERON_UBC_IS, DATA_TYPE_UINT64, ubc_intr_status,
		    OBERON_UBC_ESS, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_ERROR_STATUS_SET),
		    OBERON_UBC_MUE, DATA_TYPE_UINT64, memory_ue_log,
		    OBERON_UBC_UNUM, DATA_TYPE_STRING, unum,
		    OBERON_UBC_DID, DATA_TYPE_UINT64, device_id,
		    OBERON_UBC_CPUV, DATA_TYPE_UINT32, cpu_version,
		    NULL);
	}

	return (PX_NO_PANIC);
}

/* JBC FATAL */
PX_ERPT_SEND_DEC(jbc_fatal)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_JBC_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_LOG_ENABLE),
	    FIRE_JBC_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_INTERRUPT_ENABLE),
	    FIRE_JBC_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_JBC_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_STATUS_SET),
	    FIRE_JBC_FEL1, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, FATAL_ERROR_LOG_1),
	    FIRE_JBC_FEL2, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, FATAL_ERROR_LOG_2),
	    NULL);

	return (PX_NO_PANIC);
}

/* JBC MERGE */
PX_ERPT_SEND_DEC(jbc_merge)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_JBC_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_LOG_ENABLE),
	    FIRE_JBC_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_INTERRUPT_ENABLE),
	    FIRE_JBC_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_JBC_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_STATUS_SET),
	    FIRE_JBC_MTEL, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MERGE_TRANSACTION_ERROR_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/*
 * JBC Merge buffer retryable errors:
 *    Merge buffer parity error (rd_buf): PIO or DMA
 *    Merge buffer parity error (wr_buf): PIO or DMA
 */
/* ARGSUSED */
int
px_err_jbc_merge_handle(dev_info_t *rpdip, caddr_t csr_base,
    ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
    px_err_bit_desc_t *err_bit_descr)
{
	/*
	 * Holder function to attempt error recovery.  When the features
	 * are in place, look up the address of the transaction in:
	 *
	 * paddr = CSR_XR(csr_base, MERGE_TRANSACTION_ERROR_LOG);
	 * paddr &= MERGE_TRANSACTION_ERROR_LOG_ADDRESS_MASK;
	 *
	 * If the error is a secondary error, there is no log information
	 * just panic as it is unknown which address has been affected.
	 *
	 * Remember the address is pretranslation and might be hard to look
	 * up the appropriate driver based on the PA.
	 */
	return (px_err_panic_handle(rpdip, csr_base, derr, err_reg_descr,
	    err_bit_descr));
}

/* JBC Jbusint IN */
PX_ERPT_SEND_DEC(jbc_in)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_JBC_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_LOG_ENABLE),
	    FIRE_JBC_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_INTERRUPT_ENABLE),
	    FIRE_JBC_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_JBC_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_STATUS_SET),
	    FIRE_JBC_JITEL1, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBCINT_IN_TRANSACTION_ERROR_LOG),
	    FIRE_JBC_JITEL2, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBCINT_IN_TRANSACTION_ERROR_LOG_2),
	    NULL);

	return (PX_NO_PANIC);
}

/*
 * JBC Jbusint IN retryable errors
 * Log Reg[42:0].
 *    Write Data Parity Error: PIO Writes
 *    Read Data Parity Error: DMA Reads
 */
int
px_err_jbc_jbusint_in_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	/*
	 * Holder function to attempt error recovery.  When the features
	 * are in place, look up the address of the transaction in:
	 *
	 * paddr = CSR_XR(csr_base, JBCINT_IN_TRANSACTION_ERROR_LOG);
	 * paddr &= JBCINT_IN_TRANSACTION_ERROR_LOG_ADDRESS_MASK;
	 *
	 * If the error is a secondary error, there is no log information
	 * just panic as it is unknown which address has been affected.
	 *
	 * Remember the address is pretranslation and might be hard to look
	 * up the appropriate driver based on the PA.
	 */
	return (px_err_panic_handle(rpdip, csr_base, derr, err_reg_descr,
	    err_bit_descr));
}


/* JBC Jbusint Out */
PX_ERPT_SEND_DEC(jbc_out)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_JBC_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_LOG_ENABLE),
	    FIRE_JBC_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_INTERRUPT_ENABLE),
	    FIRE_JBC_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_JBC_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_STATUS_SET),
	    FIRE_JBC_JOTEL1, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBCINT_OUT_TRANSACTION_ERROR_LOG),
	    FIRE_JBC_JOTEL2, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBCINT_OUT_TRANSACTION_ERROR_LOG_2),
	    NULL);

	return (PX_NO_PANIC);
}

/* JBC Dmcint ODCD */
PX_ERPT_SEND_DEC(jbc_odcd)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_JBC_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_LOG_ENABLE),
	    FIRE_JBC_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_INTERRUPT_ENABLE),
	    FIRE_JBC_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_JBC_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_STATUS_SET),
	    FIRE_JBC_DMC_ODCD, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, DMCINT_ODCD_ERROR_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/*
 * JBC Dmcint ODCO nonfatal errer handling -
 *    PIO data parity error: PIO
 */
/* ARGSUSED */
int
px_err_jbc_dmcint_odcd_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	/*
	 * Holder function to attempt error recovery.  When the features
	 * are in place, look up the address of the transaction in:
	 *
	 * paddr = CSR_XR(csr_base, DMCINT_ODCD_ERROR_LOG);
	 * paddr &= DMCINT_ODCD_ERROR_LOG_ADDRESS_MASK;
	 *
	 * If the error is a secondary error, there is no log information
	 * just panic as it is unknown which address has been affected.
	 *
	 * Remember the address is pretranslation and might be hard to look
	 * up the appropriate driver based on the PA.
	 */
	return (px_err_panic_handle(rpdip, csr_base, derr, err_reg_descr,
	    err_bit_descr));
}

/* Does address in DMCINT error log register match address of pcitool access? */
static boolean_t
px_jbc_pcitool_addr_match(dev_info_t *rpdip, caddr_t csr_base)
{
	px_t	*px_p = DIP_TO_STATE(rpdip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t	pcitool_addr = pxu_p->pcitool_addr;
	caddr_t errlog_addr =
	    (caddr_t)CSR_FR(csr_base, DMCINT_ODCD_ERROR_LOG, ADDRESS);

	return (pcitool_addr == errlog_addr);
}

/*
 * JBC Dmcint ODCD errer handling for errors which are forgivable during a safe
 * access.  (This will be most likely be a PCItool access.)  If not a safe
 * access context, treat like jbc_dmcint_odcd.
 *    Unmapped PIO read error: pio:read:M:nonfatal
 *    Unmapped PIO write error: pio:write:M:nonfatal
 *    Invalid PIO write to PCIe cfg/io, csr, ebus or i2c bus: pio:write:nonfatal
 *    Invalid PIO read to PCIe cfg/io, csr, ebus or i2c bus: pio:read:nonfatal
 */
/* ARGSUSED */
int
px_err_jbc_safe_acc_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	boolean_t	pri = PX_ERR_IS_PRI(err_bit_descr->bit);

	if (!pri)
		return (px_err_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
	/*
	 * Got an error which is forgivable during a PCItool access.
	 *
	 * Don't do handler check since the error may otherwise be unfairly
	 * attributed to a device.  Just return.
	 *
	 * Note: There is a hole here in that a legitimate error can come in
	 * while a PCItool access is in play and be forgiven.  This is possible
	 * though not likely.
	 */
	if ((derr->fme_flag != DDI_FM_ERR_UNEXPECTED) &&
	    (px_jbc_pcitool_addr_match(rpdip, csr_base)))
		return (px_err_protected_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));

	return (px_err_jbc_dmcint_odcd_handle(rpdip, csr_base, derr,
	    err_reg_descr, err_bit_descr));
}

/* JBC Dmcint IDC */
PX_ERPT_SEND_DEC(jbc_idc)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_JBC_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_LOG_ENABLE),
	    FIRE_JBC_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_INTERRUPT_ENABLE),
	    FIRE_JBC_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_JBC_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_STATUS_SET),
	    FIRE_JBC_DMC_IDC, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, DMCINT_IDC_ERROR_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/* JBC CSR */
PX_ERPT_SEND_DEC(jbc_csr)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_JBC_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_LOG_ENABLE),
	    FIRE_JBC_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_INTERRUPT_ENABLE),
	    FIRE_JBC_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_JBC_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, JBC_ERROR_STATUS_SET),
	    "jbc-error-reg", DATA_TYPE_UINT64,
	    CSR_XR(csr_base, CSR_ERROR_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/* DMC IMU RDS */
PX_ERPT_SEND_DEC(imu_rds)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_IMU_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_ERROR_LOG_ENABLE),
	    FIRE_IMU_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_INTERRUPT_ENABLE),
	    FIRE_IMU_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_IMU_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_ERROR_STATUS_SET),
	    FIRE_IMU_RDS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_RDS_ERROR_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/* handle EQ overflow */
/* ARGSUSED */
int
px_err_imu_eq_ovfl_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	px_t	*px_p = DIP_TO_STATE(rpdip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;
	int	err = px_err_check_eq(rpdip);

	if ((err == PX_PANIC) && (pxu_p->cpr_flag == PX_NOT_CPR)) {
		return (px_err_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
	} else {
		return (px_err_no_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
	}
}

/* DMC IMU SCS */
PX_ERPT_SEND_DEC(imu_scs)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_IMU_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_ERROR_LOG_ENABLE),
	    FIRE_IMU_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_INTERRUPT_ENABLE),
	    FIRE_IMU_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_IMU_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_ERROR_STATUS_SET),
	    FIRE_IMU_SCS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_SCS_ERROR_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/* DMC IMU */
PX_ERPT_SEND_DEC(imu)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_IMU_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_ERROR_LOG_ENABLE),
	    FIRE_IMU_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_INTERRUPT_ENABLE),
	    FIRE_IMU_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_IMU_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, IMU_ERROR_STATUS_SET),
	    NULL);

	return (PX_NO_PANIC);
}

/* DMC MMU TFAR/TFSR */
PX_ERPT_SEND_DEC(mmu_tfar_tfsr)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);
	px_t		*px_p = DIP_TO_STATE(rpdip);
	pcie_req_id_t	fault_bdf = 0;
	uint16_t	s_status = 0;

	if (pri) {
		fault_bdf = CSR_XR(csr_base, MMU_TRANSLATION_FAULT_STATUS)
		    & (MMU_TRANSLATION_FAULT_STATUS_ID_MASK <<
		    MMU_TRANSLATION_FAULT_STATUS_ID);
		s_status = PCI_STAT_S_TARG_AB;

		/* Only PIO Fault Addresses are valid, this is DMA */
		(void) px_rp_en_q(px_p, fault_bdf, NULL, s_status);
	}

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);

	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_MMU_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_ERROR_LOG_ENABLE),
	    FIRE_MMU_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_INTERRUPT_ENABLE),
	    FIRE_MMU_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_MMU_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_ERROR_STATUS_SET),
	    FIRE_MMU_TFAR, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_TRANSLATION_FAULT_ADDRESS),
	    FIRE_MMU_TFSR, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_TRANSLATION_FAULT_STATUS),
	    NULL);

	return (PX_NO_PANIC);
}

/* DMC MMU */
PX_ERPT_SEND_DEC(mmu)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_MMU_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_ERROR_LOG_ENABLE),
	    FIRE_MMU_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_INTERRUPT_ENABLE),
	    FIRE_MMU_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_MMU_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_ERROR_STATUS_SET),
	    NULL);

	return (PX_NO_PANIC);
}

/*
 * IMU function to handle all Received but Not Enabled errors.
 *
 * These errors are due to transactions modes in which the PX driver was not
 * setup to be able to do.  If possible, inform the driver that their DMA has
 * failed by marking their DMA handle as failed, but do not panic the system.
 * Most likely the address is not valid, as Fire wasn't setup to handle them in
 * the first place.
 *
 * These errors are not retryable, unless the PX mode has changed, otherwise the
 * same error will occur again.
 */
int
px_err_mmu_rbne_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	pcie_req_id_t bdf;

	if (!PX_ERR_IS_PRI(err_bit_descr->bit))
		goto done;

	bdf = (pcie_req_id_t)CSR_FR(csr_base, MMU_TRANSLATION_FAULT_STATUS, ID);
	(void) pf_hdl_lookup(rpdip, derr->fme_ena, PF_DMA_ADDR, NULL,
	    bdf);

done:
	return (px_err_no_panic_handle(rpdip, csr_base, derr, err_reg_descr,
	    err_bit_descr));
}

/*
 * IMU function to handle all invalid address errors.
 *
 * These errors are due to transactions in which the address is not recognized.
 * If possible, inform the driver that all DMAs have failed by marking their DMA
 * handles.  Fire should not panic the system, it'll be up to the driver to
 * panic.  The address logged is invalid.
 *
 * These errors are not retryable since retrying the same transaction with the
 * same invalid address will result in the same error.
 */
/* ARGSUSED */
int
px_err_mmu_tfa_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	pcie_req_id_t bdf;

	if (!PX_ERR_IS_PRI(err_bit_descr->bit))
		goto done;

	bdf = (pcie_req_id_t)CSR_FR(csr_base, MMU_TRANSLATION_FAULT_STATUS, ID);
	(void) pf_hdl_lookup(rpdip, derr->fme_ena, PF_DMA_ADDR, NULL,
	    bdf);

done:
	return (px_err_no_panic_handle(rpdip, csr_base, derr, err_reg_descr,
	    err_bit_descr));
}

/*
 * IMU function to handle normal transactions that encounter a parity error.
 *
 * These errors are due to transactions that enouter a parity error. If
 * possible, inform the driver that their DMA have failed and that they should
 * retry.  If Fire is unable to contact the leaf driver, panic the system.
 * Otherwise, it'll be up to the device to determine is this is a panicable
 * error.
 */
/* ARGSUSED */
int
px_err_mmu_parity_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	uint64_t mmu_tfa;
	pcie_req_id_t bdf;
	int status = PF_HDL_NOTFOUND;

	if (!PX_ERR_IS_PRI(err_bit_descr->bit))
		goto done;

	mmu_tfa = CSR_XR(csr_base, MMU_TRANSLATION_FAULT_ADDRESS);
	bdf = (pcie_req_id_t)CSR_FR(csr_base, MMU_TRANSLATION_FAULT_STATUS, ID);
	status = pf_hdl_lookup(rpdip, derr->fme_ena, PF_DMA_ADDR,
	    (uint32_t)mmu_tfa, bdf);

done:
	if (status == PF_HDL_NOTFOUND)
		return (px_err_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
	else
		return (px_err_no_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
}

/*
 * wuc/ruc event - Mark the handle of the failed PIO access.  Return "no_panic"
 */
/* ARGSUSED */
int
px_err_wuc_ruc_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	px_t		*px_p = DIP_TO_STATE(rpdip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t 	data;
	uint32_t	addr, hdr;
	pcie_tlp_hdr_t	*tlp;
	int		sts = PF_HDL_NOTFOUND;

	if (!PX_ERR_IS_PRI(err_bit_descr->bit))
		goto done;

	data = CSR_XR(csr_base, TLU_TRANSMIT_OTHER_EVENT_HEADER1_LOG);
	hdr = (uint32_t)(data >> 32);
	tlp = (pcie_tlp_hdr_t *)&hdr;
	data = CSR_XR(csr_base, TLU_TRANSMIT_OTHER_EVENT_HEADER2_LOG);
	addr = (uint32_t)(data >> 32);

	switch (tlp->type) {
	case PCIE_TLP_TYPE_IO:
	case PCIE_TLP_TYPE_MEM:
	case PCIE_TLP_TYPE_MEMLK:
		sts = pf_hdl_lookup(rpdip, derr->fme_ena, PF_PIO_ADDR,
		    addr, NULL);
		break;
	case PCIE_TLP_TYPE_CFG0:
	case PCIE_TLP_TYPE_CFG1:
		sts = pf_hdl_lookup(rpdip, derr->fme_ena, PF_CFG_ADDR,
		    addr, (addr >> 16));
		break;
	}

done:
	if ((sts == PF_HDL_NOTFOUND) && (pxu_p->cpr_flag == PX_NOT_CPR))
		return (px_err_protected_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));

	return (px_err_no_panic_handle(rpdip, csr_base, derr,
	    err_reg_descr, err_bit_descr));
}

/*
 * TLU LUP event - if caused by power management activity, then it is expected.
 * In all other cases, it is an error.
 */
/* ARGSUSED */
int
px_err_tlu_lup_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	px_t	*px_p = DIP_TO_STATE(rpdip);

	/*
	 * power management code is currently the only segment that sets
	 * px_lup_pending to indicate its expectation for a healthy LUP
	 * event.  For all other occasions, LUP event should be flaged as
	 * error condition.
	 */
	return ((atomic_cas_32(&px_p->px_lup_pending, 1, 0) == 0) ?
	    PX_NO_PANIC : PX_EXPECTED);
}

/*
 * TLU LDN event - if caused by power management activity, then it is expected.
 * In all other cases, it is an error.
 */
/* ARGSUSED */
int
px_err_tlu_ldn_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	px_t    *px_p = DIP_TO_STATE(rpdip);
	return ((px_p->px_pm_flags & PX_LDN_EXPECTED) ? PX_EXPECTED :
	    PX_NO_PANIC);
}

/* PEC ILU none - see io erpt doc, section 3.1 */
PX_ERPT_SEND_DEC(pec_ilu)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_ILU_ELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, ILU_ERROR_LOG_ENABLE),
	    FIRE_ILU_IE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, ILU_INTERRUPT_ENABLE),
	    FIRE_ILU_IS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_ILU_ESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, ILU_ERROR_STATUS_SET),
	    NULL);

	return (PX_NO_PANIC);
}

/* PCIEX UE Errors */
/* ARGSUSED */
int
px_err_pciex_ue_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	px_err_pcie_t	regs = {0};
	uint32_t	err_bit;
	int		err;
	uint64_t	log;

	if (err_bit_descr->bit < 32) {
		err_bit = (uint32_t)BITMASK(err_bit_descr->bit);
		regs.ue_reg = err_bit;
		regs.primary_ue = err_bit;

		/*
		 * Log the Received Log for PTLP and UR.  The PTLP most likely
		 * is a poisoned completion.  The original transaction will be
		 * logged inthe Transmit Log.
		 */
		if (err_bit & (PCIE_AER_UCE_PTLP | PCIE_AER_UCE_UR)) {
			log = CSR_XR(csr_base,
			    TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER1_LOG);
			regs.rx_hdr1 = (uint32_t)(log >> 32);
			regs.rx_hdr2 = (uint32_t)(log && 0xFFFFFFFF);

			log = CSR_XR(csr_base,
			    TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER2_LOG);
			regs.rx_hdr3 = (uint32_t)(log >> 32);
			regs.rx_hdr4 = (uint32_t)(log && 0xFFFFFFFF);
		}

		if (err_bit & (PCIE_AER_UCE_PTLP)) {
			log = CSR_XR(csr_base,
			    TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER1_LOG);
			regs.tx_hdr1 = (uint32_t)(log >> 32);
			regs.tx_hdr2 = (uint32_t)(log && 0xFFFFFFFF);

			log = CSR_XR(csr_base,
			    TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER2_LOG);
			regs.tx_hdr3 = (uint32_t)(log >> 32);
			regs.tx_hdr4 = (uint32_t)(log && 0xFFFFFFFF);
		}
	} else {
		regs.ue_reg = (uint32_t)BITMASK(err_bit_descr->bit - 32);
	}

	err = px_err_check_pcie(rpdip, derr, &regs);

	if (err & PX_PANIC) {
		return (px_err_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
	} else {
		return (px_err_no_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
	}
}

/* PCI-E Uncorrectable Errors */
PX_ERPT_SEND_DEC(pciex_rx_ue)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_TLU_UELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_LOG_ENABLE),
	    FIRE_TLU_UIE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_INTERRUPT_ENABLE),
	    FIRE_TLU_UIS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_TLU_UESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_STATUS_SET),
	    FIRE_TLU_RUEH1L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER1_LOG),
	    FIRE_TLU_RUEH2L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER2_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/* PCI-E Uncorrectable Errors */
PX_ERPT_SEND_DEC(pciex_tx_ue)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_TLU_UELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_LOG_ENABLE),
	    FIRE_TLU_UIE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_INTERRUPT_ENABLE),
	    FIRE_TLU_UIS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_TLU_UESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_STATUS_SET),
	    FIRE_TLU_TUEH1L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER1_LOG),
	    FIRE_TLU_TUEH2L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER2_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/* PCI-E Uncorrectable Errors */
PX_ERPT_SEND_DEC(pciex_rx_tx_ue)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_TLU_UELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_LOG_ENABLE),
	    FIRE_TLU_UIE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_INTERRUPT_ENABLE),
	    FIRE_TLU_UIS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_TLU_UESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_STATUS_SET),
	    FIRE_TLU_RUEH1L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER1_LOG),
	    FIRE_TLU_RUEH2L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER2_LOG),
	    FIRE_TLU_TUEH1L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER1_LOG),
	    FIRE_TLU_TUEH2L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER2_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/* PCI-E Uncorrectable Errors */
PX_ERPT_SEND_DEC(pciex_ue)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_TLU_UELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_LOG_ENABLE),
	    FIRE_TLU_UIE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_INTERRUPT_ENABLE),
	    FIRE_TLU_UIS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_TLU_UESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_STATUS_SET),
	    NULL);

	return (PX_NO_PANIC);
}

/* PCIEX UE Errors */
/* ARGSUSED */
int
px_err_pciex_ce_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	px_err_pcie_t	regs = {0};
	int		err;

	if (err_bit_descr->bit < 32)
		regs.ce_reg = (uint32_t)BITMASK(err_bit_descr->bit);
	else
		regs.ce_reg = (uint32_t)BITMASK(err_bit_descr->bit - 32);

	err = px_err_check_pcie(rpdip, derr, &regs);

	if (err & PX_PANIC) {
		return (px_err_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
	} else {
		return (px_err_no_panic_handle(rpdip, csr_base, derr,
		    err_reg_descr, err_bit_descr));
	}
}

/* PCI-E Correctable Errors - see io erpt doc, section 3.6 */
PX_ERPT_SEND_DEC(pciex_ce)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_TLU_CELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_CORRECTABLE_ERROR_LOG_ENABLE),
	    FIRE_TLU_CIE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_CORRECTABLE_ERROR_INTERRUPT_ENABLE),
	    FIRE_TLU_CIS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_TLU_CESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_CORRECTABLE_ERROR_STATUS_SET),
	    NULL);

	return (PX_NO_PANIC);
}

/* TLU Other Event Status (receive only) - see io erpt doc, section 3.7 */
PX_ERPT_SEND_DEC(pciex_rx_oe)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_TLU_OEELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_LOG_ENABLE),
	    FIRE_TLU_OEIE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_INTERRUPT_ENABLE),
	    FIRE_TLU_OEIS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_TLU_OEESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_STATUS_SET),
	    FIRE_TLU_RUEH1L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_RECEIVE_OTHER_EVENT_HEADER1_LOG),
	    FIRE_TLU_RUEH2L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_RECEIVE_OTHER_EVENT_HEADER2_LOG),
	    NULL);

	return (PX_NO_PANIC);
}

/* TLU Other Event Status (rx + tx) - see io erpt doc, section 3.8 */
PX_ERPT_SEND_DEC(pciex_rx_tx_oe)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);
	px_t		*px_p = DIP_TO_STATE(rpdip);
	uint32_t	trans_type, fault_addr = 0;
	uint64_t	rx_h1, rx_h2, tx_h1, tx_h2;
	uint16_t	s_status;
	int		sts;
	pcie_req_id_t	fault_bdf = 0;
	pcie_cpl_t	*cpl;
	pf_data_t	pf_data = {0};

	rx_h1 = CSR_XR(csr_base, TLU_RECEIVE_OTHER_EVENT_HEADER1_LOG);
	rx_h2 = CSR_XR(csr_base, TLU_RECEIVE_OTHER_EVENT_HEADER2_LOG);
	tx_h1 = CSR_XR(csr_base, TLU_TRANSMIT_OTHER_EVENT_HEADER1_LOG);
	tx_h2 = CSR_XR(csr_base, TLU_TRANSMIT_OTHER_EVENT_HEADER2_LOG);

	if ((bit == TLU_OTHER_EVENT_STATUS_SET_RUC_P) ||
	    (bit == TLU_OTHER_EVENT_STATUS_SET_WUC_P)) {
		pf_data.aer_h0 = (uint32_t)(rx_h1 >> 32);
		pf_data.aer_h1 = (uint32_t)rx_h1;
		pf_data.aer_h2 = (uint32_t)(rx_h2 >> 32);
		pf_data.aer_h3 = (uint32_t)rx_h2;

		/* get completer bdf (fault bdf) from rx logs */
		cpl = (pcie_cpl_t *)&pf_data.aer_h1;
		fault_bdf = cpl->cid;

		/* Figure out if UR/CA from rx logs */
		if (cpl->status == PCIE_CPL_STS_UR)
			s_status = PCI_STAT_R_MAST_AB;
		else if (cpl->status == PCIE_CPL_STS_CA)
			s_status = PCI_STAT_R_TARG_AB;


		pf_data.aer_h0 = (uint32_t)(tx_h1 >> 32);
		pf_data.aer_h1 = (uint32_t)tx_h1;
		pf_data.aer_h2 = (uint32_t)(tx_h2 >> 32);
		pf_data.aer_h3 = (uint32_t)tx_h2;

		/* get fault addr from tx logs */
		sts = pf_tlp_decode(rpdip, &pf_data, 0, &fault_addr,
		    &trans_type);

		if (sts == DDI_SUCCESS)
			(void) px_rp_en_q(px_p, fault_bdf, fault_addr,
			    s_status);
	}

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_TLU_OEELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_LOG_ENABLE),
	    FIRE_TLU_OEIE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_INTERRUPT_ENABLE),
	    FIRE_TLU_OEIS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_TLU_OEESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_STATUS_SET),
	    FIRE_TLU_ROEEH1L, DATA_TYPE_UINT64, rx_h1,
	    FIRE_TLU_ROEEH2L, DATA_TYPE_UINT64, rx_h2,
	    FIRE_TLU_TOEEH1L, DATA_TYPE_UINT64, tx_h1,
	    FIRE_TLU_TOEEH2L, DATA_TYPE_UINT64, tx_h2,
	    NULL);

	return (PX_NO_PANIC);
}

/* TLU Other Event - see io erpt doc, section 3.9 */
PX_ERPT_SEND_DEC(pciex_oe)
{
	char		buf[FM_MAX_CLASS];
	boolean_t	pri = PX_ERR_IS_PRI(bit);

	(void) snprintf(buf, FM_MAX_CLASS, "%s", class_name);
	ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, pri,
	    FIRE_TLU_OEELE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_LOG_ENABLE),
	    FIRE_TLU_OEIE, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_INTERRUPT_ENABLE),
	    FIRE_TLU_OEIS, DATA_TYPE_UINT64,
	    ss_reg,
	    FIRE_TLU_OEESS, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_OTHER_EVENT_STATUS_SET),
	    NULL);

	return (PX_NO_PANIC);
}
