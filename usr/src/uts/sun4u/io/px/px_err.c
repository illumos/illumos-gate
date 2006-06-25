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
	/* JBC FATAL - see io erpt doc, section 1.1 */
	{ JBC_BIT_DESC(MB_PEA,	fatal_hw,	jbc_fatal) },
	{ JBC_BIT_DESC(CPE,	fatal_hw,	jbc_fatal) },
	{ JBC_BIT_DESC(APE,	fatal_hw,	jbc_fatal) },
	{ JBC_BIT_DESC(PIO_CPE,	fatal_hw,	jbc_fatal) },
	{ JBC_BIT_DESC(JTCEEW,	fatal_hw,	jbc_fatal) },
	{ JBC_BIT_DESC(JTCEEI,	fatal_hw,	jbc_fatal) },
	{ JBC_BIT_DESC(JTCEER,	fatal_hw,	jbc_fatal) },

	/* JBC MERGE - see io erpt doc, section 1.2 */
	{ JBC_BIT_DESC(MB_PER,	jbc_merge,	jbc_merge) },
	{ JBC_BIT_DESC(MB_PEW,	jbc_merge,	jbc_merge) },

	/* JBC Jbusint IN - see io erpt doc, section 1.3 */
	{ JBC_BIT_DESC(UE_ASYN,	fatal_gos,	jbc_in) },
	{ JBC_BIT_DESC(CE_ASYN,	non_fatal,	jbc_in) },
	{ JBC_BIT_DESC(JTE,	fatal_gos,	jbc_in) },
	{ JBC_BIT_DESC(JBE,	jbc_jbusint_in,	jbc_in) },
	{ JBC_BIT_DESC(JUE,	jbc_jbusint_in,	jbc_in) },
	{ JBC_BIT_DESC(ICISE,	fatal_gos,	jbc_in) },
	{ JBC_BIT_DESC(WR_DPE,	jbc_jbusint_in,	jbc_in) },
	{ JBC_BIT_DESC(RD_DPE,	jbc_jbusint_in,	jbc_in) },
	{ JBC_BIT_DESC(ILL_BMW,	jbc_jbusint_in,	jbc_in) },
	{ JBC_BIT_DESC(ILL_BMR,	jbc_jbusint_in,	jbc_in) },
	{ JBC_BIT_DESC(BJC,	jbc_jbusint_in,	jbc_in) },

	/* JBC Jbusint Out - see io erpt doc, section 1.4 */
	{ JBC_BIT_DESC(IJP,	fatal_gos,	jbc_out) },

	/*
	 * JBC Dmcint ODCD - see io erpt doc, section 1.5
	 *
	 * Error bits which can be set via a bad PCItool access go through
	 * jbc_safe_acc instead.
	 */
	{ JBC_BIT_DESC(PIO_UNMAP_RD,	jbc_safe_acc,		jbc_odcd) },
	{ JBC_BIT_DESC(ILL_ACC_RD,	jbc_safe_acc,		jbc_odcd) },
	{ JBC_BIT_DESC(PIO_UNMAP,	jbc_safe_acc,		jbc_odcd) },
	{ JBC_BIT_DESC(PIO_DPE,		jbc_dmcint_odcd,	jbc_odcd) },
	{ JBC_BIT_DESC(PIO_CPE,		non_fatal,		jbc_odcd) },
	{ JBC_BIT_DESC(ILL_ACC,		jbc_safe_acc,		jbc_odcd) },

	/* JBC Dmcint IDC - see io erpt doc, section 1.6 */
	{ JBC_BIT_DESC(UNSOL_RD,	non_fatal,	jbc_idc) },
	{ JBC_BIT_DESC(UNSOL_INTR,	non_fatal,	jbc_idc) },

	/* JBC CSR - see io erpt doc, section 1.7 */
	{ JBC_BIT_DESC(EBUS_TO,	jbc_csr,	jbc_csr) }
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
	{ UBC_BIT_DESC(DMARDUEA,	non_fatal,	ubc_fatal) },
	{ UBC_BIT_DESC(DMAWTUEA,	fatal_sw,	ubc_fatal) },
	{ UBC_BIT_DESC(MEMRDAXA,	fatal_sw,	ubc_fatal) },
	{ UBC_BIT_DESC(MEMWTAXA,	fatal_sw,	ubc_fatal) },
	{ UBC_BIT_DESC(DMARDUEB,	non_fatal,	ubc_fatal) },
	{ UBC_BIT_DESC(DMAWTUEB,	fatal_sw,	ubc_fatal) },
	{ UBC_BIT_DESC(MEMRDAXB,	fatal_sw,	ubc_fatal) },
	{ UBC_BIT_DESC(MEMWTAXB,	fatal_sw,	ubc_fatal) },
	{ UBC_BIT_DESC(PIOWTUE,		fatal_sw,	ubc_fatal) },
	{ UBC_BIT_DESC(PIOWBEUE,	fatal_sw,	ubc_fatal) },
	{ UBC_BIT_DESC(PIORBEUE,	fatal_sw,	ubc_fatal) }
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
	/* DMC IMU RDS - see io erpt doc, section 2.1 */
	{ IMU_BIT_DESC(MSI_MAL_ERR,		non_fatal,	imu_rds) },
	{ IMU_BIT_DESC(MSI_PAR_ERR,		fatal_stuck,	imu_rds) },
	{ IMU_BIT_DESC(PMEACK_MES_NOT_EN,	imu_rbne,	imu_rds) },
	{ IMU_BIT_DESC(PMPME_MES_NOT_EN,	imu_pme,	imu_rds) },
	{ IMU_BIT_DESC(FATAL_MES_NOT_EN,	imu_rbne,	imu_rds) },
	{ IMU_BIT_DESC(NONFATAL_MES_NOT_EN,	imu_rbne,	imu_rds) },
	{ IMU_BIT_DESC(COR_MES_NOT_EN,		imu_rbne,	imu_rds) },
	{ IMU_BIT_DESC(MSI_NOT_EN,		imu_rbne,	imu_rds) },

	/* DMC IMU SCS - see io erpt doc, section 2.2 */
	{ IMU_BIT_DESC(EQ_NOT_EN,		imu_rbne,	imu_rds) },

	/* DMC IMU - see io erpt doc, section 2.3 */
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
	/* DMC MMU TFAR/TFSR - see io erpt doc, section 2.4 */
	{ MMU_BIT_DESC(BYP_ERR,		mmu_rbne,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(BYP_OOR,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TRN_ERR,		mmu_rbne,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TRN_OOR,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TTE_INV,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TTE_PRT,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TTC_DPE,		mmu_tfa,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TBW_DME,		mmu_tblwlk,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TBW_UDE,		mmu_tblwlk,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TBW_ERR,		mmu_tblwlk,	mmu_tfar_tfsr) },
	{ MMU_BIT_DESC(TBW_DPE,		mmu_tblwlk,	mmu_tfar_tfsr) },

	/* DMC MMU - see io erpt doc, section 2.5 */
	{ MMU_BIT_DESC(TTC_CAE,		non_fatal,	mmu) }
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
	/* PEC ILU none - see io erpt doc, section 3.1 */
	{ ILU_BIT_DESC(IHB_PE,		fatal_gos,	pec_ilu) }
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
	/* PCI-E Receive Uncorrectable Errors - see io erpt doc, section 3.2 */
	{ TLU_UC_BIT_DESC(UR,		pciex_ue,	pciex_rx_ue) },
	{ TLU_UC_BIT_DESC(UC,		pciex_ue,	pciex_rx_ue) },

	/* PCI-E Transmit Uncorrectable Errors - see io erpt doc, section 3.3 */
	{ TLU_UC_OB_BIT_DESC(ECRC,	pciex_ue,	pciex_rx_ue) },
	{ TLU_UC_BIT_DESC(CTO,		pciex_ue,	pciex_tx_ue) },
	{ TLU_UC_BIT_DESC(ROF,		pciex_ue,	pciex_tx_ue) },

	/* PCI-E Rx/Tx Uncorrectable Errors - see io erpt doc, section 3.4 */
	{ TLU_UC_BIT_DESC(MFP,		pciex_ue,	pciex_rx_tx_ue) },
	{ TLU_UC_BIT_DESC(PP,		pciex_ue,	pciex_rx_tx_ue) },

	/* Other PCI-E Uncorrectable Errors - see io erpt doc, section 3.5 */
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
	/* PCI-E Correctable Errors - see io erpt doc, section 3.6 */
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
	/*
	 * TLU Other Event Status (receive only) - see io erpt doc, section 3.7
	 */
	{ TLU_OE_BIT_DESC(MRC,		fatal_hw,	pciex_rx_oe) },

	/* TLU Other Event Status (rx + tx) - see io erpt doc, section 3.8 */
	{ TLU_OE_BIT_DESC(WUC,		non_fatal,	pciex_rx_tx_oe) },
	{ TLU_OE_BIT_DESC(RUC,		non_fatal,	pciex_rx_tx_oe) },
	{ TLU_OE_BIT_DESC(CRS,		non_fatal,	pciex_rx_tx_oe) },

	/* TLU Other Event - see io erpt doc, section 3.9 */
	{ TLU_OE_BIT_DESC(IIP,		fatal_gos,	pciex_oe) },
	{ TLU_OE_BIT_DESC(EDP,		fatal_gos,	pciex_oe) },
	{ TLU_OE_BIT_DESC(EHP,		fatal_gos,	pciex_oe) },
	{ TLU_OE_OB_BIT_DESC(TLUEITMO,	fatal_gos,	pciex_oe) },
	{ TLU_OE_BIT_DESC(LIN,		non_fatal,	pciex_oe) },
	{ TLU_OE_BIT_DESC(LRS,		non_fatal,	pciex_oe) },
	{ TLU_OE_BIT_DESC(LDN,		tlu_ldn,	pciex_oe) },
	{ TLU_OE_BIT_DESC(LUP,		tlu_lup,	pciex_oe) },
	{ TLU_OE_BIT_DESC(ERU,		fatal_gos,	pciex_oe) },
	{ TLU_OE_BIT_DESC(ERO,		fatal_gos,	pciex_oe) },
	{ TLU_OE_BIT_DESC(EMP,		fatal_gos,	pciex_oe) },
	{ TLU_OE_BIT_DESC(EPE,		fatal_gos,	pciex_oe) },
	{ TLU_OE_BIT_DESC(ERP,		fatal_gos,	pciex_oe) },
	{ TLU_OE_BIT_DESC(EIP,		fatal_gos,	pciex_oe) }
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
#define	MnT6(pre) \
	B_FALSE, \
	&px_ ## pre ## _intr_mask, \
	&px_ ## pre ## _log_mask, \
	&px_ ## pre ## _count_mask, \
	px_err_ ## pre ## _tbl, \
	px_err_ ## pre ## _keys, \
	0

#define	MnT6_ob(pre) \
	B_FALSE, \
	&px_ ## pre ## _intr_mask, \
	&px_ ## pre ## _log_mask, \
	&px_ ## pre ## _count_mask, \
	px_err_ ## pre ## _ob_tbl, \
	px_err_ ## pre ## _ob_keys, \
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

/*
 * Register error handling tables.
 * The ID Field (first field) is identified by an enum px_err_id_t.
 * It is located in px_err.h
 */
px_err_reg_desc_t px_err_reg_tbl[] = {
	{ MnT6(jbc),	R4(JBC),		  "JBC Error"},
	{ MnT6(ubc),	R4(UBC),		  "UBC Error"},
	{ MnT6(mmu),	R4(MMU),		  "MMU Error"},
	{ MnT6(imu),	R4(IMU),		  "IMU Error"},
	{ MnT6(tlu_ue),	TR4(UNCORRECTABLE_ERROR), "TLU UE"},
	{ MnT6(tlu_ce), TR4(CORRECTABLE_ERROR),	  "TLU CE"},
	{ MnT6(tlu_oe), TR4(OTHER_EVENT),	  "TLU OE"},
	{ MnT6(ilu),	R4(ILU),		  "ILU Error"},
	{ MnT6(lpul),	LR4(LINK_LAYER),	  "LPU Link Layer"},
	{ MnT6(lpup),	LR4_FIXME(PHY),		  "LPU Phy Layer"},
	{ MnT6(lpur),	LR4(RECEIVE_PHY),	  "LPU RX Phy Layer"},
	{ MnT6(lpux),	LR4(TRANSMIT_PHY),	  "LPU TX Phy Layer"},
	{ MnT6(lpus),	LR4(LTSSM),		  "LPU LTSSM"},
	{ MnT6(lpug),	LR4(GIGABLAZE_GLUE),	  "LPU GigaBlaze Glue"},
};
#define	PX_ERR_REG_KEYS (sizeof (px_err_reg_tbl)) / (sizeof (px_err_reg_tbl[0]))

typedef struct px_err_ss {
	uint64_t err_status[PX_ERR_REG_KEYS];
} px_err_ss_t;

static void px_err_snapshot(px_t *px_p, px_err_ss_t *ss, boolean_t chk_cb);
static int  px_err_erpt_and_clr(px_t *px_p, ddi_fm_error_t *derr,
    px_err_ss_t *ss);
static int  px_err_check_severity(px_t *px_p, ddi_fm_error_t *derr,
    int err, int caller);

/*
 * px_err_cb_intr:
 * Interrupt handler for the JBC/UBC block.
 * o lock
 * o create derr
 * o px_err_handle(leaf1, with cb)
 * o px_err_handle(leaf2, without cb)
 * o dispatch (leaf1)
 * o dispatch (leaf2)
 * o unlock
 * o handle error: fatal? fm_panic() : return INTR_CLAIMED)
 */
uint_t
px_err_cb_intr(caddr_t arg)
{
	px_fault_t	*px_fault_p = (px_fault_t *)arg;
	dev_info_t	*rpdip = px_fault_p->px_fh_dip;
	px_t		*px_p = DIP_TO_STATE(rpdip);
	int		err = PX_OK;
	int		ret = DDI_FM_OK;
	int		fatal = 0;
	ddi_fm_error_t	derr;

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;

	mutex_enter(&px_p->px_fm_mutex);

	err |= px_err_handle(px_p, &derr, PX_INTR_CALL, B_TRUE);

	ret = ndi_fm_handler_dispatch(rpdip, NULL, &derr);
	switch (ret) {
	case DDI_FM_FATAL:
		fatal++;
		break;
	case DDI_FM_NONFATAL:
	case DDI_FM_UNKNOWN:
	default:
		break;
	}

	/* Set the intr state to idle for the leaf that received the mondo */

	(void) px_lib_intr_setstate(rpdip, px_fault_p->px_fh_sysino,
	    INTR_IDLE_STATE);

	mutex_exit(&px_p->px_fm_mutex);

	/*
	 * PX_FATAL_HW error is diagnosed after system recovered from
	 * HW initiated reset, therefore no furthur handling is required.
	 */
	if (fatal || err & (PX_FATAL_GOS | PX_FATAL_SW))
		PX_FM_PANIC("Fatal System Bus Error has occurred\n");

	return (DDI_INTR_CLAIMED);
}

/*
 * px_err_dmc_pec_intr:
 * Interrupt handler for the DMC/PEC block.
 * o lock
 * o create derr
 * o px_err_handle(leaf, with cb)
 * o dispatch (leaf)
 * o unlock
 * o handle error: fatal? fm_panic() : return INTR_CLAIMED)
 */
uint_t
px_err_dmc_pec_intr(caddr_t arg)
{
	px_fault_t	*px_fault_p = (px_fault_t *)arg;
	dev_info_t	*rpdip = px_fault_p->px_fh_dip;
	px_t		*px_p = DIP_TO_STATE(rpdip);
	int		err = PX_OK;
	int		ret = DDI_FM_OK;
	ddi_fm_error_t	derr;

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;

	mutex_enter(&px_p->px_fm_mutex);

	/* send ereport/handle/clear fire registers */
	err |= px_err_handle(px_p, &derr, PX_INTR_CALL, B_TRUE);

	/* Check all child devices for errors */
	ret = ndi_fm_handler_dispatch(rpdip, NULL, &derr);

	/* Set the interrupt state to idle */
	(void) px_lib_intr_setstate(rpdip, px_fault_p->px_fh_sysino,
	    INTR_IDLE_STATE);

	mutex_exit(&px_p->px_fm_mutex);

	/*
	 * PX_FATAL_HW indicates a condition recovered from Fatal-Reset,
	 * therefore it does not cause panic.
	 */
	if ((err & (PX_FATAL_GOS | PX_FATAL_SW)) || (ret == DDI_FM_FATAL))
		PX_FM_PANIC("Fatal System Port Error has occurred\n");

	return (DDI_INTR_CLAIMED);
}

/*
 * Error register are being handled by px_hlib xxx_init functions.
 * They are also called again by px_err_add_intr for mondo62 and 63
 * from px_cb_attach and px_attach
 */
void
px_err_reg_enable(px_t *px_p, px_err_id_t id)
{
	px_err_reg_desc_t	*reg_desc = &px_err_reg_tbl[id];
	uint64_t 		intr_mask = *reg_desc->intr_mask_p;
	uint64_t 		log_mask = *reg_desc->log_mask_p;
	caddr_t			csr_base;
	pxu_t			*pxu_p = (pxu_t *)px_p->px_plat_p;

	/* Get the correct CSR BASE */
	if (PX_ERR_XBC(id))
		csr_base = (caddr_t)pxu_p->px_address[PX_REG_XBC];
	else
		csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];

	reg_desc->enabled = B_TRUE;

	/* Enable logs if it exists */
	if (reg_desc->log_addr != NULL)
		CSR_XS(csr_base, reg_desc->log_addr, log_mask);

	/*
	 * For readability you in code you set 1 to enable an interrupt.
	 * But in Fire it's backwards.  You set 1 to *disable* an intr.
	 * Reverse the user tunable intr mask field.
	 *
	 * Disable All Errors
	 * Clear All Errors
	 * Enable Errors
	 */
	CSR_XS(csr_base, reg_desc->enable_addr, 0);
	CSR_XS(csr_base, reg_desc->clear_addr, -1);
	CSR_XS(csr_base, reg_desc->enable_addr, intr_mask);
	DBG(DBG_ATTACH, NULL, "%s Mask: 0x%llx\n",
	    reg_desc->msg, CSR_XR(csr_base, reg_desc->enable_addr));
	DBG(DBG_ATTACH, NULL, "%s Status: 0x%llx\n",
	    reg_desc->msg, CSR_XR(csr_base, reg_desc->status_addr));
	DBG(DBG_ATTACH, NULL, "%s Clear: 0x%llx\n",
	    reg_desc->msg, CSR_XR(csr_base, reg_desc->clear_addr));
	if (reg_desc->log_addr != NULL) {
		DBG(DBG_ATTACH, NULL, "%s Log: 0x%llx\n",
		    reg_desc->msg, CSR_XR(csr_base, reg_desc->log_addr));
	}
}

void
px_err_reg_disable(px_t *px_p, px_err_id_t id)
{
	px_err_reg_desc_t	*reg_desc = &px_err_reg_tbl[id];
	caddr_t			csr_base;
	pxu_t			*pxu_p = (pxu_t *)px_p->px_plat_p;

	/* Get the correct CSR BASE */
	if (PX_ERR_XBC(id))
		csr_base = (caddr_t)(uintptr_t)pxu_p->px_address[PX_REG_XBC];
	else
		csr_base = (caddr_t)(uintptr_t)pxu_p->px_address[PX_REG_CSR];

	reg_desc->enabled = B_FALSE;

	switch (id) {
	case PX_ERR_JBC:
	case PX_ERR_UBC:
	case PX_ERR_MMU:
	case PX_ERR_IMU:
	case PX_ERR_TLU_UE:
	case PX_ERR_TLU_CE:
	case PX_ERR_TLU_OE:
	case PX_ERR_ILU:
		if (reg_desc->log_addr != NULL) {
			CSR_XS(csr_base, reg_desc->log_addr, 0);
		}
		CSR_XS(csr_base, reg_desc->enable_addr, 0);
		break;
	case PX_ERR_LPU_LINK:
	case PX_ERR_LPU_PHY:
	case PX_ERR_LPU_RX:
	case PX_ERR_LPU_TX:
	case PX_ERR_LPU_LTSSM:
	case PX_ERR_LPU_GIGABLZ:
		if (reg_desc->log_addr != NULL) {
			CSR_XS(csr_base, reg_desc->log_addr, -1);
		}
		CSR_XS(csr_base, reg_desc->enable_addr, -1);
		break;
	}
}

/*
 * px_err_handle:
 * Common function called by trap, mondo and fabric intr.
 * o Snap shot current fire registers
 * o check for safe access
 * o send ereport and clear snap shot registers
 * o check severity of snap shot registers
 *
 * @param px_p		leaf in which to check access
 * @param derr		fm err data structure to be updated
 * @param caller	PX_TRAP_CALL | PX_INTR_CALL
 * @param chk_cb	whether to handle cb registers
 * @return err		PX_OK | PX_NONFATAL |
 *                      PX_FATAL_GOS | PX_FATAL_HW | PX_STUCK_FATAL
 */
int
px_err_handle(px_t *px_p, ddi_fm_error_t *derr, int caller,
    boolean_t chk_cb)
{
	px_err_ss_t		ss;
	int			err = PX_OK;

	ASSERT(MUTEX_HELD(&px_p->px_fm_mutex));

	/* snap shot the current fire registers */
	px_err_snapshot(px_p, &ss, chk_cb);

	/* check for safe access */
	px_err_safeacc_check(px_p, derr);

	/* send ereports/handle/clear registers */
	err = px_err_erpt_and_clr(px_p, derr, &ss);

	/* check for error severity */
	err = px_err_check_severity(px_p, derr, err, caller);

	/* Mark the On Trap Handle if an error occured */
	if (err != PX_OK) {
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
 * JBC/UBC, DMC, and PEC, unless chk_cb == false;
 *
 * @param px_p		leaf in which to take the snap shot.
 * @param ss		pre-allocated memory to store the snap shot.
 * @param chk_cb	boolean on whether to store jbc/ubc register.
 */
static void
px_err_snapshot(px_t *px_p, px_err_ss_t *ss, boolean_t chk_cb)
{
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t	xbc_csr_base = (caddr_t)pxu_p->px_address[PX_REG_XBC];
	caddr_t	pec_csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];
	px_err_reg_desc_t *reg_desc;
	int reg_id;

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		reg_id = PX_ERR_UBC;
		break;
	case PX_CHIP_FIRE:
		reg_id = PX_ERR_JBC;
		break;
	default:
		DBG(DBG_ERR_INTR, NULL, "px_err_snapshot - "
		    "unknown chip type: 0x%x\n", PX_CHIP_TYPE(pxu_p));
		reg_id = 0;
		break;
	}

	/* snapshot CB interrupt status */
	if (chk_cb == B_TRUE) {
		reg_desc = &px_err_reg_tbl[reg_id];
		/* Only look at enabled groups. */
		if (reg_desc->enabled == B_TRUE)	{
			ss->err_status[reg_id] = CSR_XR(xbc_csr_base,
			    reg_desc->status_addr);
		}
	} else {
		ss->err_status[reg_id] = 0;
	}

	/* snapshot DMC/PEC interrupt status */
	for (reg_id = 2; reg_id < PX_ERR_REG_KEYS; reg_id += 1) {
		reg_desc = &px_err_reg_tbl[reg_id];
		/* Only look at enabled groups. */
		if (reg_desc->enabled == B_TRUE)	{
			ss->err_status[reg_id] = CSR_XR(pec_csr_base,
			    reg_desc->status_addr);
		}
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
 * @param ss		pre-allocated memory to store the snap shot.
 */
static int
px_err_erpt_and_clr(px_t *px_p, ddi_fm_error_t *derr, px_err_ss_t *ss)
{
	dev_info_t		*rpdip = px_p->px_dip;
	pxu_t			*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t			csr_base;
	px_err_reg_desc_t	*err_reg_tbl;
	px_err_bit_desc_t	*err_bit_tbl;
	px_err_bit_desc_t	*err_bit_desc;

	uint64_t		*log_mask, *count_mask;
	uint64_t		status_addr, clear_addr;
	uint64_t		ss_reg;

	int			(*err_handler)();
	int			(*erpt_handler)();
	int			reg_id, key;
	int			err = PX_OK;
	int			biterr;

	ASSERT(MUTEX_HELD(&px_p->px_fm_mutex));

	/* send erport/handle/clear JBC errors */
	for (reg_id = 0; reg_id < PX_ERR_REG_KEYS; reg_id += 1) {
		/* Get the correct register description table */
		err_reg_tbl = &px_err_reg_tbl[reg_id];

		/* Only look at enabled groups. */
		if (err_reg_tbl->enabled != B_TRUE)
			continue;

		/* Get the correct CSR BASE */
		if (PX_ERR_XBC(reg_id))
			csr_base = (caddr_t)pxu_p->px_address[PX_REG_XBC];
		else
			csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];

		/* Get pointers to masks and register addresses */
		log_mask = err_reg_tbl->log_mask_p;
		count_mask = err_reg_tbl->count_mask_p;
		status_addr = err_reg_tbl->status_addr;
		clear_addr = err_reg_tbl->clear_addr;
		ss_reg = ss->err_status[reg_id];

		/* Get the register BIT description table */
		err_bit_tbl = err_reg_tbl->err_bit_tbl;

		/* For each known bit in the register send erpt and handle */
		for (key = 0; key < err_reg_tbl->err_bit_keys; key += 1) {
			/* Get the bit description table for this register */
			err_bit_desc = &err_bit_tbl[key];

			/*
			 * If the ss_reg is set for this bit,
			 * send ereport and handle
			 */
			if (BIT_TST(ss_reg, err_bit_desc->bit)) {
				/* Increment the counter if necessary */
				if (BIT_TST(*count_mask, err_bit_desc->bit)) {
					err_bit_desc->counter++;
				}

				/* Error Handle for this bit */
				err_handler = err_bit_desc->err_handler;
				if (err_handler) {
					biterr = err_handler(rpdip,
					    csr_base,
					    derr,
					    err_reg_tbl,
					    err_bit_desc);
					err |= biterr;
				}

				/* Send the ereport if it's an UNEXPECTED err */
				erpt_handler = err_bit_desc->erpt_handler;
				if ((derr->fme_flag == DDI_FM_ERR_UNEXPECTED) &&
				    (biterr != PX_OK)) {
					if (erpt_handler)
						(void) erpt_handler(rpdip,
						    csr_base,
						    ss_reg,
						    derr,
						    err_bit_desc->bit,
						    err_bit_desc->class_name);
				}
			}
		}
		/* Print register status */
		if (ss_reg & *log_mask)
			DBG(DBG_ERR_INTR, rpdip, "<%x>=%16llx %s\n",
			    status_addr, ss_reg, err_reg_tbl->msg);

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
 * @param ss		pre-allocated memory to store the snap shot.
 */
static int
px_err_check_severity(px_t *px_p, ddi_fm_error_t *derr, int err, int caller)
{
	px_pec_t 	*pec_p = px_p->px_pec_p;
	boolean_t	is_safeacc = B_FALSE;

	/* nothing to do if called with no error */
	if (err == PX_OK)
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

	/*
	 * The third argument "err" is passed in as error status from checking
	 * Fire register, re-adjust error status from safe access.
	 */
	if (is_safeacc && !(err & PX_FATAL_GOS))
		return (PX_NONFATAL);

	return (err);
}

/* predefined convenience functions */
/* ARGSUSED */
int
px_err_fatal_hw_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	return (PX_FATAL_HW);
}

/* ARGSUSED */
int
px_err_fatal_gos_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	return (PX_FATAL_GOS);
}

/* ARGSUSED */
int
px_err_fatal_stuck_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	return (PX_STUCK_FATAL);
}

/* ARGSUSED */
int
px_err_fatal_sw_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	return (PX_FATAL_SW);
}

/* ARGSUSED */
int
px_err_non_fatal_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	return (PX_NONFATAL);
}

/* ARGSUSED */
int
px_err_ok_handle(dev_info_t *rpdip, caddr_t csr_base, ddi_fm_error_t *derr,
	px_err_reg_desc_t *err_reg_descr, px_err_bit_desc_t *err_bit_descr)
{
	return (PX_OK);
}

/* ARGSUSED */
int
px_err_unknown_handle(dev_info_t *rpdip, caddr_t csr_base, ddi_fm_error_t *derr,
	px_err_reg_desc_t *err_reg_descr, px_err_bit_desc_t *err_bit_descr)
{
	return (PX_ERR_UNKNOWN);
}

/* ARGSUSED */
PX_ERPT_SEND_DEC(do_not)
{
	return (PX_OK);
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

	if (resource) {
		ddi_fm_ereport_post(rpdip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    FIRE_PRIMARY, DATA_TYPE_BOOLEAN_VALUE, B_TRUE,
		    OBERON_UBC_ELE, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_ERROR_LOG_ENABLE),
		    OBERON_UBC_IE, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_INTERRUPT_ENABLE),
		    OBERON_UBC_IS, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_INTERRUPT_STATUS),
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
		    OBERON_UBC_IS, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_INTERRUPT_STATUS),
		    OBERON_UBC_ESS, DATA_TYPE_UINT64,
		    CSR_XR(csr_base, UBC_ERROR_STATUS_SET),
		    OBERON_UBC_MUE, DATA_TYPE_UINT64, memory_ue_log,
		    OBERON_UBC_UNUM, DATA_TYPE_STRING, unum,
		    OBERON_UBC_DID, DATA_TYPE_UINT64, device_id,
		    OBERON_UBC_CPUV, DATA_TYPE_UINT32, cpu_version,
		    NULL);
	}

	return (PX_OK);
}

/* JBC FATAL - see io erpt doc, section 1.1 */
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

	return (PX_OK);
}

/* JBC MERGE - see io erpt doc, section 1.2 */
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

	return (PX_OK);
}

/*
 * JBC Merge buffer nonfatal errors:
 *    Merge buffer parity error (rd_buf): dma:read:M:nonfatal
 *    Merge buffer parity error (wr_buf): dma:write:M:nonfatal
 */
/* ARGSUSED */
int
px_err_jbc_merge_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	boolean_t	pri = PX_ERR_IS_PRI(err_bit_descr->bit);
	uint64_t	paddr;
	int		ret;

	if (!pri)
		return (PX_FATAL_GOS);

	paddr = CSR_XR(csr_base, MERGE_TRANSACTION_ERROR_LOG);
	paddr &= MERGE_TRANSACTION_ERROR_LOG_ADDRESS_MASK;

	ret = px_handle_lookup(
		rpdip, DMA_HANDLE, derr->fme_ena, (void *)paddr);

	return ((ret == DDI_FM_FATAL) ? PX_FATAL_GOS : PX_NONFATAL);
}

/* JBC Jbusint IN - see io erpt doc, section 1.3 */
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

	return (PX_OK);
}

/*
 * JBC Jbusint IN nonfatal errors: PA logged in Jbusint In Transaction Error
 * Log Reg[42:0].
 *     CE async fault error: nonfatal
 *     Jbus bus error: dma::nonfatal
 *     Jbus unmapped error: pio|dma:rdwr:M:nonfatal
 *     Write data parity error: pio/write:M:nonfatal
 *     Read data parity error: pio/read:M:nonfatal
 *     Illegal NCWR bytemask: pio:write:M:nonfatal
 *     Illegal NCRD bytemask: pio:write:M:nonfatal
 *     Invalid jbus transaction: nonfatal
 */
/* ARGSUSED */
int
px_err_jbc_jbusint_in_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	boolean_t	pri = PX_ERR_IS_PRI(err_bit_descr->bit);
	uint64_t	paddr;
	int		ret;

	if (!pri)
		return (PX_FATAL_GOS);

	paddr = CSR_XR(csr_base, JBCINT_IN_TRANSACTION_ERROR_LOG);
	paddr &= JBCINT_IN_TRANSACTION_ERROR_LOG_ADDRESS_MASK;

	ret = px_handle_lookup(
		rpdip, DMA_HANDLE, derr->fme_ena, (void *)paddr);

	return ((ret == DDI_FM_FATAL) ? PX_FATAL_GOS : PX_NONFATAL);
}


/* JBC Jbusint Out - see io erpt doc, section 1.4 */
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

	return (PX_OK);
}

/* JBC Dmcint ODCD - see io erpt doc, section 1.5 */
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

	return (PX_OK);
}

/*
 * JBC Dmcint ODCO nonfatal errer handling -
 *    PIO data parity error: pio:write:M:nonfatal
 */
/* ARGSUSED */
int
px_err_jbc_dmcint_odcd_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	boolean_t	pri = PX_ERR_IS_PRI(err_bit_descr->bit);
	uint64_t	paddr;
	int		ret;

	if (!pri)
		return (PX_FATAL_GOS);

	paddr = CSR_XR(csr_base, DMCINT_ODCD_ERROR_LOG);
	paddr &= DMCINT_ODCD_ERROR_LOG_ADDRESS_MASK;

	ret = px_handle_lookup(
		rpdip, DMA_HANDLE, derr->fme_ena, (void *)paddr);

	return ((ret == DDI_FM_FATAL) ? PX_FATAL_GOS : PX_NONFATAL);
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
		return (PX_FATAL_GOS);
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
		return (PX_FATAL_SW);

	return (px_err_jbc_dmcint_odcd_handle(rpdip, csr_base, derr,
	    err_reg_descr, err_bit_descr));
}

/* JBC Dmcint IDC - see io erpt doc, section 1.6 */
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

	return (PX_OK);
}

/* JBC CSR - see io erpt doc, section 1.7 */
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

	return (PX_OK);
}

/*
 * JBC CSR errer handling -
 * Ebus ready timeout error: pio:rdwr:M:nonfatal
 */
/* ARGSUSED */
int
px_err_jbc_csr_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	boolean_t	pri = PX_ERR_IS_PRI(err_bit_descr->bit);
	uint64_t	paddr;
	int		ret;

	if (!pri)
		return (PX_FATAL_GOS);

	paddr = CSR_XR(csr_base, CSR_ERROR_LOG);
	paddr &= CSR_ERROR_LOG_ADDRESS_MASK;

	ret = px_handle_lookup(
		rpdip, DMA_HANDLE, derr->fme_ena, (void *)paddr);

	return ((ret == DDI_FM_FATAL) ? PX_FATAL_GOS : PX_NONFATAL);
}

/* JBC Dmcint IDC - see io erpt doc, section 1.6 */

/* DMC IMU RDS - see io erpt doc, section 2.1 */
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

	return (PX_OK);
}

/* imu function to handle all Received but Not Enabled errors */
/* ARGSUSED */
int
px_err_imu_rbne_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	uint64_t	imu_log_enable, imu_intr_enable;
	int		mask = BITMASK(err_bit_descr->bit);
	int		err = PX_NONFATAL;

	imu_log_enable = CSR_XR(csr_base, err_reg_descr->log_addr);
	imu_intr_enable = CSR_XR(csr_base, err_reg_descr->enable_addr);

	/*
	 * If matching bit is not set, meaning corresponding rbne not
	 * enabled, then receiving it indicates some sort of malfunction
	 * possibly in hardware.
	 *
	 * Other wise, software may have intentionally disabled certain
	 * errors for a period of time within which the occuring of the
	 * disabled errors become rbne, that is non fatal.
	 */

	if (!(imu_log_enable & imu_intr_enable & mask))
		err = PX_FATAL_GOS;

	return (err);
}

/*
 * No platforms uses PME. Any PME received is simply logged
 * for analysis.
 */
/* ARGSUSED */
int
px_err_imu_pme_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	px_t		*px_p = DIP_TO_STATE(rpdip);

	px_p->px_pme_ignored++;
	return (PX_NONFATAL);
}

/* handle EQ overflow */
/* ARGSUSED */
int
px_err_imu_eq_ovfl_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	px_t			*px_p = DIP_TO_STATE(rpdip);
	px_msiq_state_t 	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	msiqid_t		eqno;
	pci_msiq_state_t	msiq_state;
	int			err = PX_NONFATAL;
	int			i;

	eqno = msiq_state_p->msiq_1st_msiq_id;
	for (i = 0; i < msiq_state_p->msiq_cnt; i++) {
		if (px_lib_msiq_getstate(rpdip, eqno, &msiq_state) ==
			DDI_SUCCESS) {
			if (msiq_state == PCI_MSIQ_STATE_ERROR) {
				err = PX_FATAL_GOS;
			}
		}
	}

	return (err);
}

/* DMC IMU SCS - see io erpt doc, section 2.2 */
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

	return (PX_OK);
}

/* DMC IMU - see io erpt doc, section 2.3 */
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

	return (PX_OK);
}

/* DMC MMU TFAR/TFSR - see io erpt doc, section 2.4 */
PX_ERPT_SEND_DEC(mmu_tfar_tfsr)
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
	    FIRE_MMU_TFAR, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_TRANSLATION_FAULT_ADDRESS),
	    FIRE_MMU_TFSR, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, MMU_TRANSLATION_FAULT_STATUS),
	    NULL);

	return (PX_OK);
}

/* DMC MMU - see io erpt doc, section 2.5 */
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

	return (PX_OK);
}

/* imu function to handle all Received but Not Enabled errors */
int
px_err_mmu_rbne_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	boolean_t	pri = PX_ERR_IS_PRI(err_bit_descr->bit);
	uint64_t	mmu_log_enable, mmu_intr_enable;
	uint64_t	mask = BITMASK(err_bit_descr->bit);
	uint64_t	mmu_tfa, mmu_ctrl;
	uint64_t	mmu_enable_bit = 0;
	int		err = PX_NONFATAL;
	int		ret;

	mmu_log_enable = CSR_XR(csr_base, err_reg_descr->log_addr);
	mmu_intr_enable = CSR_XR(csr_base, err_reg_descr->enable_addr);

	mmu_tfa = CSR_XR(csr_base, MMU_TRANSLATION_FAULT_ADDRESS);
	mmu_ctrl = CSR_XR(csr_base, MMU_CONTROL_AND_STATUS);

	switch (err_bit_descr->bit) {
	case MMU_INTERRUPT_STATUS_BYP_ERR_P:
		mmu_enable_bit = BITMASK(MMU_CONTROL_AND_STATUS_BE);
		break;
	case MMU_INTERRUPT_STATUS_TRN_ERR_P:
		mmu_enable_bit = BITMASK(MMU_CONTROL_AND_STATUS_TE);
		break;
	default:
		mmu_enable_bit = 0;
		break;
	}

	/*
	 * If the interrupts are enabled and Translation/Bypass Enable bit
	 * was set, then panic.  This error should not have occured.
	 */
	if (mmu_log_enable & mmu_intr_enable &
	    (mmu_ctrl & mmu_enable_bit)) {
		err = PX_FATAL_GOS;
	} else {
		if (!pri)
			return (PX_FATAL_GOS);

		ret = px_handle_lookup(
			rpdip, DMA_HANDLE, derr->fme_ena, (void *)mmu_tfa);
		err = (ret == DDI_FM_FATAL) ? PX_FATAL_GOS : PX_NONFATAL;

		/*
		 * S/W bug - this error should always be enabled
		 */

		/* enable error & intr reporting for this bit */
		CSR_XS(csr_base, MMU_ERROR_LOG_ENABLE, mmu_log_enable | mask);
		CSR_XS(csr_base, MMU_INTERRUPT_ENABLE, mmu_intr_enable | mask);

		/* enable translation access/bypass enable */
		CSR_XS(csr_base, MMU_CONTROL_AND_STATUS,
		    mmu_ctrl | mmu_enable_bit);
	}

	return (err);
}

/* Generic error handling functions that involve MMU Translation Fault Addr */
/* ARGSUSED */
int
px_err_mmu_tfa_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	boolean_t	pri = PX_ERR_IS_PRI(err_bit_descr->bit);
	uint64_t	mmu_tfa;
	uint_t		ret;

	if (!pri)
		return (PX_FATAL_GOS);

	mmu_tfa = CSR_XR(csr_base, MMU_TRANSLATION_FAULT_ADDRESS);
	ret = px_handle_lookup(
		rpdip, DMA_HANDLE, derr->fme_ena, (void *)mmu_tfa);

	return ((ret == DDI_FM_FATAL) ? PX_FATAL_GOS : PX_NONFATAL);
}

/* MMU Table walk errors */
/* ARGSUSED */
int
px_err_mmu_tblwlk_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	boolean_t	pri = PX_ERR_IS_PRI(err_bit_descr->bit);
	uint64_t	mmu_tfa;
	uint_t		ret;

	if (!pri)
		return (PX_FATAL_GOS);

	mmu_tfa = CSR_XR(csr_base, MMU_TRANSLATION_FAULT_ADDRESS);
	ret = px_handle_lookup(
		rpdip, DMA_HANDLE, derr->fme_ena, (void *)mmu_tfa);

	return ((ret == DDI_FM_FATAL) ? PX_FATAL_GOS : PX_NONFATAL);
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
	    PX_NONFATAL : PX_OK);
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
	return ((px_p->px_pm_flags & PX_LDN_EXPECTED) ? PX_OK : PX_NONFATAL);
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

	return (PX_OK);
}

/* PCIEX UE Errors */
/* ARGSUSED */
int
px_err_pciex_ue_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	uint32_t	mask = (uint32_t)BITMASK(err_bit_descr->bit);

	return ((err_bit_descr->bit >= 32 && px_fabric_die_rc_ue_gos) ?
	    PX_FATAL_GOS : PX_FABRIC_ERR_SEV(mask, px_fabric_die_rc_ue,
		px_fabric_die_rc_ue_gos));
}

/* PCI-E Uncorrectable Errors - see io erpt doc, section 3.2 */
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

	return (PX_OK);
}

/* PCI-E Uncorrectable Errors - see io erpt doc, section 3.3 */
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

	return (PX_OK);
}

/* PCI-E Uncorrectable Errors - see io erpt doc, section 3.4 */
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

	return (PX_OK);
}

/* PCI-E Uncorrectable Errors - see io erpt doc, section 3.5 */
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

	return (PX_OK);
}

/* PCIEX UE Errors */
/* ARGSUSED */
int
px_err_pciex_ce_handle(dev_info_t *rpdip, caddr_t csr_base,
	ddi_fm_error_t *derr, px_err_reg_desc_t *err_reg_descr,
	px_err_bit_desc_t *err_bit_descr)
{
	uint32_t	mask = (uint32_t)BITMASK(err_bit_descr->bit);

	return ((err_bit_descr->bit >= 32 && px_fabric_die_rc_ce_gos) ?
	    PX_FATAL_GOS : PX_FABRIC_ERR_SEV(mask, px_fabric_die_rc_ce,
		px_fabric_die_rc_ce_gos));
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

	return (PX_OK);
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

	return (PX_OK);
}

/* TLU Other Event Status (rx + tx) - see io erpt doc, section 3.8 */
PX_ERPT_SEND_DEC(pciex_rx_tx_oe)
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
	    FIRE_TLU_ROEEH1L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_RECEIVE_OTHER_EVENT_HEADER1_LOG),
	    FIRE_TLU_ROEEH2L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_RECEIVE_OTHER_EVENT_HEADER2_LOG),
	    FIRE_TLU_TOEEH1L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_TRANSMIT_OTHER_EVENT_HEADER1_LOG),
	    FIRE_TLU_TOEEH2L, DATA_TYPE_UINT64,
	    CSR_XR(csr_base, TLU_TRANSMIT_OTHER_EVENT_HEADER2_LOG),
	    NULL);

	return (PX_OK);
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

	return (PX_OK);
}
