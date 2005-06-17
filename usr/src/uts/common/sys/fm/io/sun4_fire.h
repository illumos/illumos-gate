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

#ifndef _SYS_FM_IO_SUN4_FIRE_H
#define	_SYS_FM_IO_SUN4_FIRE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Fire Ereport Classes
 */

#define	PCIEX_FIRE		"fire"

/* FIRE's JBUS ereport classes */
#define	FIRE_JBC_MB_PEA			"jbc.mb_pea"
#define	FIRE_JBC_CPE			"jbc.cpe"
#define	FIRE_JBC_APE			"jbc.ape"
#define	FIRE_JBC_PIO_CPE		"jbc.pio_cpe"
#define	FIRE_JBC_JTCEEW			"jbc.jtceew"
#define	FIRE_JBC_JTCEEI			"jbc.jtceei"
#define	FIRE_JBC_JTCEER			"jbc.jtceer"
#define	FIRE_JBC_MB_PER			"jbc.mb_per"
#define	FIRE_JBC_MB_PEW			"jbc.mb_pew"
#define	FIRE_JBC_UE_ASYN		"jbc.ue_asyn"
#define	FIRE_JBC_CE_ASYN		"jbc.ce_asyn"
#define	FIRE_JBC_JTE			"jbc.jte"
#define	FIRE_JBC_JBE			"jbc.jbe"
#define	FIRE_JBC_JUE			"jbc.jue"
#define	FIRE_JBC_ICISE			"jbc.icise"
#define	FIRE_JBC_WR_DPE			"jbc.wr_dpe"
#define	FIRE_JBC_RD_DPE			"jbc.rd_dpe"
#define	FIRE_JBC_ILL_BMW		"jbc.ill_bmw"
#define	FIRE_JBC_ILL_BMR		"jbc.ill_bmr"
#define	FIRE_JBC_BJC			"jbc.bjc"
#define	FIRE_JBC_IJP			"jbc.ijp"
#define	FIRE_JBC_PIO_UNMAP_RD		"jbc.pio_unmap_rd"
#define	FIRE_JBC_PIO_UNMAP		"jbc.pio_unmap"
#define	FIRE_JBC_PIO_DPE		"jbc.pio_dpe"
#define	FIRE_JBC_ILL_ACC		"jbc.ill_acc"
#define	FIRE_JBC_ILL_ACC_RD		"jbc.ill_acc_rd"
#define	FIRE_JBC_UNSOL_RD		"jbc.unsol_rd"
#define	FIRE_JBC_UNSOL_INTR		"jbc.unsol_intr"
#define	FIRE_JBC_EBUS_TO		"jbc.ebus_to"


/* FIRE's DMC ereport classes */
#define	FIRE_DMC_MSI_NOT_EN		"dmc.msi_not_en"
#define	FIRE_DMC_MSI_PAR_ERR		"dmc.msi_par_err"
#define	FIRE_DMC_MSI_MAL_ERR		"dmc.msi_mal_err"
#define	FIRE_DMC_COR_MES_NOT_EN		"dmc.cor_not_en"
#define	FIRE_DMC_NONFATAL_MES_NOT_EN	"dmc.nonfatal_not_en"
#define	FIRE_DMC_FATAL_MES_NOT_EN	"dmc.fatal_not_en"
#define	FIRE_DMC_PMPME_MES_NOT_EN	"dmc.pmpme_not_en"
#define	FIRE_DMC_PMEACK_MES_NOT_EN	"dmc.pmeack_not_en"
#define	FIRE_DMC_EQ_NOT_EN		"dmc.eq_not_en"
#define	FIRE_DMC_EQ_OVER		"dmc.eq_over"
#define	FIRE_DMC_BYP_ERR		"dmc.byp_err"
#define	FIRE_DMC_BYP_OOR		"dmc.byp_oor"
#define	FIRE_DMC_TRN_ERR		"dmc.trn_err"
#define	FIRE_DMC_TRN_OOR		"dmc.trn_oor"
#define	FIRE_DMC_TTE_INV		"dmc.tte_inv"
#define	FIRE_DMC_TTE_PRT		"dmc.tte_prt"
#define	FIRE_DMC_TTC_DPE		"dmc.ttc_dpe"
#define	FIRE_DMC_TBW_DME		"dmc.tbw_dme"
#define	FIRE_DMC_TBW_UDE		"dmc.tbw_ude"
#define	FIRE_DMC_TBW_ERR		"dmc.tbw_err"
#define	FIRE_DMC_TBW_DPE		"dmc.tbw_dpe"
#define	FIRE_DMC_TTC_CAE		"dmc.ttc_cae"


/* FIRE's PEC ereport classes */
#define	FIRE_PEC_IHB_PE			"pec.ihb_pe"
#define	FIRE_PEC_MRC			"pec.mrc"
#define	FIRE_PEC_WUC			"pec.wuc"
#define	FIRE_PEC_RUC			"pec.ruc"
#define	FIRE_PEC_CRS			"pec.crs"
#define	FIRE_PEC_IIP			"pec.iip"
#define	FIRE_PEC_EDP			"pec.edp"
#define	FIRE_PEC_EHP			"pec.ehp"
#define	FIRE_PEC_LIN			"pec.lin"
#define	FIRE_PEC_LRS			"pec.lrs"
#define	FIRE_PEC_LDN			"pec.ldn"
#define	FIRE_PEC_LUP			"pec.lup"
#define	FIRE_PEC_ERU			"pec.eru"
#define	FIRE_PEC_ERO			"pec.ero"
#define	FIRE_PEC_EMP			"pec.emp"
#define	FIRE_PEC_EPE			"pec.epe"
#define	FIRE_PEC_ERP			"pec.erp"
#define	FIRE_PEC_EIP			"pec.eip"

/* Primary error */
#define	FIRE_PRIMARY			"primary"

/* PEC ereport payload */
#define	FIRE_ILU_ELE			"ilu-ele"
#define	FIRE_ILU_ESS			"ilu-ess"
#define	FIRE_ILU_IE			"ilu-ie"
#define	FIRE_ILU_IS			"ilu-is"
#define	FIRE_TLU_CELE			"tlu-cele"
#define	FIRE_TLU_CESS			"tlu-cess"
#define	FIRE_TLU_CIE			"tlu-cie"
#define	FIRE_TLU_CIS			"tlu-cis"
#define	FIRE_TLU_OEELE			"tlu-oeele"
#define	FIRE_TLU_OEESS			"tlu-oeess"
#define	FIRE_TLU_OEIE			"tlu-oeie"
#define	FIRE_TLU_OEIS			"tlu-oeis"
#define	FIRE_TLU_ROEEH1L		"tlu-roeeh1l"
#define	FIRE_TLU_ROEEH2L		"tlu-roeeh2l"
#define	FIRE_TLU_RUEH1L			"tlu-rueh1l"
#define	FIRE_TLU_RUEH2L			"tlu-rueh2l"
#define	FIRE_TLU_TOEEH1L		"tlu-toeeh1l"
#define	FIRE_TLU_TOEEH2L		"tlu-toeeh2l"
#define	FIRE_TLU_TUEH1L			"tlu-tueh1l"
#define	FIRE_TLU_TUEH2L			"tlu-tueh2l"
#define	FIRE_TLU_UELE			"tlu-uele"
#define	FIRE_TLU_UESS			"tlu-uess"
#define	FIRE_TLU_UIE			"tlu-uie"
#define	FIRE_TLU_UIS			"tlu-uis"

/* DMC ereport payload */
#define	FIRE_IMU_ELE			"imu-ele"
#define	FIRE_IMU_ESS			"imu-ess"
#define	FIRE_IMU_IE			"imu-ie"
#define	FIRE_IMU_IS			"imu-is"
#define	FIRE_IMU_RDS			"imu-rds"
#define	FIRE_IMU_SCS			"imu-scs"
#define	FIRE_MMU_ELE			"mmu-ele"
#define	FIRE_MMU_ESS			"mmu-ess"
#define	FIRE_MMU_IE			"mmu-ie"
#define	FIRE_MMU_IS			"mmu-is"
#define	FIRE_MMU_TFAR			"mmu-tfar"
#define	FIRE_MMU_TFSR			"mmu-tfsr"

/* JBC ereport payload */
#define	FIRE_JBC_DMC_IDC		"jbc-dmc-idc"
#define	FIRE_JBC_DMC_ODCD		"jbc-dmc-odcd"
#define	FIRE_JBC_ELE			"jbc-ele"
#define	FIRE_JBC_ESS			"jbc-ess"
#define	FIRE_JBC_FEL1			"jbc-fel1"
#define	FIRE_JBC_FEL2			"jbc-fel2"
#define	FIRE_JBC_IE			"jbc-ie"
#define	FIRE_JBC_IS			"jbc-is"
#define	FIRE_JBC_JITEL1			"jbc-jitel1"
#define	FIRE_JBC_JITEL2			"jbc-jitel2"
#define	FIRE_JBC_JOTEL1			"jbc-jotel1"
#define	FIRE_JBC_JOTEL2			"jbc-jotel2"
#define	FIRE_JBC_MTEL			"jbc-mtel"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FM_IO_SUN4_FIRE_H */
