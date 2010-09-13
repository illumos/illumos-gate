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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FM_IO_SUN4UPCI_H
#define	_SYS_FM_IO_SUN4UPCI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Sun4u PCI FMA Event Protocol definitions */

#define	PCI_PSYCHO			"psy"
#define	PCI_SCHIZO			"sch"
#define	PCI_TOMATILLO			"tom"
#define	PCI_XMITS			"xmits"

/* PBM ereport classes */
#define	PCI_PBM_TTO			"pbm.tto"
#define	PCI_PBM_RETRY			"pbm.rl"
#define	PCI_SEC_PBM_TTO			"pbm.s-tto"
#define	PCI_SEC_PBM_RETRY		"pbm.s-rl"
#define	PCI_SEC_MA			"pbm.s-ma"
#define	PCI_SEC_REC_TA			"pbm.s-rta"
#define	PCI_SEC_MDPE			"pbm.s-mdpe"
#define	PCI_PBM_TARG_TTO		"pbm.target-tto"
#define	PCI_PBM_TARG_RETRY		"pbm.target-rl"

/* Schizo/Tomatillo ereport classes */
#define	PCI_SCH_MMU_ERR			"mmu"
#define	PCI_SCH_BUS_UNUSABLE_ERR	"bu"
#define	PCI_SEC_SCH_BUS_UNUSABLE_ERR	"s-bu"
#define	PCI_SCH_SLOT_LOCK_ERR		"sl"
#define	PCI_SCH_SBH			"sbh"

#define	PCI_TOM_MMU_BAD_TSBTBW		"mmu.btt"
#define	PCI_TOM_MMU_BAD_VA		"mmu.bva"
#define	PCI_TOM_MMU_PROT_ERR		"mmu.prot"
#define	PCI_TOM_MMU_INVAL_ERR		"mmu.inval"
#define	PCI_TOM_MMU_TO_ERR		"mmu.to"
#define	PCI_TOM_MMU_UE			"mmu.ue"

/* Psycho ereport classes */

#define	PCI_PSY_SBH			"sbh"

/* IO detected memory ereport classes */
#define	PCI_ECC_DRD_UE			"ecc.drue"
#define	PCI_ECC_DRD_CE			"ecc.drce"
#define	PCI_ECC_DWR_UE			"ecc.dwue"
#define	PCI_ECC_DWR_CE			"ecc.dwce"
#define	PCI_ECC_PIO_UE			"ecc.pue"
#define	PCI_ECC_PIO_CE			"ecc.pce"
#define	PCI_ECC_SEC_DRD_UE		"ecc.s-drue"
#define	PCI_ECC_SEC_DRD_CE		"ecc.s-drce"
#define	PCI_ECC_SEC_DWR_UE		"ecc.s-dwue"
#define	PCI_ECC_SEC_DWR_CE		"ecc.s-dwce"
#define	PCI_ECC_SEC_PIO_UE		"ecc.s-pue"
#define	PCI_ECC_SEC_PIO_CE		"ecc.s-pce"


/* Safari ereport classes */
#define	SAFARI_APERR			"saf.ape"
#define	SAFARI_UNMAP_ERR		"saf.um"
#define	SAFARI_TO_ERR			"saf.to"
#define	SAFARI_BUS_ERR			"saf.bus"
#define	SAFARI_DSTAT_ERR		"saf.dstat"
#define	SAFARI_BAD_CMD			"saf.bc"
#define	SAFARI_SSM_DIS			"saf.smm-dis"
#define	SAFARI_BAD_CMD_PCIA		"saf.bca"
#define	SAFARI_BAD_CMD_PCIB		"saf.bcb"
#define	SAFARI_PAR_ERR_INT_PCIB		"saf.parb"
#define	SAFARI_PAR_ERR_INT_PCIA		"saf.para"
#define	SAFARI_PAR_ERR_INT_SAF		"saf.pars"
#define	SAFARI_PLL_ERR_PCIB		"saf.pllb"
#define	SAFARI_PLL_ERR_PCIA		"saf.plla"
#define	SAFARI_PLL_ERR_SAF		"saf.plls"
#define	SAFARI_SAF_CIQ_TO		"saf.ciq-to"
#define	SAFARI_SAF_LPQ_TO		"saf.lpq-to"
#define	SAFARI_SAF_SFPQ_TO		"saf.sfpq-to"
#define	SAFARI_SAF_UFPQ_TO		"saf.ufpq-to"
#define	SAFARI_CPU0_PAR_SINGLE		"saf.cpu0-par"
#define	SAFARI_CPU0_PAR_BIDI		"saf.cpu0-bidi"
#define	SAFARI_CPU1_PAR_SINGLE		"saf.cpu1-par"
#define	SAFARI_CPU1_PAR_BIDI		"saf.cpu1-bidi"

/* Jbus ereport classes */
#define	JBUS_APERR			"jbus.ape"
#define	JBUS_PWR_DATA_PERR		"jbus.pwpe"
#define	JBUS_DRD_DATA_PERR		"jbus.drpe"
#define	JBUS_DWR_DATA_PERR		"jbus.dwpe"
#define	JBUS_CTL_PERR			"jbus.cpe"
#define	JBUS_ILL_BYTE_EN		"jbus.ibe"
#define	JBUS_ILL_COH_IN			"jbus.iis"
#define	JBUS_SNOOP_ERR_RD		"jbus.srd"
#define	JBUS_SNOOP_ERR_RDS		"jbus.srds"
#define	JBUS_SNOOP_ERR_RDSA		"jbus.srdsa"
#define	JBUS_SNOOP_ERR_OWN		"jbus.sown"
#define	JBUS_SNOOP_ERR_RDO		"jbus.srdo"
#define	JBUS_BAD_CMD			"jbus.bc"
#define	JBUS_UNMAP_ERR			"jbus.um"
#define	JBUS_TO_ERR			"jbus.to"
#define	JBUS_BUS_ERR			"jbus.bus"
#define	JBUS_TO_EXP_ERR			"jbus.to-exp"
#define	JBUS_SNOOP_ERR_GR		"jbus.sgr"
#define	JBUS_SNOOP_ERR_PCI		"jbus.spci"
#define	JBUS_SNOOP_ERR			"jbus.snp"

/* PBM ereport payload */
#define	PCI_PBM_CSR			"pbm-csr"
#define	PCI_PBM_AFSR			"pbm-afsr"
#define	PCI_PBM_AFAR			"pbm-afar"
#define	PCI_PBM_SLOT			"errant-slot"
#define	PCI_PBM_VALOG			"pbm-valog"

/* IOMMU ereport payload */
#define	PCI_PBM_IOMMU_CTRL		"iommu-csr"
#define	PCI_PBM_IOMMU_TFAR		"iommu-tfar"

/* IO detected memory error payload */
#define	PCI_ECC_AFSR			"ecc-afsr"
#define	PCI_ECC_AFAR			"ecc-afar"
#define	PCI_ECC_CTRL			"ecc-ctrl"
#define	PCI_ECC_SYND			"ecc-syndrome"
#define	PCI_ECC_TYPE			"ecc-err-type"
#define	PCI_ECC_DISP			"ecc-err-disposition"
#define	PCI_ECC_UNUM			"mem-unum"
#define	PCI_ECC_RESOURCE		"mem-resource"

/* Safari ereport payload */
#define	SAFARI_CSR			"safari-csr"
#define	SAFARI_ERR			"safari-err"
#define	SAFARI_INTR			"safari-intr"
#define	SAFARI_ELOG			"safari-elog"
#define	SAFARI_PCR			"safari-pcr"
#define	SAFARI_RESOURCE			"safari-resource"
#define	PCI_PBM_LOG_1			"pbm-log1"
#define	PCI_PBM_LOG_2			"pbm-log2"

/* Jbus ereport payload */
#define	JBUS_CSR			"jbus-csr"
#define	JBUS_ERR			"jbus-err"
#define	JBUS_INTR			"jbus-intr"
#define	JBUS_ELOG			"jbus-elog"
#define	JBUS_PCR			"jbus-pcr"
#define	JBUS_RESOURCE			"jbus-resource"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FM_IO_SUN4UPCI_H */
