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

#ifndef _SYS_FM_IO_PCI_H
#define	_SYS_FM_IO_PCI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCI_ERROR_SUBCLASS	"pci"
#define	PCI_SEC_ERROR_SUBCLASS	"sec"

/* Common PCI ereport classes */
#define	PCI_DET_PERR		"dpe"
#define	PCI_MDPE		"mdpe"
#define	PCI_REC_SERR		"rserr"
#define	PCI_SIG_SERR		"sserr"
#define	PCI_MA			"ma"
#define	PCI_REC_TA		"rta"
#define	PCI_SIG_TA		"sta"
#define	PCI_DTO			"dto"
#define	PCI_TARG_MDPE		"target-mdpe"
#define	PCI_TARG_MA		"target-ma"
#define	PCI_TARG_REC_TA		"target-rta"
#define	PCI_NR			"nr"

/* PCI Error payload name fields */
#define	PCI_CONFIG_STATUS	"pci-status"
#define	PCI_CONFIG_COMMAND	"pci-command"
#define	PCI_SEC_CONFIG_STATUS	"pci-sec-status"
#define	PCI_BCNTRL		"pci-bdg-ctrl"
#define	PCI_PA			"pci-pa"

/*
 * PCI-X extensions
 */
#define	PCIX_ERROR_SUBCLASS	"pcix"
#define	PCIX_SEC_ERROR_SUBCLASS "sec-"

/* Common PCI-X ereport classes */
#define	PCIX_ECC_CE_ADDR	"ecc.ce-addr"
#define	PCIX_ECC_CE_ATTR	"ecc.ce-attr"
#define	PCIX_ECC_CE_DATA	"ecc.ce-data"
#define	PCIX_ECC_UE_ADDR	"ecc.ue-addr"
#define	PCIX_ECC_UE_ATTR	"ecc.ue-attr"
#define	PCIX_ECC_UE_DATA	"ecc.ue-data"
#define	PCIX_RX_SPL_MSG		"rx-spl"
#define	PCIX_ECC_S_CE		"s-ce"
#define	PCIX_ECC_S_UE		"s-ue"
#define	PCIX_SPL_DIS		"spl-dis"
#define	PCIX_BSS_SPL_DLY	"spl-dly"
#define	PCIX_BSS_SPL_OR		"spl-or"
#define	PCIX_UNEX_SPL		"unex-spl"

#define	PCIX_SEC_STATUS		"pcix-sec-status"
#define	PCIX_BDG_STAT		"pcix-bdg-stat"
#define	PCIX_COMMAND		"pcix-command"
#define	PCIX_STATUS		"pcix-status"
#define	PCIX_ECC_CTLSTAT	"pcix-ecc-ctlstat"
#define	PCIX_ECC_ATTR		"pcix-ecc-attr"

/*
 * PCI Express extensions
 */
#define	PCIEX_ERROR_SUBCLASS		"pciex"

/* Common PCI Express ereport classes */
#define	PCIEX_RE		"pl.re"
#define	PCIEX_TE		"pl.te"

#define	PCIEX_SD		"dl.sd"
#define	PCIEX_BDP		"dl.bdllp"
#define	PCIEX_BTP		"dl.btlp"
#define	PCIEX_DLP		"dl.dllp"
#define	PCIEX_RNR		"dl.rnr"
#define	PCIEX_RTO		"dl.rto"

#define	PCIEX_CA		"tl.ca"
#define	PCIEX_CTO		"tl.cto"
#define	PCIEX_ECRC		"tl.ecrc"
#define	PCIEX_FCP		"tl.fcp"
#define	PCIEX_MFP		"tl.mtlp"
#define	PCIEX_POIS		"tl.ptlp"
#define	PCIEX_ROF		"tl.rof"
#define	PCIEX_UC		"tl.uc"
#define	PCIEX_UR		"tl.ur"

#define	PCIEX_INTERR		"bdg.sec-interr"
#define	PCIEX_S_MA_SC		"bdg.sec-ma-sc"
#define	PCIEX_S_PERR		"bdg.sec-perr"
#define	PCIEX_S_RMA		"bdg.sec-rma"
#define	PCIEX_S_RTA		"bdg.sec-rta"
#define	PCIEX_S_SERR		"bdg.sec-serr"
#define	PCIEX_S_TA_SC		"bdg.sec-ta-sc"
#define	PCIEX_S_TEX		"bdg.sec-tex"
#define	PCIEX_S_UADR		"bdg.sec-uadr"
#define	PCIEX_S_UAT		"bdg.sec-uat"
#define	PCIEX_S_UDE		"bdg.sec-ude"
#define	PCIEX_S_USC		"bdg.usc"
#define	PCIEX_S_USCMD		"bdg.uscmd"

#define	PCIEX_RC_FE_MSG		"rc.fe-msg"
#define	PCIEX_RC_NFE_MSG	"rc.nfe-msg"
#define	PCIEX_RC_CE_MSG		"rc.ce-msg"
#define	PCIEX_RC_MCE_MSG	"rc.mce-msg"
#define	PCIEX_RC_MUE_MSG	"rc.mue-msg"

#define	PCIEX_CORR		"correctable"
#define	PCIEX_FAT		"fatal"
#define	PCIEX_NONFAT		"nonfatal"
#define	PCIEX_NADV		"noadverr"
#define	PCIEX_ANFE		"a-nonfatal"

/* PCI Express payload name fields */
#define	PCIEX_DEVSTS_REG	"dev-status"
#define	PCIEX_LINKSTS_REG	"link-status"
#define	PCIEX_ROOT_ERRSTS_REG	"rc-status"
#define	PCIEX_CE_STATUS_REG	"ce-status"
#define	PCIEX_UE_STATUS_REG	"ue-status"
#define	PCIEX_UE_SEV_REG	"ue-severity"
#define	PCIEX_SEC_UE_STATUS	"sue-status"
#define	PCIEX_SRC_ID		"source-id"
#define	PCIEX_SRC_VALID		"source-valid"
#define	PCIEX_ADV_CTL		"adv-ctl"
#define	PCIEX_UE_HDR0		"ue_hdr0"
#define	PCIEX_UE_HDR1		"ue_hdr1"
#define	PCIEX_UE_HDR2		"ue_hdr2"
#define	PCIEX_UE_HDR3		"ue_hdr3"
#define	PCIEX_SUE_HDR0		"sue_hdr0"
#define	PCIEX_SUE_HDR1		"sue_hdr1"
#define	PCIEX_SUE_HDR2		"sue_hdr2"
#define	PCIEX_SUE_HDR3		"sue_hdr3"

/* Common fabric class names */
#define	PCIEX_FABRIC		"fabric"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FM_IO_PCI_H */
