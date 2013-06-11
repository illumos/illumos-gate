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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _AHCIREG_H
#define	_AHCIREG_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	AHCI_MAX_PORTS		32
#define	AHCI_PORT_MAX_CMD_SLOTS	32

#define	VIA_VENID		0x1106

/*
 * In AHCI spec, command table contains a list of 0 (no data transfer)
 * to up to 65,535 scatter/gather entries for the data transfer.
 */
#define	AHCI_MAX_PRDT_NUMBER	65535
#define	AHCI_MIN_PRDT_NUMBER	1

/*
 * The default value of s/g entrie is 257, at least 1MB (4KB/pg * 256) + 1
 * if misaligned, and it's tuable by setting ahci_dma_prdt_number in
 * /etc/system file.
 */
#define	AHCI_PRDT_NUMBER	257

/* PCI header offset for AHCI Base Address */
#define	AHCI_PCI_RNUM		0x24

/* various global HBA capability bits */
#define	AHCI_HBA_CAP_NP		(0x1f << 0) /* number of ports */
#define	AHCI_HBA_CAP_SXS	(0x1 << 5) /* external SATA */
#define	AHCI_HBA_CAP_EMS	(0x1 << 6) /* enclosure management */
#define	AHCI_HBA_CAP_CCCS	(0x1 << 7) /* command completed coalescing */
#define	AHCI_HBA_CAP_NCS	(0x1f << 8) /* number of command slots */
#define	AHCI_HBA_CAP_PSC	(0x1 << 13) /* partial state capable */
#define	AHCI_HBA_CAP_SSC	(0x1 << 14) /* slumber state capable */
#define	AHCI_HBA_CAP_PMD	(0x1 << 15) /* PIO multiple DRQ block */
#define	AHCI_HBA_CAP_FBSS	(0x1 << 16) /* FIS-based switching */
#define	AHCI_HBA_CAP_SPM	(0x1 << 17) /* port multiplier */
#define	AHCI_HBA_CAP_SAM	(0x1 << 18) /* AHCI mode only */
#define	AHCI_HBA_CAP_SNZO	(0x1 << 19) /* non-zero DMA offsets */
#define	AHCI_HBA_CAP_ISS	(0xf << 20) /* interface speed support */
#define	AHCI_HBA_CAP_SCLO	(0x1 << 24) /* command list override */
#define	AHCI_HBA_CAP_SAL	(0x1 << 25) /* activity LED */
#define	AHCI_HBA_CAP_SALP	(0x1 << 26) /* aggressive link power mgmt */
#define	AHCI_HBA_CAP_SSS	(0x1 << 27) /* staggered  spin-up */
#define	AHCI_HBA_CAP_SMPS	(0x1 << 28) /* mechanical presence switch */
#define	AHCI_HBA_CAP_SSNTF	(0x1 << 29) /* Snotification register */
#define	AHCI_HBA_CAP_SNCQ	(0x1 << 30) /* Native Command Queuing */
#define	AHCI_HBA_CAP_S64A	((uint32_t)0x1 << 31) /* 64-bit addressing */
#define	AHCI_HBA_CAP_NCS_SHIFT	8  /* Number of command slots */
#define	AHCI_HBA_CAP_ISS_SHIFT	20 /* Interface speed support */

/* various global HBA control bits */
#define	AHCI_HBA_GHC_HR		(0x1 << 0) /* HBA Reset */
#define	AHCI_HBA_GHC_IE		(0x1 << 1) /* Interrupt Enable */
#define	AHCI_HBA_GHC_MRSM	(0x1 << 2) /* MSI Revert to Single Message */
#define	AHCI_HBA_GHC_AE		((uint32_t)0x1 << 31) /* AHCI Enable */

/* various global HBA Command Completion Coalescing (CCC) control bits */
#define	AHCI_HBA_CCC_CTL_EN		0x00000001  /* Enable */
#define	AHCI_HBA_CCC_CTL_INT_MASK	(0x1f << 3) /* Interrupt */
#define	AHCI_HBA_CCC_CTL_CC_MASK	0x0000ff00  /* Command Completions */
#define	AHCI_HBA_CCC_CTL_TV_MASK	0xffff0000  /* Timeout Value */
#define	AHCI_HBA_CCC_CTL_INT_SHIFT	3
#define	AHCI_HBA_CCC_CTL_CC_SHIFT	8
#define	AHCI_HBA_CCC_CTL_TV_SHIFT	16

/* global HBA Enclosure Management Location (EM_LOC) */
#define	AHCI_HBA_EM_LOC_SZ_MASK		0x0000ffff /* Buffer Size */
#define	AHCI_HBA_EM_LOC_OFST_MASK	0xffff0000 /* Offset */
#define	AHCI_HBA_EM_LOC_OFST_SHIFT	16

/* global HBA Enclosure Management Control (EM_CTL) bits */
#define	AHCI_HBA_EM_CTL_STS_MR		(0x1 << 0) /* Message Received */
#define	AHCI_HBA_EM_CTL_CTL_TM		(0x1 << 8) /* Transmit Message */
#define	AHCI_HBA_EM_CTL_CTL_RST		(0x1 << 9) /* Reset */
#define	AHCI_HBA_EM_CTL_SUPP_LED	(0x1 << 16) /* LED Message Types */
#define	AHCI_HBA_EM_CTL_SUPP_SAFTE	(0x1 << 17) /* SAF-TE EM Messages */
#define	AHCI_HBA_EM_CTL_SUPP_SES2	(0x1 << 18) /* SES-2 EM Messages */
#define	AHCI_HBA_EM_CTL_SUPP_SGPIO	(0x1 << 19) /* SGPIO EM Messages */
#define	AHCI_HBA_EM_CTL_ATTR_SMB	(0x1 << 24) /* Single Message Buffer */
#define	AHCI_HBA_EM_CTL_ATTR_XMT	(0x1 << 25) /* Transmit Only */
#define	AHCI_HBA_EM_CTL_ATTR_ALHD	(0x1 << 26) /* Activity LED HW Driven */
#define	AHCI_HBA_EM_CTL_ATTR_PM		(0x1 << 27) /* PM Support */


/* global HBA registers definitions */
#define	AHCI_GLOBAL_OFFSET(ahci_ctlp)	(ahci_ctlp->ahcictl_ahci_addr)
	/* HBA Capabilities */
#define	AHCI_GLOBAL_CAP(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x00)
	/* Global HBA Control */
#define	AHCI_GLOBAL_GHC(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x04)
	/* Interrupt Status Register */
#define	AHCI_GLOBAL_IS(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x08)
	/* Ports Implemented */
#define	AHCI_GLOBAL_PI(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x0c)
	/* AHCI Version */
#define	AHCI_GLOBAL_VS(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x10)
	/* Command Completion Coalescing Control */
#define	AHCI_GLOBAL_CCC_CTL(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x14)
	/* Command Completion Coalescing Ports */
#define	AHCI_GLOBAL_CCC_PORTS(ahci_ctlp)	\
					(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x18)
	/* Enclosure Management Location */
#define	AHCI_GLOBAL_EM_LOC(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x1c)
	/* Enclosure Management Control */
#define	AHCI_GLOBAL_EM_CTL(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x20)
	/* HBA Capabilities Extended (AHCI spec 1.2) */
#define	AHCI_GLOBAL_CAP2(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x24)
	/* BIOS/OS Handoff Control and Status (AHCI spec 1.2) */
#define	AHCI_GLOBAL_BOHC(ahci_ctlp)	(AHCI_GLOBAL_OFFSET(ahci_ctlp) + 0x28)

#define	AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)	\
	((0x1 << port) & ahci_ctlp->ahcictl_ports_implemented)

/* various port interrupt bits */
	/* Device to Host Register FIS Interrupt */
#define	AHCI_INTR_STATUS_DHRS (0x1 << 0)
	/* PIO Setup FIS Interrupt */
#define	AHCI_INTR_STATUS_PSS			(0x1 << 1)
	/* DMA Setup FIS Interrupt */
#define	AHCI_INTR_STATUS_DSS			(0x1 << 2)
	/* Set Device Bits Interrupt */
#define	AHCI_INTR_STATUS_SDBS			(0x1 << 3)
	/* Unknown FIS Interrupt */
#define	AHCI_INTR_STATUS_UFS			(0x1 << 4)
	/* Descriptor Processed */
#define	AHCI_INTR_STATUS_DPS			(0x1 << 5)
	/* Port Connect Change Status */
#define	AHCI_INTR_STATUS_PCS			(0x1 << 6)
	/* Device Mechanical Presence Status */
#define	AHCI_INTR_STATUS_DMPS			(0x1 << 7)
	/* PhyRdy Change Status */
#define	AHCI_INTR_STATUS_PRCS			(0x1 << 22)
	/* Incorrect Port Multiplier Status */
#define	AHCI_INTR_STATUS_IPMS			(0x1 << 23)
	/* Overflow Status */
#define	AHCI_INTR_STATUS_OFS			(0x1 << 24)
	/* Interface Non-fatal Error Status */
#define	AHCI_INTR_STATUS_INFS			(0x1 << 26)
	/* Interface Fatal Error Status */
#define	AHCI_INTR_STATUS_IFS			(0x1 << 27)
	/* Host Bus Data Error Status */
#define	AHCI_INTR_STATUS_HBDS			(0x1 << 28)
	/* Host Bus Fatal Error Status */
#define	AHCI_INTR_STATUS_HBFS			(0x1 << 29)
	/* Task File Error Status */
#define	AHCI_INTR_STATUS_TFES			(0x1 << 30)
	/* Cold Port Detect Status */
#define	AHCI_INTR_STATUS_CPDS			((uint32_t)0x1 << 31)
#define	AHCI_PORT_INTR_MASK			0xfec000ff

/* port command and status bits */
#define	AHCI_CMD_STATUS_ST	(0x1 << 0) /* Start */
#define	AHCI_CMD_STATUS_SUD	(0x1 << 1) /* Spin-up device */
#define	AHCI_CMD_STATUS_POD	(0x1 << 2) /* Power on device */
#define	AHCI_CMD_STATUS_CLO	(0x1 << 3) /* Command list override */
#define	AHCI_CMD_STATUS_FRE	(0x1 << 4) /* FIS receive enable */
#define	AHCI_CMD_STATUS_CCS	(0x1f << 8) /* Current command slot */
			/* Mechanical presence switch state */
#define	AHCI_CMD_STATUS_MPSS	(0x1 << 13)
#define	AHCI_CMD_STATUS_FR	(0x1 << 14) /* FIS receiving running */
#define	AHCI_CMD_STATUS_CR	(0x1 << 15) /* Command list running */
#define	AHCI_CMD_STATUS_CPS	(0x1 << 16) /* Cold presence state */
#define	AHCI_CMD_STATUS_PMA	(0x1 << 17) /* Port multiplier attached */
#define	AHCI_CMD_STATUS_HPCP	(0x1 << 18) /* Hot plug capable port */
			/* Mechanical presence switch attached to port */
#define	AHCI_CMD_STATUS_MPSP	(0x1 << 19)
#define	AHCI_CMD_STATUS_CPD	(0x1 << 20) /* Cold presence detection */
#define	AHCI_CMD_STATUS_ESP	(0x1 << 21) /* External SATA port */
#define	AHCI_CMD_STATUS_ATAPI	(0x1 << 24) /* Device is ATAPI */
#define	AHCI_CMD_STATUS_DLAE	(0x1 << 25) /* Drive LED on ATAPI enable */
			/* Aggressive link power magament enable */
#define	AHCI_CMD_STATUS_ALPE	(0x1 << 26)
#define	AHCI_CMD_STATUS_ASP	(0x1 << 27) /* Aggressive slumber/partial */
			/* Interface communication control */
#define	AHCI_CMD_STATUS_ICC	(0xf << 28)
#define	AHCI_CMD_STATUS_CCS_SHIFT	8
#define	AHCI_CMD_STATUS_ICC_SHIFT	28

/* port task file data bits */
#define	AHCI_TFD_STS_MASK	0x000000ff
#define	AHCI_TFD_ERR_MASK	0x0000ff00
#define	AHCI_TFD_STS_BSY	(0x1 << 7)
#define	AHCI_TFD_STS_DRQ	(0x1 << 3)
#define	AHCI_TFD_STS_ERR	(0x1 << 0)
#define	AHCI_TFD_ERR_SHIFT	8
#define	AHCI_TFD_ERR_SGS	(0x1 << 0) /* DDR1: Send_good_status */

/* FIS-Based Switching Control Register */
#define	AHCI_FBS_SWE_MASK	(0xf << 16)	/* Device With Error */
#define	AHCI_FBS_ADO_MASK	(0xf << 12)	/* Active Device Optimization */
#define	AHCI_FBS_DEV_MASK	(0xf << 8)	/* Device To Issue */
#define	AHCI_FBS_SDE		(0x1 << 2)	/* Single Device Error */
#define	AHCI_FBS_DEC		(0x1 << 1)	/* Device Error Clear */
#define	AHCI_FBS_EN		(0x1 << 0)	/* Enable */

/* Sxxx Registers */
#define	AHCI_SERROR_CLEAR_ALL			0xffffffff
#define	AHCI_SNOTIF_CLEAR_ALL			0xffffffff

/* per port registers offset */
#define	AHCI_PORT_OFFSET(ahci_ctlp, port)			\
		(ahci_ctlp->ahcictl_ahci_addr + (0x100 + (port * 0x80)))
	/* Command List Base Address */
#define	AHCI_PORT_PxCLB(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x00)
	/* Command List Base Address Upper 32-Bits */
#define	AHCI_PORT_PxCLBU(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x04)
	/* FIS Base Address */
#define	AHCI_PORT_PxFB(ahci_ctlp, port)				\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x08)
	/* FIS Base Address Upper 32-Bits */
#define	AHCI_PORT_PxFBU(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x0c)
	/* Interrupt Status */
#define	AHCI_PORT_PxIS(ahci_ctlp, port)				\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x10)
	/* Interrupt Enable */
#define	AHCI_PORT_PxIE(ahci_ctlp, port)				\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x14)
	/* Command and Status */
#define	AHCI_PORT_PxCMD(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x18)
	/* Task File Data */
#define	AHCI_PORT_PxTFD(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x20)
	/* Signature */
#define	AHCI_PORT_PxSIG(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x24)
	/* Serial ATA Status (SCR0:SStatus) */
#define	AHCI_PORT_PxSSTS(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x28)
	/* Serial ATA Control (SCR2:SControl) */
#define	AHCI_PORT_PxSCTL(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x2c)
	/* Serial ATA Error (SCR1:SError) */
#define	AHCI_PORT_PxSERR(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x30)
	/* Serial ATA Active (SCR3:SActive) */
#define	AHCI_PORT_PxSACT(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x34)
	/* Command Issue */
#define	AHCI_PORT_PxCI(ahci_ctlp, port)				\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x38)
	/* SNotification */
#define	AHCI_PORT_PxSNTF(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x3c)
	/* FIS-Based Switching Control */
#define	AHCI_PORT_PxFBS(ahci_ctlp, port)			\
			(AHCI_PORT_OFFSET(ahci_ctlp, port) + 0x40)

#define	AHCI_SLOT_MASK(ahci_ctlp)				\
	((ahci_ctlp->ahcictl_num_cmd_slots == AHCI_PORT_MAX_CMD_SLOTS) ? \
	0xffffffff : ((0x1 << ahci_ctlp->ahcictl_num_cmd_slots) - 1))
#define	AHCI_NCQ_SLOT_MASK(ahci_portp)				\
	((ahci_portp->ahciport_max_ncq_tags == AHCI_PORT_MAX_CMD_SLOTS) ? \
	0xffffffff : ((0x1 << ahci_portp->ahciport_max_ncq_tags) - 1))
#define	AHCI_PMPORT_MASK(ahci_portp)				\
	((0x1 << ahci_portp->ahciport_pmult_info->ahcipmi_num_dev_ports) - 1)

/* Device signatures */
#define	AHCI_SIGNATURE_PORT_MULTIPLIER	0x96690101
#define	AHCI_SIGNATURE_ATAPI		0xeb140101
#define	AHCI_SIGNATURE_DISK		0x00000101

#define	AHCI_H2D_REGISTER_FIS_TYPE	0x27
#define	AHCI_H2D_REGISTER_FIS_LENGTH	5

#define	AHCI_CMDHEAD_ATAPI	0x1 /* set to 1 for ATAPI command */
#define	AHCI_CMDHEAD_DATA_WRITE	0x1 /* From system memory to device */
#define	AHCI_CMDHEAD_DATA_READ	0x0 /* From device to system memory */
#define	AHCI_CMDHEAD_PREFETCHABLE	0x1 /* if set, HBA prefetch PRDs */

/* Register - Host to Device FIS (from SATA spec) */
typedef struct ahci_fis_h2d_register {
	/* offset 0x00 */
	uint32_t	ahcifhr_type_pmp_rsvd_cmddevctl_cmd_features;

#define	SET_FIS_TYPE(fis, type)					\
	(fis->ahcifhr_type_pmp_rsvd_cmddevctl_cmd_features |= (type & 0xff))

#define	SET_FIS_PMP(fis, pmp)					\
	(fis->ahcifhr_type_pmp_rsvd_cmddevctl_cmd_features |= 	\
		((pmp & 0xf) << 8))

#define	SET_FIS_CDMDEVCTL(fis, cmddevctl)			\
	(fis->ahcifhr_type_pmp_rsvd_cmddevctl_cmd_features |=	\
		((cmddevctl & 0x1) << 15))

#define	GET_FIS_COMMAND(fis)					\
	((fis->ahcifhr_type_pmp_rsvd_cmddevctl_cmd_features >> 16) & 0xff)

#define	SET_FIS_COMMAND(fis, command)				\
	(fis->ahcifhr_type_pmp_rsvd_cmddevctl_cmd_features |=	\
		((command & 0xff) << 16))

#define	GET_FIS_FEATURES(fis)					\
	((fis->ahcifhr_type_pmp_rsvd_cmddevctl_cmd_features >> 24) & 0xff)

#define	SET_FIS_FEATURES(fis, features)				\
	(fis->ahcifhr_type_pmp_rsvd_cmddevctl_cmd_features |=	\
		((features & 0xff) << 24))

	/* offset 0x04 */
	uint32_t	ahcifhr_sector_cyllow_cylhi_devhead;

#define	GET_FIS_SECTOR(fis)					\
	(fis->ahcifhr_sector_cyllow_cylhi_devhead & 0xff)

#define	SET_FIS_SECTOR(fis, sector)				\
	(fis->ahcifhr_sector_cyllow_cylhi_devhead |= ((sector & 0xff)))

#define	GET_FIS_CYL_LOW(fis)					\
	((fis->ahcifhr_sector_cyllow_cylhi_devhead >> 8) & 0xff)

#define	SET_FIS_CYL_LOW(fis, cyl_low)				\
	(fis->ahcifhr_sector_cyllow_cylhi_devhead |= ((cyl_low & 0xff) << 8))

#define	GET_FIS_CYL_HI(fis)					\
	((fis->ahcifhr_sector_cyllow_cylhi_devhead >> 16) & 0xff)

#define	SET_FIS_CYL_HI(fis, cyl_hi)				\
	(fis->ahcifhr_sector_cyllow_cylhi_devhead |= ((cyl_hi & 0xff) << 16))

#define	GET_FIS_DEV_HEAD(fis)					\
	((fis->ahcifhr_sector_cyllow_cylhi_devhead >> 24) & 0xff)

#define	SET_FIS_DEV_HEAD(fis, dev_head)				\
	(fis->ahcifhr_sector_cyllow_cylhi_devhead |= ((dev_head & 0xff) << 24))

	/* offset 0x08 */
	uint32_t	ahcifhr_sectexp_cyllowexp_cylhiexp_featuresexp;

#define	GET_FIS_SECTOR_EXP(fis)					\
	(fis->ahcifhr_sectexp_cyllowexp_cylhiexp_featuresexp  & 0xff)

#define	SET_FIS_SECTOR_EXP(fis, sectorexp)			\
	(fis->ahcifhr_sectexp_cyllowexp_cylhiexp_featuresexp |=	\
		((sectorexp & 0xff)))

#define	GET_FIS_CYL_LOW_EXP(fis)				\
	((fis->ahcifhr_sectexp_cyllowexp_cylhiexp_featuresexp >> 8) & 0xff)

#define	SET_FIS_CYL_LOW_EXP(fis, cyllowexp)			\
	(fis->ahcifhr_sectexp_cyllowexp_cylhiexp_featuresexp |=	\
		((cyllowexp & 0xff) << 8))

#define	GET_FIS_CYL_HI_EXP(fis)					\
	((fis->ahcifhr_sectexp_cyllowexp_cylhiexp_featuresexp >> 16) & 0xff)

#define	SET_FIS_CYL_HI_EXP(fis, cylhiexp)			\
	(fis->ahcifhr_sectexp_cyllowexp_cylhiexp_featuresexp |=	\
		((cylhiexp & 0xff) << 16))

#define	SET_FIS_FEATURES_EXP(fis, features_exp)			\
	(fis->ahcifhr_sectexp_cyllowexp_cylhiexp_featuresexp |=	\
		((features_exp & 0xff) << 24))

	/* offset 0x0c */
	uint32_t	ahcifhr_sectcount_sectcountexp_rsvd_devctl;

#define	GET_FIS_SECTOR_COUNT(fis)				\
	(fis->ahcifhr_sectcount_sectcountexp_rsvd_devctl & 0xff)

#define	SET_FIS_SECTOR_COUNT(fis, sector_count)			\
	(fis->ahcifhr_sectcount_sectcountexp_rsvd_devctl |= 	\
		((sector_count & 0xff)))

#define	GET_FIS_SECTOR_COUNT_EXP(fis)				\
	((fis->ahcifhr_sectcount_sectcountexp_rsvd_devctl >> 8) & 0xff)

#define	SET_FIS_SECTOR_COUNT_EXP(fis, sector_count_exp)		\
	(fis->ahcifhr_sectcount_sectcountexp_rsvd_devctl |=	\
		((sector_count_exp & 0xff) << 8))

#define	SET_FIS_DEVCTL(fis, devctl)				\
	(fis->ahcifhr_sectcount_sectcountexp_rsvd_devctl |= 	\
		((devctl & 0xff) << 24))

	/* offset 0x10 */
	uint32_t	ahcifhr_rsvd3[1]; /* should be zero */
} ahci_fis_h2d_register_t;

/* Register - Device to Host FIS (from SATA spec) */
typedef struct ahci_fis_d2h_register {
	/* offset 0x00 */
	uint32_t	ahcifdr_type_intr_rsvd_status_error;

#define	GET_RFIS_STATUS(fis)					\
	((fis->ahcifdr_type_intr_rsvd_status_error >> 16) & 0xff)

#define	GET_RFIS_ERROR(fis)					\
	((fis->ahcifdr_type_intr_rsvd_status_error >> 24) & 0xff)

	/* offset 0x04 */
	uint32_t	ahcifdr_sector_cyllow_cylhi_devhead;

#define	GET_RFIS_CYL_LOW(fis)					\
	(fis->ahcifdr_sector_cyllow_cylhi_devhead & 0xff)

#define	GET_RFIS_CYL_MID(fis)					\
	((fis->ahcifdr_sector_cyllow_cylhi_devhead >> 8) & 0xff)

#define	GET_RFIS_CYL_HI(fis)					\
	((fis->ahcifdr_sector_cyllow_cylhi_devhead >> 16) & 0xff)

#define	GET_RFIS_DEV_HEAD(fis)					\
	((fis->ahcifdr_sector_cyllow_cylhi_devhead >> 24) & 0xff)

	/* offset 0x08 */
	uint32_t	ahcifdr_sectexp_cyllowexp_cylhiexp_rsvd;

#define	GET_RFIS_CYL_LOW_EXP(fis)					\
	(fis->ahcifdr_sectexp_cyllowexp_cylhiexp_rsvd  & 0xff)

#define	GET_RFIS_CYL_MID_EXP(fis)				\
	((fis->ahcifdr_sectexp_cyllowexp_cylhiexp_rsvd >> 8) & 0xff)

#define	GET_RFIS_CYL_HI_EXP(fis)					\
	((fis->ahcifdr_sectexp_cyllowexp_cylhiexp_rsvd >> 16) & 0xff)

	/* offset 0x0c */
	uint32_t	ahcifdr_sectcount_sectcountexp_rsvd;

#define	GET_RFIS_SECTOR_COUNT(fis)				\
	(fis->ahcifdr_sectcount_sectcountexp_rsvd & 0xff)

#define	GET_RFIS_SECTOR_COUNT_EXP(fis)				\
	((fis->ahcifdr_sectcount_sectcountexp_rsvd >> 8) & 0xff)

	/* offset 0x10 */
	uint32_t	ahcifdr_rsvd;
} ahci_fis_d2h_register_t;

/* Set Device Bits - Device to Host FIS (from SATA spec) */
typedef struct ahci_fis_set_device_bits {
	/* offset 0x00 */
	uint32_t	ahcifsdb_type_rsvd_intr_status_error;

#define	GET_N_BIT_OF_SET_DEV_BITS(fis)				\
	((fis->ahcifsdb_type_rsvd_intr_status_error >> 15) & 0x1)

	/* offset 0x04 */
	uint32_t	ahcifsdb_rsvd;
} ahci_fis_set_device_bits_t;

/* DMA Setup - Device to Host or Host to Device (from SATA spec) */
typedef struct ahci_fis_dma_setup {
	/* offset 0x00 */
	uint32_t	ahcifds_type_rsvd_direction_intr_rsvd;

	/* offset 0x04 */
	uint32_t	ahcifds_dma_buffer_identifier_low;

	/* offset 0x08 */
	uint32_t	ahcifds_dma_buffer_identifier_high;

	/* offset 0x0c */
	uint32_t	ahcifds_rsvd1;

	/* offset 0x10 */
	uint32_t	ahcifds_dma_buffer_offset;

	/* offset 0x14 */
	uint32_t	ahcifds_dma_transfer_count;

	/* offset 0x18 */
	uint32_t	ahcifds_rsvd2;
} ahci_fis_dma_setup_t;

/* PIO Setup - Device to Host FIS (from SATA spec) */
typedef struct ahci_fis_pio_setup {
	/* offset 0x00 */
	uint32_t	ahcifps_type_rsvd_direction_intr_status_error;

	/* offset 0x04 */
	uint32_t	ahcifps_sector_cyllow_cylhi_devhead;

	/* offset 0x08 */
	uint32_t	ahcifps_sectexp_cyllowexp_cylhiexp_rsvd;

	/* offset 0x0c */
	uint32_t	ahcifps_sectcount_sectcountexp_rsvd_e_status;

	/* offset 0x10 */
	uint32_t	ahcifps_transfer_count_rsvd;
} ahci_fis_pio_setup_t;

/* BIST Active - Host to Device or Device to Host (from SATA spec) */
typedef struct ahci_fis_bist_active {
	/* offset 0x00 */
	uint32_t	ahcifba_type_rsvd_pattern_rsvd;

	/* offset 0x04 */
	uint32_t	ahcifba_data1;

	/* offset 0x08 */
	uint32_t	ahcifba_data2;
} ahci_fis_bist_active_t;

/* Up to 64 bytes */
typedef struct ahci_fis_unknown {
	uint32_t	ahcifu_first_dword;
	uint32_t	ahcifu_dword[15];
} ahci_fis_unknown_t;

/*
 * This is a software constructed FIS. For data transfer,
 * this is the H2D Register FIS format as specified in
 * the Serial ATA 1.0a specification. Valid Command FIS
 * length are 2 to 16 Dwords.
 */
typedef struct ahci_fis_command {
	union {
		ahci_fis_h2d_register_t	ahcifc_h2d_register;
		ahci_fis_bist_active_t	ahcifc_bist_active;
	} ahcifc_fis;
	uint32_t	ahcifc_rsvd3[11]; /* should be zero */
} ahci_fis_command_t;

/* Received FISes structure - size 100h */
typedef struct ahci_rcvd_fis {
	/* offset 0x00 - DMA Setup FIS */
	ahci_fis_dma_setup_t		ahcirf_dma_setup_fis;
	uint32_t			ahcirf_fis_rsvd1;

	/* offset 0x20 - PIO Setup FIS */
	ahci_fis_pio_setup_t		ahcirf_pio_setup_fis;
	uint32_t			ahcirf_fis_rsvd2[3];

	/* offset 0x40 - D2H Register FIS */
	ahci_fis_d2h_register_t		ahcirf_d2h_register_fis;
	uint32_t			ahcirf_fis_rsvd3;

	/* offset 0x58 - Set Device Bits FIS */
	ahci_fis_set_device_bits_t	ahcirf_set_device_bits_fis;

	/* offset 0x60 - Unknown FIS */
	ahci_fis_unknown_t		ahcirf_unknown_fis;

	/* offset 0xa0h - Reserved */
	uint32_t			ahcirf_fis_rsvd4[24];
} ahci_rcvd_fis_t;

/* physical region description table (PRDT) item structure */
typedef struct ahci_prdt_item {
	/* DW 0 - Data Base Address */
	uint32_t	ahcipi_data_base_addr;

	/* DW 1 - Data Base Address Upper */
	uint32_t	ahcipi_data_base_addr_upper;

	/* DW 2 - Reserved */
	uint32_t	ahcipi_rsvd;

	/* DW 3 - Description Information */
	uint32_t	ahcipi_descr_info;

#define	GET_PRDT_ITEM_INTR_ON_COMPLETION(prdt_item)	\
		((prdt_item.ahcipi_descr_info >> 31) & 0x01)

#define	GET_PRDT_ITEM_DATA_BYTE_COUNT(prdt_item)	\
		(prdt_item.ahcipi_descr_info & 0x3fffff)

} ahci_prdt_item_t;

/* command table structure */
typedef struct ahci_cmd_table {
	/* offset 0x00 - Command FIS */
	ahci_fis_command_t	ahcict_command_fis;

	/* offset 0x40 - ATAPI Command */
	uint8_t			ahcict_atapi_cmd[SATA_ATAPI_MAX_CDB_LEN];

	/* offset 0x50 - Reserved */
	uint32_t		ahcict_rsvd[12];

	/* offset 0x80 - Physical Region Description Table */
	ahci_prdt_item_t	ahcict_prdt[AHCI_PRDT_NUMBER];
} ahci_cmd_table_t;

/* command head structure - size 20h */
typedef struct ahci_cmd_header {
	/* DW 0 - Description Information */
	uint32_t	ahcich_descr_info;

#define	BZERO_DESCR_INFO(cmd_header)				\
	(cmd_header->ahcich_descr_info = 0)

#define	GET_PRD_TABLE_LENGTH(cmd_header)			\
		((cmd_header->ahcich_descr_info >> 16) & 0xffff)

#define	SET_PRD_TABLE_LENGTH(cmd_header, length)		\
	(cmd_header->ahcich_descr_info |= ((length & 0xffff) << 16))

#define	GET_PORT_MULTI_PORT(cmd_header)				\
		((cmd_header->ahcich_descr_info >> 12) & 0x0f)

#define	SET_PORT_MULTI_PORT(cmd_header, flags)			\
	(cmd_header->ahcich_descr_info |= ((flags & 0x0f) << 12))

#define	GET_CLEAR_BUSY_UPON_R_OK(cmd_header)			\
		((cmd_header->ahcich_descr_info >> 10) & 0x01)

#define	SET_CLEAR_BUSY_UPON_R_OK(cmd_header, flags)		\
	(cmd_header->ahcich_descr_info |= ((flags & 0x01) << 10))

#define	GET_BIST(cmd_header)					\
		((cmd_header->ahcich_descr_info >> 9) & 0x01)

#define	GET_RESET(cmd_header)					\
		((cmd_header->ahcich_descr_info >> 8) & 0x01)

#define	SET_RESET(cmd_header, features_exp)			\
	(cmd_header->ahcich_descr_info |= ((features_exp & 0x01) << 8))

#define	GET_PREFETCHABLE(cmd_header)				\
		((cmd_header->ahcich_descr_info >> 7) & 0x01)

#define	SET_PREFETCHABLE(cmd_header, flags)			\
	(cmd_header->ahcich_descr_info |= ((flags & 0x01) << 7))

#define	GET_WRITE(cmd_header)					\
		((cmd_header->ahcich_descr_info >> 6) & 0x01)

#define	SET_WRITE(cmd_header, flags)				\
	(cmd_header->ahcich_descr_info |= ((flags & 0x01) << 6))

#define	GET_ATAPI(cmd_header)					\
		((cmd_header->ahcich_descr_info >> 5) & 0x01)

#define	SET_ATAPI(cmd_header, flags)				\
	(cmd_header->ahcich_descr_info |= ((flags & 0x01) << 5))

#define	GET_COMMAND_FIS_LENGTH(cmd_header)			\
		(cmd_header->ahcich_descr_info && 0x1f)

#define	SET_COMMAND_FIS_LENGTH(cmd_header, length)		\
	(cmd_header->ahcich_descr_info |= (length & 0x1f))

	/* DW 1 - Physical Region Descriptor Byte Count */
	uint32_t	ahcich_prd_byte_count;

#define	BZERO_PRD_BYTE_COUNT(cmd_header)			\
	(cmd_header->ahcich_prd_byte_count = 0)

	/* DW 2 - Command Table Base Address */
	uint32_t	ahcich_cmd_tab_base_addr;

#define	SET_COMMAND_TABLE_BASE_ADDR(cmd_header, base_address)	\
	(cmd_header->ahcich_cmd_tab_base_addr = base_address)

	/* DW 3 - Command Table Base Address Upper */
	uint32_t	ahcich_cmd_tab_base_addr_upper;

#define	SET_COMMAND_TABLE_BASE_ADDR_UPPER(cmd_header, base_address) \
	(cmd_header->ahcich_cmd_tab_base_addr_upper = base_address)

	/* DW 4-7 - Reserved */
	uint32_t	ahcich_rsvd[4];
} ahci_cmd_header_t;


#ifdef	__cplusplus
}
#endif

#endif /* _AHCIREG_H */
