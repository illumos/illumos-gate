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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SI3124REG_H
#define	_SI3124REG_H

#ifdef	__cplusplus
extern "C" {
#endif

#pragma pack(1)

typedef struct si_sge {
	/* offset 0x00 */
	union {
		uint64_t _sge_addr_ll;
		uint32_t _sge_addr_la[2];
	} _sge_addr_un;

#define	sge_addr_low	_sge_addr_un._sge_addr_la[0]
#define	sge_addr_high	_sge_addr_un._sge_addr_la[1]
#define	sge_addr	_sge_addr_un._sge_addr_ll

	/* offset 0x08 */
	uint32_t sge_data_count;

	/* offset 0x0c */
	uint32_t sge_trm_lnk_drd_xcf_rsvd;

#define	SET_SGE_LNK(sge)	(sge.sge_trm_lnk_drd_xcf_rsvd = 0x40000000)
#define	SET_SGE_TRM(sge)	(sge.sge_trm_lnk_drd_xcf_rsvd = 0x80000000)
#define	IS_SGE_TRM_SET(sge)	(sge.sge_trm_lnk_drd_xcf_rsvd & 0x80000000)

} si_sge_t;

/* Scatter Gather Table consists of four SGE entries */
typedef struct si_sgt {
	si_sge_t sgt_sge[4];
} si_sgt_t;


/* Register - Host to Device FIS (from SATA spec) */
typedef struct fis_reg_h2d {
	/* offset 0x00 */
	uint32_t fish_type_pmp_rsvd_cmddevctl_cmd_features;

#define	SET_FIS_TYPE(fis, type)	\
	((&fis)->fish_type_pmp_rsvd_cmddevctl_cmd_features |= (type & 0xff))

#define	SET_FIS_PMP(fis, pmp)	\
	((&fis)->fish_type_pmp_rsvd_cmddevctl_cmd_features |= \
	    ((pmp & 0xf) << 8))

#define	SET_FIS_CDMDEVCTL(fis, cmddevctl)	\
	((&fis)->fish_type_pmp_rsvd_cmddevctl_cmd_features |=	\
		((cmddevctl & 0x1) << 15))

#define	SET_FIS_COMMAND(fis, command)	\
	((&fis)->fish_type_pmp_rsvd_cmddevctl_cmd_features |=	\
		((command & 0xff) << 16))

#define	GET_FIS_COMMAND(fis)	\
	(((&fis)->fish_type_pmp_rsvd_cmddevctl_cmd_features >> 16) & 0xff)

#define	SET_FIS_FEATURES(fis, features)	\
	((&fis)->fish_type_pmp_rsvd_cmddevctl_cmd_features |=	\
		((features & 0xff) << 24))

#define	GET_FIS_FEATURES(fis)	\
	(((&fis)->fish_type_pmp_rsvd_cmddevctl_cmd_features >> 24) & 0xff)

	/* offset 0x04 */
	uint32_t fish_sector_cyllow_cylhi_devhead;

#define	SET_FIS_SECTOR(fis, sector)	\
	((&fis)->fish_sector_cyllow_cylhi_devhead |= ((sector & 0xff)))

#define	GET_FIS_SECTOR(fis)	\
	((&fis)->fish_sector_cyllow_cylhi_devhead & 0xff)

#define	SET_FIS_CYL_LOW(fis, cyl_low)	\
	((&fis)->fish_sector_cyllow_cylhi_devhead |= ((cyl_low & 0xff) << 8))

#define	GET_FIS_CYL_LOW(fis)	\
	(((&fis)->fish_sector_cyllow_cylhi_devhead >> 8) & 0xff)

#define	SET_FIS_CYL_HI(fis, cyl_hi)	\
	((&fis)->fish_sector_cyllow_cylhi_devhead |= ((cyl_hi & 0xff) << 16))

#define	GET_FIS_CYL_HI(fis)	\
	(((&fis)->fish_sector_cyllow_cylhi_devhead >> 16) & 0xff)

#define	SET_FIS_DEV_HEAD(fis, dev_head)	\
	((&fis)->fish_sector_cyllow_cylhi_devhead |= ((dev_head & 0xff) << 24))

#define	GET_FIS_DEV_HEAD(fis)	\
	(((&fis)->fish_sector_cyllow_cylhi_devhead >> 24) & 0xff)


	/* offset 0x08 */
	uint32_t fish_sectexp_cyllowexp_cylhiexp_featuresexp;

#define	SET_FIS_SECTOR_EXP(fis, sectorexp)	\
	((&fis)->fish_sectexp_cyllowexp_cylhiexp_featuresexp |=	\
		((sectorexp & 0xff)))

#define	GET_FIS_SECTOR_EXP(fis)	\
	((&fis)->fish_sectexp_cyllowexp_cylhiexp_featuresexp  & 0xff)

#define	SET_FIS_CYL_LOW_EXP(fis, cyllowexp)			\
	((&fis)->fish_sectexp_cyllowexp_cylhiexp_featuresexp |= 	\
		((cyllowexp & 0xff) << 8))

#define	GET_FIS_CYL_LOW_EXP(fis)			\
	(((&fis)->fish_sectexp_cyllowexp_cylhiexp_featuresexp >> 8) & 0xff)

#define	SET_FIS_CYL_HI_EXP(fis, cylhiexp)			\
	((&fis)->fish_sectexp_cyllowexp_cylhiexp_featuresexp |= 	\
		((cylhiexp & 0xff) << 16))

#define	GET_FIS_CYL_HI_EXP(fis)			\
	(((&fis)->fish_sectexp_cyllowexp_cylhiexp_featuresexp >> 16) & 0xff)

#define	SET_FIS_FEATURES_EXP(fis, features_exp)		\
	((&fis)->fish_sectexp_cyllowexp_cylhiexp_featuresexp |= 	\
		((features_exp & 0xff) << 24))

	/* offset 0x0c */
	uint32_t fish_sectcount_sectcountexp_rsvd_devctl;

#define	SET_FIS_SECTOR_COUNT(fis, sector_count)	\
	((&fis)->fish_sectcount_sectcountexp_rsvd_devctl |= \
	    ((sector_count & 0xff)))

#define	GET_FIS_SECTOR_COUNT(fis)	\
	((&fis)->fish_sectcount_sectcountexp_rsvd_devctl & 0xff)

#define	SET_FIS_SECTOR_COUNT_EXP(fis, sector_count_exp)	\
	((&fis)->fish_sectcount_sectcountexp_rsvd_devctl |= \
		((sector_count_exp & 0xff) << 8))

#define	GET_FIS_SECTOR_COUNT_EXP(fis)	\
	(((&fis)->fish_sectcount_sectcountexp_rsvd_devctl >> 8) & 0xff)

#define	SET_FIS_SECTOR_DEVCTL(fis, devctl)	\
	((&fis)->fish_sectcount_sectcountexp_rsvd_devctl |= \
	    ((devctl & 0xff) << 24))

	/* offset 0x10 */
	uint32_t fish_rsvd3;		/* should be zero */
} fis_reg_h2d_t;




/*
 * Port Request Block
 */
typedef struct si_prb {
	/* offset 0x00 */
	uint32_t prb_control_override;

#define	SET_PRB_CONTROL_PKT_READ(prb)	\
	(prb->prb_control_override |= (0x1 << 4))

#define	SET_PRB_CONTROL_PKT_WRITE(prb)	\
	(prb->prb_control_override |= (0x1 << 5))

#define	SET_PRB_CONTROL_SOFT_RESET(prb)	\
	(prb->prb_control_override |= (0x1 << 7))

	/* offset 0x04 */
	uint32_t prb_received_count;

	/* offset 0x08 */
	fis_reg_h2d_t prb_fis; 			/* this is of 0x14 bytes size */

	/* offset 0x1c */
	uint32_t prb_rsvd3;

	/* offset 0x20 */
	si_sge_t prb_sge0;

	/* offset 0x30 */
	si_sge_t prb_sge1;

} si_prb_t;

#pragma pack()


/* Various interrupt bits */
#define	INTR_COMMAND_COMPLETE		(0x1 << 0)
#define	INTR_COMMAND_ERROR		(0x1 << 1)
#define	INTR_PORT_READY			(0x1 << 2)
#define	INTR_POWER_CHANGE		(0x1 << 3)
#define	INTR_PHYRDY_CHANGE		(0x1 << 4)
#define	INTR_COMWAKE_RECEIVED		(0x1 << 5)
#define	INTR_UNRECOG_FIS		(0x1 << 6)
#define	INTR_DEV_XCHANGED		(0x1 << 7)
#define	INTR_8B10B_DECODE_ERROR		(0x1 << 8)
#define	INTR_CRC_ERROR			(0x1 << 9)
#define	INTR_HANDSHAKE_ERROR		(0x1 << 10)
#define	INTR_SETDEVBITS_NOTIFY		(0x1 << 11)
#define	INTR_MASK			(0xfff)

/* Device signatures */
#define	SI_SIGNATURE_PORT_MULTIPLIER	0x96690101
#define	SI_SIGNATURE_ATAPI		0xeb140101
#define	SI_SIGNATURE_DISK		0x00000101


/* Global definitions */
#define	GLOBAL_OFFSET(si_ctlp)		(si_ctlp->sictl_global_addr)
#define	GLOBAL_CONTROL_REG(si_ctlp)	(GLOBAL_OFFSET(si_ctlp)+0x40)
#define	GLOBAL_INTERRUPT_STATUS(si_ctlp)	(GLOBAL_OFFSET(si_ctlp)+0x44)

/* Per port definitions */
#define	PORT_OFFSET(si_ctlp, port)	(si_ctlp->sictl_port_addr + port*0x2000)
#define	PORT_LRAM(si_ctlp, port, slot)		\
			(PORT_OFFSET(si_ctlp, port) + 0x0 + slot*0x80)
#define	PORT_CONTROL_SET(si_ctlp, port)		\
			(PORT_OFFSET(si_ctlp, port) + 0x1000)
#define	PORT_STATUS(si_ctlp, port)		\
			(PORT_OFFSET(si_ctlp, port) + 0x1000)
#define	PORT_CONTROL_CLEAR(si_ctlp, port)		\
			(PORT_OFFSET(si_ctlp, port) + 0x1004)
#define	PORT_INTERRUPT_STATUS(si_ctlp, port)	\
			(PORT_OFFSET(si_ctlp, port) + 0x1008)
#define	PORT_INTERRUPT_ENABLE_SET(si_ctlp, port)	\
			(PORT_OFFSET(si_ctlp, port) + 0x1010)
#define	PORT_INTERRUPT_ENABLE_CLEAR(si_ctlp, port) \
			(PORT_OFFSET(si_ctlp, port) + 0x1014)
#define	PORT_COMMAND_ERROR(si_ctlp, port) 	\
			(PORT_OFFSET(si_ctlp, port) + 0x1024)
#define	PORT_SLOT_STATUS(si_ctlp, port)	(PORT_OFFSET(si_ctlp, port) + 0x1800)

#define	PORT_SCONTROL(si_ctlp, port)	(PORT_OFFSET(si_ctlp, port) + 0x1f00)
#define	PORT_SSTATUS(si_ctlp, port)	(PORT_OFFSET(si_ctlp, port) + 0x1f04)
#define	PORT_SERROR(si_ctlp, port)	(PORT_OFFSET(si_ctlp, port) + 0x1f08)
#define	PORT_SACTIVE(si_ctlp, port)	(PORT_OFFSET(si_ctlp, port) + 0x1f0c)

#define	PORT_COMMAND_ACTIVATION(si_ctlp, port, slot)	\
			(PORT_OFFSET(si_ctlp, port) + 0x1c00 + slot*0x8)

#define	PORT_SIGNATURE_MSB(si_ctlp, port, slot)		\
			(PORT_OFFSET(si_ctlp, port) + slot*0x80 + 0x0c)
#define	PORT_SIGNATURE_LSB(si_ctlp, port, slot)		\
			(PORT_OFFSET(si_ctlp, port) + slot*0x80 + 0x14)

/* Interesting bits of Port Control Set register */
#define	PORT_CONTROL_SET_BITS_PORT_RESET		0x1
#define	PORT_CONTROL_SET_BITS_DEV_RESET			0x2
#define	PORT_CONTROL_SET_BITS_PORT_INITIALIZE		0x4
#define	PORT_CONTROL_SET_BITS_PACKET_LEN		0x20
#define	PORT_CONTROL_SET_BITS_RESUME			0x40
#define	PORT_CONTROL_SET_BITS_PM_ENABLE			0x2000

/* Interesting bits of Port Control Clear register */
#define	PORT_CONTROL_CLEAR_BITS_PORT_RESET		0x1
#define	PORT_CONTROL_CLEAR_BITS_INTR_NCoR		0x8
#define	PORT_CONTROL_CLEAR_BITS_PACKET_LEN		0x20
#define	PORT_CONTROL_CLEAR_BITS_RESUME			0x40

/* Interesting bits of Port Status register */
#define	PORT_STATUS_BITS_PORT_READY		0x80000000

/* Interesting bits of Global Control register */
#define	GLOBAL_CONTROL_REG_BITS_CLEAR		0x00000000

#define	POST_PRB_ADDR(si_ctlp, si_portp, port, slot)			  \
	(void) ddi_dma_sync(si_portp->siport_prbpool_dma_handle,	  \
			slot * sizeof (si_prb_t),			  \
			sizeof (si_prb_t),				  \
			DDI_DMA_SYNC_FORDEV);				  \
									  \
	(void) ddi_dma_sync(si_portp->siport_sgbpool_dma_handle,	  \
			slot * sizeof (si_sgblock_t) * si_dma_sg_number,  \
			sizeof (si_sgblock_t) * si_dma_sg_number,	  \
			DDI_DMA_SYNC_FORDEV);				  \
									  \
	ddi_put64(si_ctlp->sictl_port_acc_handle, 			  \
		(uint64_t *)PORT_COMMAND_ACTIVATION(si_ctlp, port, slot), \
		(uint64_t)(si_portp->siport_prbpool_physaddr + 		  \
		slot*sizeof (si_prb_t)));

#define	SI_SLOT_MASK	0x7fffffff
#define	SI_NUM_SLOTS	0x1f		/* 31 */

#define	ATTENTION_BIT	0x80000000
#define	IS_ATTENTION_RAISED(slot_status)	(slot_status & ATTENTION_BIT)

#define	SI3124_DEV_ID	0x3124
#define	SI3132_DEV_ID	0x3132
#define	SI3531_DEV_ID	0x3531

#define	PM_CSR(devid)	 ((devid == SI3124_DEV_ID) ? 0x68 : 0x58)

#define	REGISTER_FIS_H2D	0x27

#define	SI31xx_INTR_PORT_MASK	0xf

/* PCI BAR registers */
#define	PCI_BAR0	1	/* Contains global register set */
#define	PCI_BAR1	2	/* Contains port register set */

/* Port Status and Control Registers (from port multiplier spec) */
#define	PSCR_REG0	0
#define	PSCR_REG1	1
#define	PSCR_REG2	2
#define	PSCR_REG3	3

/* SStatus bit fields */
#define	SSTATUS_DET_MASK	0x0000000f
#define	SSTATUS_SPD_MASK	0x000000f0
#define	SSTATUS_SPD_SHIFT	4
#define	SSTATUS_IPM_MASK	0x00000f00
#define	SSTATUS_IPM_SHIFT	8


#define	SSTATUS_DET_NODEV_NOPHY		 0x0 /* No device, no PHY */
#define	SSTATUS_DET_DEVPRESENT_NOPHY	 0x1 /* Dev present, no PHY */
#define	SSTATUS_DET_DEVPRESENT_PHYONLINE 0x3 /* Dev present, PHY online */

#define	SSTATUS_IPM_NODEV_NOPHY			0x0 /* No dev, no PHY */
#define	SSTATUS_IPM_INTERFACE_ACTIVE		0x1 /* Interface active */
#define	SSTATUS_IPM_INTERFACE_POWERPARTIAL	0x2 /* partial power mgmnt */
#define	SSTATUS_IPM_INTERFACE_POWERSLUMBER	0x6 /* slumber power mgmt */

/* SControl bit fields */
#define	SCONTROL_DET_MASK	0x0000000f




/* Command Error codes */
#define	CMD_ERR_DEVICEERRROR		1
#define	CMD_ERR_SDBERROR		2
#define	CMD_ERR_DATAFISERROR		3
#define	CMD_ERR_SENDFISERROR		4
#define	CMD_ERR_INCONSISTENTSTATE	5
#define	CMD_ERR_DIRECTIONERROR		6
#define	CMD_ERR_UNDERRUNERROR		7
#define	CMD_ERR_OVERRUNERROR		8
#define	CMD_ERR_PACKETPROTOCOLERROR	11
#define	CMD_ERR_PLDSGTERRORBOUNDARY	16
#define	CMD_ERR_PLDSGTERRORTARETABORT	17
#define	CMD_ERR_PLDSGTERRORMASTERABORT	18
#define	CMD_ERR_PLDSGTERRORPCIERR	19
#define	CMD_ERR_PLDCMDERRORBOUNDARY	24
#define	CMD_ERR_PLDCMDERRORTARGETABORT	25
#define	CMD_ERR_PLDCMDERRORMASTERABORT	26
#define	CMD_ERR_PLDCMDERORPCIERR	27
#define	CMD_ERR_PSDERRORTARGETABORT	33
#define	CMD_ERR_PSDERRORMASTERABORT	34
#define	CMD_ERR_PSDERRORPCIERR		35
#define	CMD_ERR_SENDSERVICEERROR	36

#ifdef	__cplusplus
}
#endif

#endif /* _SI3124REG_H */
