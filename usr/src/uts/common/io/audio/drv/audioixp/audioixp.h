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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AUDIOIXP_H_
#define	_AUDIOIXP_H_

/*
 * Header file for the audioixp device driver
 */

#define	IXP_DEV_CONFIG		"onboard1"
#define	IXP_DEV_VERSION		"a"

/*
 * Driver supported configuration information
 */
#define	IXP_NAME		"audioixp"
#define	IXP_MOD_NAME		"ATI IXP audio driver"
#define	IXP_CONFIG_REGS		(0)	/* PCI configure register */
#define	IXP_IO_AM_REGS		(1)	/* PCI base register 0x10 */

#define	IXP_PLAY		0
#define	IXP_REC			1

#define	IXP_BD_NUMS			(8)

/*
 * PCI configuration registers and bits
 */
#define	IXP_PCI_ID_200		(0x10024341U)
#define	IXP_PCI_ID_300		(0x10024361U)
#define	IXP_PCI_ID_400		(0x10024370U)
#define	IXP_PCI_ID_SB600	(0x10024382U)

/*
 * Audio controller registers and bits
 */
#define	IXP_AUDIO_INT				(0x00)
#define	IXP_AUDIO_INT_IN_DMA_OVERFLOW		(1U<<0)
#define	IXP_AUDIO_INT_IN_DMA			(1U<<1)
#define	IXP_AUDIO_INT_OUT_DMA_UNDERFLOW		(1U<<2)
#define	IXP_AUDIO_INT_OUT_DMA			(1U<<3)
#define	IXP_AUDIO_INT_CODEC0_NOT_READY		(1U<<10)
#define	IXP_AUDIO_INT_CODEC1_NOT_READY		(1U<<11)
#define	IXP_AUDIO_INT_CODEC2_NOT_READY		(1U<<12)
#define	IXP_AUDIO_INT_NEW_FRAME			(1U<<13)

#define	IXP_AUDIO_INT_EN			(0x04)
#define	IXP_AUDIO_INT_EN_IN_DMA_OVERFLOW	(1U<<0)
#define	IXP_AUDIO_INT_EN_STATUS			(1U<<1)
#define	IXP_AUDIO_INT_EN_OUT_DMA_UNDERFLOW	(1U<<2)
#define	IXP_AUDIO_INT_EN_CODEC0_NOT_READY	(1U<<10)
#define	IXP_AUDIO_INT_EN_CODEC1_NOT_READY	(1U<<11)
#define	IXP_AUDIO_INT_EN_CODEC2_NOT_READY	(1U<<12)
#define	IXP_AUDIO_INT_EN_NEW_FRAME		(1U<<13)

#define	IXP_AUDIO_CMD				(0x08)
#define	IXP_AUDIO_CMD_POWER_DOWN		(1U<<0)
#define	IXP_AUDIO_CMD_EN_IN			(1U<<1)
#define	IXP_AUDIO_CMD_EN_OUT			(1U<<2)
#define	IXP_AUDIO_CMD_EN_IN_DMA			(1U<<8)
#define	IXP_AUDIO_CMD_EN_OUT_DMA		(1U<<9)
#define	IXP_AUDIO_CMD_INTER_IN			(1U<<21)
#define	IXP_AUDIO_CMD_INTER_OUT			(1U<<22)
#define	IXP_AUDIO_CMD_BURST_EN			(1U<<25)
#define	IXP_AUDIO_CMD_AC_ACTIVE			(1U<<28)
#define	IXP_AUDIO_CMD_AC_SOFT_RESET		(1U<<29)
#define	IXP_AUDIO_CMD_AC_SYNC			(1U<<30)
#define	IXP_AUDIO_CMD_AC_RESET			(1U<<31)

#define	IXP_AUDIO_OUT_PHY_ADDR_DATA		(0x0c)
#define	IXP_AUDIO_OUT_PHY_PRIMARY_CODEC	(0u)
#define	IXP_AUDIO_OUT_PHY_SECOND_CODEC	(1u)
#define	IXP_AUDIO_OUT_PHY_THIRD_CODEC	(2u)
#define	IXP_AUDIO_OUT_PHY_READ		(1u<<2)
#define	IXP_AUDIO_OUT_PHY_WRITE		(0u)
#define	IXP_AUDIO_OUT_PHY_EN			(1u<<8)
#define	IXP_AUDIO_OUT_PHY_ADDR_SHIFT		(9)
#define	IXP_AUDIO_OUT_PHY_ADDR_MASK		(0x7fu<<9)
#define	IXP_AUDIO_OUT_PHY_DATA_SHIFT		(16)
#define	IXP_AUDIO_OUT_PHY_DATA_MASK		(0xffffu<<16)

#define	IXP_AUDIO_IN_PHY_ADDR_DATA		(0x10)
#define	IXP_AUDIO_IN_PHY_READY			(1u<<8)
#define	IXP_AUDIO_IN_PHY_ADDR_SHIFT		(9)
#define	IXP_AUDIO_IN_PHY_ADDR_MASK		(0x7fu<<9)
#define	IXP_AUDIO_IN_PHY_DATA_SHIFT		(16)
#define	IXP_AUDIO_IN_PHY_DATA_MASK		(0xffffu<<16)

#define	IXP_AUDIO_SLOTREQ			(0x14)
#define	IXP_AUDIO_COUNTER			(0x18)
#define	IXP_AUDIO_IN_FIFO_THRESHOLD		(0x1c)
#define	IXP_AUDIO_IN_DMA_LINK_P			(0x20)
#define	IXP_AUDIO_IN_DMA_LINK_P_EN		(1u<<0)

#define	IXP_AUDIO_IN_DMA_DT_START		(0x24)
#define	IXP_AUDIO_IN_DMA_DT_NEXT		(0x28)
#define	IXP_AUDIO_IN_DMA_DT_CUR			(0x2c)
#define	IXP_AUDIO_IN_DT_SIZE_FIFO_INFO		(0x30)

#define	IXP_AUDIO_OUT_DMA_SLOT_EN_THRESHOLD	(0x34)
#define	IXP_AUDIO_OUT_DMA_SLOT_3		(1U<<0)
#define	IXP_AUDIO_OUT_DMA_SLOT_4		(1U<<1)
#define	IXP_AUDIO_OUT_DMA_SLOT_5		(1U<<2)
#define	IXP_AUDIO_OUT_DMA_SLOT_6		(1U<<3)
#define	IXP_AUDIO_OUT_DMA_SLOT_7		(1U<<4)
#define	IXP_AUDIO_OUT_DMA_SLOT_8		(1U<<5)
#define	IXP_AUDIO_OUT_DMA_SLOT_9		(1U<<6)
#define	IXP_AUDIO_OUT_DMA_SLOT_10		(1U<<7)
#define	IXP_AUDIO_OUT_DMA_SLOT_11		(1U<<8)
#define	IXP_AUDIO_OUT_DMA_SLOT_12		(1U<<9)
#define	IXP_AUDIO_OUT_DMA_THRESHOLD_MASK	(0x7fU<<11)
#define	IXP_AUDIO_OUT_DMA_THRESHOLD_SHIFT	(11)

#define	IXP_AUDIO_OUT_DMA_LINK_P		(0x38)
#define	IXP_AUDIO_OUT_DMA_LINK_P_EN		(1U<<0)

#define	IXP_AUDIO_OUT_DMA_DT_START		(0x3c)
#define	IXP_AUDIO_OUT_DMA_DT_NEXT		(0x40)
#define	IXP_AUDIO_OUT_DMA_DT_CUR		(0x44)
#define	IXP_AUDIO_OUT_DT_SIZE_USED_FREE		(0x48)
#define	IXP_AUDIO_SPDIF_CMD			(0x4c)
#define	IXP_AUDIO_SPDIF_LINK_P			(0x50)
#define	IXP_AUDIO_SPDIF_DT_START		(0x54)
#define	IXP_AUDIO_SPDIF_DT_NEXT			(0x58)
#define	IXP_AUDIO_SPDIF_DT_CUR			(0x5c)
#define	IXP_AUDIO_SPDIF_DT_SIZE_FIFO_INFO	(0x60)
#define	IXP_AUDIO_MODEM_MIRROR			(0x7c)
#define	IXP_AUDIO_AUDIO_MIRROR			(0x80)
#define	IXP_AUDIO_6CH_RECORDER_EN		(0x84)
#define	IXP_AUDIO_FIFO_FLUSH		(0x88)
#define	IXP_AUDIO_FIFO_FLUSH_OUT		(1u<<0)
#define	IXP_AUDIO_FIFO_FLUSH_IN			(1u<<1)

#define	IXP_AUDIO_OUT_FIFO_INFO		(0x8c)
#define	IXP_AUDIO_SPDIF_STATUS_BITS_REG1	(0x90)
#define	IXP_AUDIO_SPDIF_STATUS_BITS_REG2	(0x94)
#define	IXP_AUDIO_SPDIF_STATUS_BITS_REG3	(0x98)
#define	IXP_AUDIO_SPDIF_STATUS_BITS_REG4	(0x9c)
#define	IXP_AUDIO_SPDIF_STATUS_BITS_REG5	(0xa0)
#define	IXP_AUDIO_SPDIF_STATUS_BITS_REG6	(0xa4)
#define	IXP_AUDIO_PHY_SEMA			(0xa8)

/*
 * AC97 status and link control registers are located
 * in PCI configuration space.
 */
#define	IXP_REG_GSR				0x40
#define	IXP_REG_GCR				0x41

/* AC link interface status register */
#define	IXP_GSR_PRI_READY			0x01
#define	IXP_GSR_SEC_READY			0x04
#define	IXP_GSR_TRI_READY			0x10
#define	IXP_GSR_FOUR_READY			0x20

/* AC link interface control register */
#define	IXP_GCR_ENAC97				0x80
#define	IXP_GCR_RST				0x40
#define	IXP_GCR_RSYNCHI				0x20
#define	IXP_GCR_SDO				0x10
#define	IXP_GCR_VSR				0x08
#define	IXP_GCR_3D_AUDIO_CHANNEL		0x04

/*
 * Macro for AD1980 codec
 */
#define	AD1980_VID1		0x4144
#define	AD1980_VID2		0x5370
#define	AD1985_VID2		0x5375
#define	CODEC_AD_REG_MISC	0x76	/* offset of ad1980 misc control reg */
#define	AD1980_MISC_LOSEL	0x0020	/* Line-out amplifier output selector */
#define	AD1980_MISC_HPSEL	0x0400	/* HP-out amplifier output selector */

struct audioixp_port {
	int			num;
	struct audioixp_state	*statep;
	ddi_dma_handle_t	samp_dmah;
	ddi_acc_handle_t	samp_acch;
	size_t			samp_size;
	caddr_t			samp_kaddr;
	uint32_t		samp_paddr;

	ddi_dma_handle_t	bdl_dmah;
	ddi_acc_handle_t	bdl_acch;
	size_t			bdl_size;
	caddr_t			bdl_kaddr;
	uint32_t		bdl_paddr;

	unsigned		nframes;
	unsigned		fragfr;
	unsigned		fragsz;
	uint64_t		count;
	uint32_t		offset;
	uint8_t			nchan;

	unsigned		sync_dir;

	boolean_t		started;

	audio_engine_t		*engine;
};
typedef struct audioixp_port audioixp_port_t;

/*
 * buffer descriptor list entry, see datasheet
 */
struct audioixp_bd_entry {
	uint32_t	buf_base;	/* the address of the buffer */
	uint16_t	status;		/* status of the buffer */
	uint16_t	buf_len;	/* size of the buffer in DWORD */
	uint32_t	next;		/* physical addr of next bd_entry */
};
typedef struct	audioixp_bd_entry	audioixp_bd_entry_t;

/*
 * audioixp_state_t	-per instance state and operation data
 */
struct audioixp_state {
	kmutex_t		inst_lock;	/* state protection lock */
	dev_info_t		*dip;
	audio_dev_t		*adev;		/* audio handle */
	ac97_t			*ac97;
	audioixp_port_t		*play_port;
	audioixp_port_t		*rec_port;

	ddi_acc_handle_t	pcih;		/* pci configuration space */
	ddi_acc_handle_t	regsh;		/* for audio mixer register */
	caddr_t			regsp;		/* base of audio mixer regs */

	boolean_t		suspended;
	boolean_t		swap_out;	/* swap line-out and sur-out */

	uint32_t		ixp_codec_not_ready_bits; /* for codec detect */
};
typedef struct audioixp_state	 audioixp_state_t;

/*
 * Useful bit twiddlers
 */
#define	GET32(reg)	\
	ddi_get32(statep->regsh, (void *)(statep->regsp + (reg)))

#define	PUT32(reg, val)	\
	ddi_put32(statep->regsh, (void *)(statep->regsp + (reg)), (val))

#define	SET32(reg, val)	PUT32(reg, GET32(reg) | ((uint32_t)(val)))

#define	CLR32(reg, val)	PUT32(reg, GET32(reg) & ~((uint32_t)(val)))

#define	IXP_INTS		(175)	/* default interrupt rate */
#define	IXP_MIN_INTS		(24)	/* minimum interrupt rate */
#define	IXP_MAX_INTS		(500)	/* maximum interrupt rate */

#endif /* _AUDIOIXP_H_ */
