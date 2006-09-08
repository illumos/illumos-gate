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

#ifndef	_SYS_AUDIOIXP_IMPL_H_
#define	_SYS_AUDIOIXP_IMPL_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	IXP_CONFIG_REGS		(0)	/* PCI configure register */
#define	IXP_IO_AM_REGS		(1)	/* PCI base register 0x10 */

#define	IXP_IDNUM			(0x6175)
#define	IXP_MINPACKET			(0)
#define	IXP_MAXPACKET			(1*1024)
#define	IXP_HIWATER			(64*1024)
#define	IXP_LOWATER			(32*1024)

#define	IXP_DMA_PCM_IN		(1)
#define	IXP_DMA_PCM_OUT		(2)

#define	IXP_KIOP(X)	((kstat_intr_t *)(X->ixp_ksp->ks_data))

/*
 * PCI configuration registers and bits
 */
#define	IXP_PCI_REG_VID				(0x00)
#define	IXP_PCI_VID				(0x1002)

#define	IXP_PCI_REG_DID				(0x02)
#define	IXP_PCI_DID				(0x4370)

#define	IXP_PCI_REG_CMD				(0x04)
#define	IXP_PCI_CMD_MEM_ACC_EN			(0x0002)
#define	IXP_PCI_CMD_MASTER_EN			(0x0004)
#define	IXP_PCI_CMD_MEM_WR_INVAL_EN		(0x0010)
#define	IXP_PCI_CMD_PARITY_ERR_RESP		(0x0040)
#define	IXP_PCI_CMD_SERR_EN			(0x0100)
#define	IXP_PCI_CMD_INTA_EN			(0x0400)

#define	IXP_PCI_REG_STS				(0x06)
#define	IXP_PCI_STS_INTA			(0x0008)
#define	IXP_PCI_STS_CAP_LIST			(0x0010)
#define	IXP_PCI_STS_66M_CAP			(0x0020)
#define	IXP_PCI_STS_FAST_B2B_CAP		(0x0080)
#define	IXP_PCI_STS_MASTER_PARITY_ERROR		(0x0100)
#define	IXP_PCI_STS_RECEIVED_TARGET_ABORT	(0x1000)
#define	IXP_PCI_STS_RECEIVED_MASTER_ABORT	(0x2000)
#define	IXP_PCI_STS_SERR			(0x4000)
#define	IXP_PCI_STS_PARITY_ERR			(0x8000)

#define	IXP_PCI_REG_REV_ID_CLS_CODE		(0x08)
#define	IXP_PCI_REV_ID_400			(0x00)
#define	IXP_PCI_REV_ID_450			(0x80)
#define	IXP_PCI_CLS_CODE			(0x040100)

#define	IXP_PCI_REG_CACHE_LINE_SIZE		(0x0c)
#define	IXP_PCI_REG_LATENCY_TIMER		(0x0d)
#define	IXP_PCI_REG_HEADER_TYPE			(0x0e)
#define	IXP_PCI_REG_BUILTIN_SELF_TEST		(0x0f)
#define	IXP_PCI_REG_BA0				(0x10)
#define	IXP_PCI_REG_BA1				(0x14)
#define	IXP_PCI_REG_BA2				(0x18)
#define	IXP_PCI_REG_BA3				(0x1c)
#define	IXP_PCI_REG_BA4				(0x20)
#define	IXP_PCI_REG_BA5				(0x24)
#define	IXP_PCI_REG_CARDBUS_CIS_POINTER		(0x28)
#define	IXP_PCI_REG_SUB_ID			(0x2c)
#define	IXP_PCI_REG_EX_ROM_BA			(0x30)
#define	IXP_PCI_REG_CAP_P			(0x34)
#define	IXP_PCI_REG_INT_LINE			(0x3c)
#define	IXP_PCI_REG_INT_PIN			(0x3d)
#define	IXP_PCI_REG_MIN_GRANT			(0x3e)
#define	IXP_PCI_REG_MAX_LATENCY			(0x3f)
#define	IXP_PCI_REG_MSI_CAP_REG_SET_ID		(0x40)
#define	IXP_PCI_REG_MSI_MSG_CTRL		(0x42)
#define	IXP_PCI_REG_MSI_MSG_ADDR		(0x44)
#define	IXP_PCI_REG_MSI_MSG_DATA		(0x48)
#define	IXP_PCI_REG_MSI_PROGRAM_WEIGHT		(0x4c)
#define	IXP_PCI_REG_UNMASK_LATENCY_TIMER_EXPIRATION	(0x50)

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
#define	IXP_AUDIO_IN_FIFO_THREASHOLD		(0x1c)
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

#define	IXP_INIT_NO_RESTORE		(1)
#define	IXP_INIT_RESTORE		(0)
#define	IXP_CODEC_REG(r)		((r) >> 1)

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

#define	IXP_LAST_AC_REG				(0x3a)

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
#define	AD1980_SURR_MUTE	0x8080	/* Mute for surround volume register */

/*
 * Macro for ALC202 codec
 */
#define	ALC202_VID1		0x414c
#define	ALC202_VID2		0x4740

/* audioixp_state_t.flags defines */
#define	IXP_DMA_PLAY_STARTED	0x00000001
#define	IXP_DMA_PLAY_PAUSED	0x00000002
#define	IXP_DMA_PLAY_EMPTY	0x00000004
#define	IXP_DMA_RECD_STARTED	0x00000010

#define	IXP_BD_NUMS			(2)

/* we always have 2 chunks */
#define	IXP_CHUNK_MASK			(0x1l)

#define	IXP_BSIZE			(8*1024)

#define	IXP_MAX_CHANNELS		(200)		/* force max # chs */
#define	IXP_MAX_HW_CHANNELS		(32)
#define	IXP_MAX_IN_CHANNELS		(1)
#define	IXP_MAX_OUT_CHANNELS	\
	(IXP_MAX_HW_CHANNELS - IXP_MAX_IN_CHANNELS)
#define	IXP_IN_STREAM		(31)
#define	IXP_PORT_UNMUTE		(0xffffffff)

#define	IXP_MOD_SIZE			(32)
#define	IXP_PLAY_BUF_SZ			(1024)
#define	IXP_RECORD_BUF_SZ		(1024)
#define	IXP_BUF_MIN			(512)
#define	IXP_BUF_MAX			(8192)

/*
 * chunk buffer
 */
struct audioixp_bdlist_chunk {
	caddr_t			data_buf;	/* virtual address of buffer */
	uint32_t		addr_phy;	/* physical address of buffer */
	ddi_dma_handle_t	dma_handle;	/* dma handle */
	ddi_acc_handle_t	acc_handle;	/* access handle */
	size_t			real_len;	/* real len */
};
typedef struct audioixp_bdlist_chunk	audioixp_bdlist_chunk_t;

/*
 * sample buffer
 */
struct audioixp_sample_buf {
	boolean_t	io_started;	/* start/stop state for play/record */
	uint8_t		avail;		/* the number of available chunk(s) */
	uint8_t		next;		/* next bd entry to process */
	audioixp_bdlist_chunk_t
			chunk[2];	/* 2 chunks for each buffers */
	uint32_t	last_hw_pointer;
};
typedef struct audioixp_sample_buf	audioixp_sample_buf_t;


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
 * we allocate all buffer descriptors lists in continuous dma memory,
 * so just define the struct
 */
struct audioixp_bd_list {
	audioixp_bd_entry_t		pcm_in[IXP_BD_NUMS];
	audioixp_bd_entry_t		pcm_out[IXP_BD_NUMS];
};
typedef struct audioixp_bd_list	audioixp_bd_list_t;


/*
 * audioixp_state_t	-per instance state and operation data
 */
struct audioixp_state {
	kmutex_t		inst_lock;	/* state protection lock */
	ddi_iblock_cookie_t	intr_iblock;
	dev_info_t		*dip;	/* used by audioixp_getinfo() */
	audiohdl_t		audio_handle;	/* audio handle */
	am_ad_info_t		ad_info;	/* audio device info state */
	uint16_t		codec_shadow[64];
						/* shadow of AC97 registers */
	boolean_t		var_sr;		/* variable sample rate ? */
	boolean_t		swap_out;	/* swap line-out and sur-out */
	ddi_acc_handle_t	pci_conf_handle; /* pci configuration space */
	ddi_acc_handle_t	am_regs_handle;	/* for audio mixer register */
	caddr_t			am_regs_base;	/* base of audio mixer regs */

	ddi_dma_handle_t	bdl_dma_handle; /* for buffer descriptor list */
	ddi_acc_handle_t	bdl_acc_handle;	/* access handle of bdlist */
	audioixp_bd_list_t	*bdl_virtual;	/* virtual address of BDL */
	audioixp_bd_list_t	*bdl_phys;	/* Physical address of BDL */
	size_t			bdl_size;	/* real len of BDL */

	audioixp_sample_buf_t	play_buf; /* buffer for playback */
	audioixp_sample_buf_t	record_buf; /* buffer for record */
	int			play_buf_size;	/* the size of play buffer */
	int			record_buf_size; /* size of in buffer */

	audio_info_t		ixp_defaults; /* default state for dev */
	audio_device_t		ixp_dev_info; /* audio device info state */
	uint16_t		vol_bits_mask;	/* bits used to ctrl volume */

	kstat_t			*ixp_ksp;	/* kernel statistics */
	uint32_t		flags;		/* state flags */

	uint_t			ixp_psample_rate;	/* play sample rate */
	uint_t			ixp_pchannels;	/* play channels */
	uint_t			ixp_pprecision;	/* play precision */
	uint_t			ixp_csample_rate;	/* record sample rate */
	uint_t			ixp_cchannels;	/* record channels */
	uint_t			ixp_cprecision;	/* record precision */
	uint_t			ixp_output_port;	/* current out port */
	uint_t			ixp_input_port;	/* current input port */
	uint_t			ixp_monitor_gain;	/* monitor gain */
	int			ixp_csamples; /* pcm-in samples/intr */
	int			ixp_psamples; /* pcm-out samples/intr */

	uint32_t		ixp_res_flags;	/* resource flags */
	uint32_t		ixp_codec_not_ready_bits; /* for codec detect */
};
typedef struct audioixp_state	 audioixp_state_t;

/* bits of audioixp_state_t.IXP_res_flags */
#define	IXP_RS_PCI_REGS		(1u<<0)
#define	IXP_RS_AM_REGS		(1u<<1)
#define	IXP_RS_DMA_BDL_HANDLE	(1u<<2)
#define	IXP_RS_DMA_BDL_MEM	(1u<<3)
#define	IXP_RS_DMA_BDL_BIND	(1u<<4)

/*
 * Useful bit twiddlers
 */
#define	IXP_BM_GET8(reg)	\
	pci_config_get8(statep->pci_conf_handle, reg)

#define	IXP_BM_GET16(reg)	\
	pci_config_get16(statep->pci_conf_handle, reg)

#define	IXP_BM_GET32(reg)	\
	pci_config_get32(statep->pci_conf_handle, reg)

#define	IXP_BM_PUT8(reg, val)	\
	pci_config_put8(statep->pci_conf_handle, reg, val)

#define	IXP_BM_PUT16(reg, val)	\
	pci_config_put16(statep->pci_conf_handle, reg, val)

#define	IXP_BM_PUT32(reg, val)	\
	pci_config_put32(statep->pci_conf_handle, reg, val)

#define	IXP_AM_GET32(reg)	\
	ddi_get32(statep->am_regs_handle, \
	(void *)((char *)statep->am_regs_base + (reg)))

#define	IXP_AM_PUT32(reg, val)	\
	ddi_put32(statep->am_regs_handle, \
	(void *)((char *)statep->am_regs_base + (reg)), (val))

#define	IXP_AM_UPDATE8(reg, mask, value) \
	{ 				\
		int8_t	tmp;		\
		tmp = IXP_AM_GET8((reg));	\
		tmp &= ~(mask);		\
		tmp |= (value);		\
		IXP_PUT8((reg), (tmp));	\
	}

#define	IXP_AM_UPDATE16(reg, mask, value) \
	{ 				\
		int16_t	tmp;		\
		tmp = IXP_AM_GET16((reg));	\
		tmp &= ~(mask);		\
		tmp |= (value);		\
		IXP_PUT16((reg), (tmp));	\
	}

#define	IXP_AM_UPDATE32(reg, mask, value) \
	{ 				\
		int32_t	tmp;		\
		tmp = IXP_AM_GET32((reg));	\
		tmp &= ~(mask);		\
		tmp |= (value);		\
		IXP_AM_PUT32((reg), (tmp));	\
	}

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIOIXP_IMPL_H_ */
