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

#ifndef	_SYS_AUDIO810_IMPL_H_
#define	_SYS_AUDIO810_IMPL_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL


/*
 * Misc. defines
 */
#define	I810_IDNUM			(0x6175)
#define	I810_MINPACKET			(0)
#define	I810_MAXPACKET			(1*1024)
#define	I810_HIWATER			(64*1024)
#define	I810_LOWATER			(32*1024)

#define	I810_DMA_PCM_IN			(1)
#define	I810_DMA_PCM_OUT		(2)

#define	I810_LAST_AC_REG		(0x3A)

#define	I810_INIT_NO_RESTORE		(1)
#define	I810_INIT_RESTORE		(0)
#define	I810_CODEC_REG(r)		((r) >> 1)

#define	I845_AM_REGS_SIZE		(0x200)
#define	I845_BM_REGS_SIZE		(0x100)
#define	I810_AM_REGS_SIZE		(0x100)
#define	I810_BM_REGS_SIZE		(0x40)
#define	I810_BD_NUMS			(32)
#define	I810_BD_SIZE	\
	(I810_BD_NUMS * sizeof (i810_bd_entry_t))

#define	I810_BSIZE			(8*1024)

#define	I810_NOT_SUSPENDED		(0)
#define	I810_SUSPENDED			(~I810_NOT_SUSPENDED)

#define	I810_MAX_CHANNELS		(200)		/* force max # chs */
#define	I810_MAX_HW_CHANNELS		(32)
#define	I810_MAX_IN_CHANNELS		(1)
#define	I810_MAX_OUT_CHANNELS	\
	(I810_MAX_HW_CHANNELS - I810_MAX_IN_CHANNELS)
#define	I810_INPUT_STREAM		(31)
#define	I810_PORT_UNMUTE		(0xffffffff)

#define	I810_KIOP(X)	((kstat_intr_t *)(X->i810_ksp->ks_data))

#define	I810_MOD_SIZE			(16)
#define	I810_PLAY_BUF_SZ		(1024)
#define	I810_RECORD_BUF_SZ		(1024)
#define	I810_BUF_MIN			(512)
#define	I810_BUF_MAX			(8192)

/* The size of each entry of "reg" property is 5 integers */
#define	I810_INTS_PER_REG_PROP		5

/* The index to the size of address space for each entry of "reg" property */
#define	I810_REG_PROP_ADDR_LEN_IDX	4

/* offset from the base of specified DMA engine */
#define	I810_OFFSET_BD_BASE		(0x00)
#define	I810_OFFSET_CIV			(0x04)
#define	I810_OFFSET_LVI			(0x05)
#define	I810_OFFSET_SR			(0x06)
#define	I810_OFFSET_PICB		(0x08)
#define	I810_OFFSET_PIV			(0x0A)
#define	I810_OFFSET_CR			(0x0B)

/* DMA engine offset from base */
#define	I810_BASE_PCM_IN		(0x00)
#define	I810_BASE_PCM_OUT		(0x10)
#define	I810_BASE_MIC			(0x20)

/* PCM in bus master registers */
#define	I810_PCM_IN_BD_BASE	(I810_OFFSET_BD_BASE)
#define	I810_PCM_IN_CIV		(I810_OFFSET_CIV)
#define	I810_PCM_IN_LVI		(I810_OFFSET_LVI)
#define	I810_PCM_IN_SR		(I810_OFFSET_SR)
#define	I810_PCM_IN_PICB	(I810_OFFSET_PICB)
#define	I810_PCM_IN_PIV		(I810_OFFSET_PIV)
#define	I810_PCM_IN_CR		(I810_OFFSET_CR)

#define	I810_PCM_OUT_BD_BASE	(I810_OFFSET_BD_BASE + I810_BASE_PCM_OUT)
#define	I810_PCM_OUT_CIV	(I810_OFFSET_CIV + I810_BASE_PCM_OUT)
#define	I810_PCM_OUT_LVI	(I810_OFFSET_LVI + I810_BASE_PCM_OUT)
#define	I810_PCM_OUT_SR		(I810_OFFSET_SR + I810_BASE_PCM_OUT)
#define	I810_PCM_OUT_PICB	(I810_OFFSET_PICB + I810_BASE_PCM_OUT)
#define	I810_PCM_OUT_PIV	(I810_OFFSET_PIV + I810_BASE_PCM_OUT)
#define	I810_PCM_OUT_CR		(I810_OFFSET_CR + I810_BASE_PCM_OUT)


#define	I810_MIC_BD_BASE	(I810_OFFSET_BD_BASE + I810_BASE_MIC)
#define	I810_MIC_CIV		(I810_OFFSET_CIV + I810_BASE_MIC)
#define	I810_MIC_LVI		(I810_OFFSET_LVI +I810_BASE_MIC)
#define	I810_MIC_SR		(I810_OFFSET_SR + I810_BASE_MIC)
#define	I810_MIC_PICB		(I810_OFFSET_PICB + I810_BASE_MIC)
#define	I810_MIC_PIV		(I810_OFFSET_PIV + I810_BASE_MIC)
#define	I810_MIC_CR		(I810_OFFSET_CR + I810_BASE_MIC)

#define	I810_REG_GCR			0x2C
#define	I810_REG_GSR			0x30
#define	I810_REG_CASR			0x34

/* bits of bus master status register */
#define	I810_BM_SR_DCH			0x01
#define	I810_BM_SR_CELV			0x02
#define	I810_BM_SR_LVBCI		0x04
#define	I810_BM_SR_BCIS			0x08
#define	I810_BM_SR_FIFOE		0x10

/* bits of bus master control register */
#define	I810_BM_CR_RUN			0x01
#define	I810_BM_CR_RST			0x02
#define	I810_BM_CR_LVBIE		0x04
#define	I810_BM_CR_FEIE			0x08
#define	I810_BM_CR_IOCE			0x10

#define	I810_BM_CR_PAUSE		0x00

/*
 * Global Control Register
 */
#define	I810_GCR_GPIE			0x00000001
#define	I810_GCR_COLD_RST		0x00000002
#define	I810_GCR_WARM_RST		0x00000004
#define	I810_GCR_ACLINK_OFF		0x00000008
#define	I810_GCR_PRI_INTR_ENABLE	0x00000010
#define	I810_GCR_SEC_INTR_ENABLE	0x00000020

/* For ICH2 or more, bit21:20 is the PCM 4/6-channel enable bits */
#define	I810_GCR_2_CHANNELS		(0 << 20)
#define	I810_GCR_4_CHANNELS		(1 << 20)
#define	I810_GCR_6_CHANNELS		(2 << 20)
#define	I810_GCR_CHANNELS_MASK		(3 << 20)

/*
 * Global Status Register
 */
#define	I810_GSR_TRI_READY		0x10000000	/* for ICH4/5 */
#define	I810_GSR_READ_COMPL		0x00008000
#define	I810_GSR_INTR_SEC_RESUME	0x00000800
#define	I810_GSR_INTR_PRI_RESUME	0x00000400
#define	I810_GSR_SEC_READY		0x00000200
#define	I810_GSR_PRI_READY		0x00000100
#define	I810_GSR_INTR_MIC		0x00000080
#define	I810_GSR_INTR_POUT		0x00000040
#define	I810_GSR_INTR_PIN		0x00000020
#define	I810_GSR_INTR_MO		0x00000004
#define	I810_GSR_INTR_MI		0x00000002
#define	I810_GSR_INTR_GSI		0x00000001
#define	I810_GSR_USE_INTR		0x00000060	/* PCM-IN ,PCM-OUT */

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
 * chunk buffer
 */
struct i810_bdlist_chunk {
	caddr_t			data_buf;	/* virtual address of buffer */
	uint32_t		addr_phy;	/* physical address of buffer */
	ddi_dma_handle_t	dma_handle;	/* dma handle */
	ddi_acc_handle_t	acc_handle;	/* access handle */
	size_t			real_len;	/* real len */
};
typedef struct i810_bdlist_chunk	i810_bdlist_chunk_t;

/*
 * sample buffer
 */
struct i810_sample_buf {
	boolean_t	io_started;	/* start/stop state for play/record */
	int		avail;		/* the number of available chunk(s) */
	uint8_t		tail;		/* For CPU, 1st available BD entry */
	uint8_t		head;		/* For CPU, 1st BD entry to reclaim */
	i810_bdlist_chunk_t	chunk[2];	/* 2 chunks for each buffers */
};
typedef struct i810_sample_buf	i810_sample_buf_t;


/*
 * buffer descripter list entry, sees datasheet
 */
struct i810_bd_entry {
	uint32_t	buf_base;	/* the address of the buffer */
	uint16_t	buf_len;	/* the number of samples */
	uint16_t	reserved:14;
	uint8_t		cmd_bup:1;
	uint8_t		cmd_ioc:1;
};
typedef struct	i810_bd_entry	i810_bd_entry_t;

/*
 * audio810_state_t	-per instance state and operation data
 */
struct audio810_state {
	kmutex_t		inst_lock;	/* state protection lock */
	ddi_iblock_cookie_t	intr_iblock;
	dev_info_t		*dip;	/* used by audio810_getinfo() */
	audiohdl_t		audio_handle;	/* audio handle */
	am_ad_info_t		ad_info;	/* audio device info state */
	uint16_t		codec_shadow[64]; /* shadow of AC97 registers */

	boolean_t		var_sr;		/* variable sample rate ? */
	boolean_t		swap_out;	/* swap line-out and sur-out */
	ddi_acc_handle_t	pci_conf_handle; /* pci configuration space */
	ddi_acc_handle_t	am_regs_handle;	/* for audio mixer register */
	ddi_acc_handle_t	bm_regs_handle;	/* for bus master register */
	caddr_t			am_regs_base;	/* base of audio mixer regs */
	caddr_t			bm_regs_base;	/* base of bus master regs */

	ddi_dma_handle_t	bdl_dma_handle; /* for buffer descriptor list */
	ddi_acc_handle_t	bdl_acc_handle;	/* access handle of bdlist */
	void			*bdl_virtual;	/* virtual address of BDL */
	size_t			bdl_size;	/* real len of BDL */
	i810_bd_entry_t		*bdl_virt_pin;  /* vaddr of PCM in BDL */
	i810_bd_entry_t		*bdl_virt_pout; /* vaddr of PCM out BDL */
	uint32_t		bdl_phys_pin;	/* phys addr of PCM in BDL */
	uint32_t		bdl_phys_pout;	/* phys addr of PCM in BDL */

	i810_sample_buf_t	play_buf;	/* buffer for playback */
	i810_sample_buf_t	record_buf;	/* buffer for record */
	int			play_buf_size;	/* the size of play buffer */
	int			record_buf_size;	/* size of in buffer */

	audio_info_t		i810_defaults;	/* default state for dev */
	audio_device_t		i810_dev_info;	/* audio device info state */
	uint16_t		vol_bits_mask;	/* bits used to ctrl volume */

	kstat_t			*i810_ksp;	/* kernel statistics */
	uint32_t		flags;		/* state flags */

	uint_t			i810_psample_rate;	/* play sample rate */
	uint_t			i810_pchannels;		/* play channels */
	uint_t			i810_pprecision;	/* play precision */
	uint_t			i810_csample_rate;	/* record sample rate */
	uint_t			i810_cchannels;		/* record channels */
	uint_t			i810_cprecision;	/* record precision */
	uint_t			i810_output_port;	/* current out port */
	uint_t			i810_input_port;	/* current input port */
	uint_t			i810_monitor_gain;	/* monitor gain */
	int			i810_csamples;	/* pcm-in samples/interrupt */
	int			i810_psamples;	/* pcm-out samples/intr */

	uint32_t		i810_res_flags;		/* resource flags */
	int			i810_suspended;	/* suspend/resume state */
	int			i810_busy_cnt;	/* device busy count */
	kcondvar_t		i810_cv;	/* suspend/resume cond. var */
};
typedef struct audio810_state	 audio810_state_t;

/* audio810_state_t.flags defines */
#define	I810_DMA_PLAY_STARTED	0x00000001	/* play DMA eng. initialized */
#define	I810_DMA_PLAY_PAUSED	0x00000002	/* play DMA engine paused */
#define	I810_DMA_PLAY_EMPTY	0x00000004	/* play DMA engine empty */
#define	I810_DMA_RECD_STARTED	0x00000010	/* record DMA engine started */



/* bits of audio810_state_t.i810_res_flags */
#define	I810_RS_PCI_REGS		0x0001
#define	I810_RS_AM_REGS			0x0002
#define	I810_RS_BM_REGS			0x0004
#define	I810_RS_DMA_BDL_HANDLE		0x0008
#define	I810_RS_DMA_BDL_MEM		0x0010
#define	I810_RS_DMA_BDL_BIND		0x0020


/*
 * Useful bit twiddlers
 */
#define	I810_BM_GET8(reg)	\
	ddi_get8(statep->bm_regs_handle, \
	(void *)((char *)statep->bm_regs_base + (reg)))

#define	I810_BM_GET16(reg)	\
	ddi_get16(statep->bm_regs_handle, \
	(void *)((char *)statep->bm_regs_base + (reg)))

#define	I810_BM_GET32(reg)	\
	ddi_get32(statep->bm_regs_handle, \
	(void *)((char *)statep->bm_regs_base + (reg)))

#define	I810_BM_PUT8(reg, val)	\
	ddi_put8(statep->bm_regs_handle, \
	(void *)((char *)statep->bm_regs_base + (reg)), (val))

#define	I810_BM_PUT16(reg, val)	\
	ddi_put16(statep->bm_regs_handle, \
	(void *)((char *)statep->bm_regs_base + (reg)), (val))

#define	I810_BM_PUT32(reg, val)	\
	ddi_put32(statep->bm_regs_handle, \
	(void *)((char *)statep->bm_regs_base + (reg)), (val))

#define	I810_AM_GET16(reg)	\
	ddi_get16(statep->am_regs_handle, \
	(void *)((char *)statep->am_regs_base + (reg)))

#define	I810_AM_PUT16(reg, val)	\
	ddi_put16(statep->am_regs_handle, \
	(void *)((char *)statep->am_regs_base + (reg)), (val))

#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO810_IMPL_H_ */
