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

#ifndef	_AUDIO810_H_
#define	_AUDIO810_H_

/*
 * Header file for the audio810 device driver
 */

/*
 * Driver supported configuration information
 */
#define	I810_NAME			"audio810"
#define	I810_MOD_NAME			"audio810 audio driver"

#define	I810_INTS			(120)	/* default interrupt rate */
#define	I810_MIN_INTS			(24)	/* minimum interrupt rate */
#define	I810_MAX_INTS			(500)	/* maximum interrupt rate */
#define	I810_NFRAGS			(8)	/* default # fragments */

/*
 * Misc. defines
 */

#define	I810_BD_NUMS			(32)
#define	I810_NUM_PORTS			(2)
#define	I810_MOD_SIZE			(16)

#define	I810_ROUNDUP(x, algn)		(((x) + ((algn) - 1)) & ~((algn) - 1))
#define	I810_KIOP(X)			((kstat_intr_t *)(X->ksp->ks_data))

/* The size of each entry of "reg" property is 5 integers */
#define	I810_INTS_PER_REG_PROP		5

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

#define	I810_REG_GCR			0x2C
#define	I810_REG_GSR			0x30
#define	I810_REG_CASR			0x34
#define	I810_REG_SISCTL			0x4C	/* SiS 7012 control */

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
/* SiS 7012 has its own flags here */
#define	I810_GCR_SIS_2_CHANNELS		(0 << 6)
#define	I810_GCR_SIS_4_CHANNELS		(1 << 6)
#define	I810_GCR_SIS_6_CHANNELS		(2 << 6)
#define	I810_GCR_SIS_CHANNELS_MASK	(3 << 6)


/*
 * Global Status Register
 */
#define	I810_GSR_TRI_READY		0x10000000	/* for ICH4/5 */
#define	I810_GSR_CAP8CH			0x00400000
#define	I810_GSR_CAP6CH			0x00200000
#define	I810_GSR_CAP4CH			0x00100000
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
 * SiS Control Register
 */
#define	I810_SISCTL_UNMUTE		0x01

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

#define	I810_PCM_IN		0
#define	I810_PCM_OUT		1

struct audio810_port {
	struct audio810_state	*statep;
	int			num;
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

	unsigned		intrs;
	unsigned		fragfr;
	unsigned		fragsz;
	uint64_t		count;
	uint8_t			nfrag;
	uint8_t			nchan;

	uint8_t			regoff;
	uint8_t			stsoff;		/* status offset */
	uint8_t			picboff;	/* picb offset */
	uint8_t			civ;
	uint16_t		picb;
	unsigned		sync_dir;

	boolean_t		started;

	audio_engine_t		*engine;
};
typedef struct audio810_port audio810_port_t;

/*
 * buffer descripter list entry, sees datasheet
 */
struct i810_bd_entry {
	uint32_t	buf_base;	/* the address of the buffer */
	uint16_t	buf_len;	/* the number of samples */
	uint16_t	buf_cmd;
};
typedef struct	i810_bd_entry	i810_bd_entry_t;
#define	BUF_CMD_BUP	0x4000
#define	BUF_CMD_IOC	0x8000

typedef enum i810_quirk {
	QUIRK_NONE = 0,
	QUIRK_SIS7012,		/* weird registers and such */
} i810_quirk_t;

/*
 * audio810_state_t	-per instance state and operation data
 */
struct audio810_state {
	kmutex_t		inst_lock;	/* state protection lock */
	kmutex_t		ac_lock;
	ddi_iblock_cookie_t	iblock;
	dev_info_t		*dip;	/* used by audio810_getinfo() */
	audio_dev_t		*adev;
	ac97_t			*ac97;
	audio810_port_t		*ports[2];

	ddi_acc_handle_t	am_regs_handle;	/* for audio mixer register */
	ddi_acc_handle_t	bm_regs_handle;	/* for bus master register */
	caddr_t			am_regs_base;	/* base of audio mixer regs */
	caddr_t			bm_regs_base;	/* base of bus master regs */

	kstat_t			*ksp;		/* kernel statistics */

	boolean_t		intr_added;
	boolean_t		suspended;	/* suspend/resume state */
	uint8_t			maxch;
	i810_quirk_t		quirk;
};
typedef struct audio810_state	 audio810_state_t;

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

#endif /* _AUDIO810_H_ */
