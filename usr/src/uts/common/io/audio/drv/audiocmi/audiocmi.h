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
 * Purpose: Driver for CMEDIA CM8738 PCI audio controller.
 */
/*
 * This file is part of Open Sound System
 *
 * Copyright (C) 4Front Technologies 1996-2008.
 *
 * This software is released under CDDL 1.0 source license.
 * See the COPYING file included in the main directory of this source
 * distribution for the license terms and conditions.
 */

#ifndef	_AUDIOCMI_H
#define	_AUDIOCMI_H

#define	CMEDIA_VENDOR_ID	0x13F6
#define	CMEDIA_CM8738		0x0111
#define	CMEDIA_CM8338A		0x0100
#define	CMEDIA_CM8338B		0x0101

/*
 * CM8338 registers definition
 */

#define	REG_FUNCTRL0		0x00
#define	REG_FUNCTRL1		0x04
#define	REG_CHFORMAT		0x08
#define	REG_INTCTRL		0x0C
#define	REG_INTSTAT		0x10
#define	REG_LEGACY		0x14
#define	REG_MISC		0x18
#define	REG_TDMAPOS		0x1C
#define	REG_SBVER		0x20	/* 8 bit access only */
#define	REG_IDXDATA		0x22	/* 8 bit access only */
#define	REG_IDXADDR		0x23	/* 8 bit access only */
#define	REG_MIX2		0x24
#define	REG_MIX3		0x25
#define	REG_VAUX		0x26
#define	REG_CH0_PADDR		0x80	/* buffer address (32b) */
#define	REG_CH0_BUFSZ		0x84	/* buffer size in samples (16b) */
#define	REG_CH0_FRAGSZ		0x86	/* fragment size in samples (16b) */
#define	REG_CH1_PADDR		0x88
#define	REG_CH1_BUFSZ		0x8C
#define	REG_CH1_FRAGSZ		0x8E
#define	REG_SPDIF_STAT		0x90
#define	REG_MISC2		0x92

#define	FUNCTRL0_CH1_RST	BIT(19)
#define	FUNCTRL0_CH0_RST	BIT(18)
#define	FUNCTRL0_CH1_EN		BIT(17)
#define	FUNCTRL0_CH0_EN		BIT(16)
#define	FUNCTRL0_CH1_PAUSE	BIT(3)
#define	FUNCTRL0_CH0_PAUSE	BIT(2)
#define	FUNCTRL0_CH1_REC	BIT(1)
#define	FUNCTRL0_CH0_REC	BIT(0)

#define	FUNCTRL1_DAC_RATE_MASK	(0x7 << 13)
#define	FUNCTRL1_DAC_RATE_48K	(0x7 << 13)
#define	FUNCTRL1_DAC_RATE_32K	(0x6 << 13)
#define	FUNCTRL1_DAC_RATE_16K	(0x5 << 13)
#define	FUNCTRL1_DAC_RATE_8K	(0x4 << 13)
#define	FUNCTRL1_DAC_RATE_44K	(0x3 << 13)
#define	FUNCTRL1_DAC_RATE_22K	(0x2 << 13)
#define	FUNCTRL1_DAC_RATE_11K	(0x1 << 13)
#define	FUNCTRL1_DAC_RATE_5K	(0x0 << 13)
#define	FUNCTRL1_ADC_RATE_MASK	(0x7 << 10)
#define	FUNCTRL1_ADC_RATE_48K	(0x7 << 10)
#define	FUNCTRL1_ADC_RATE_32K	(0x6 << 10)
#define	FUNCTRL1_ADC_RATE_16K	(0x5 << 10)
#define	FUNCTRL1_ADC_RATE_8K	(0x4 << 10)
#define	FUNCTRL1_ADC_RATE_44K	(0x3 << 10)
#define	FUNCTRL1_ADC_RATE_22K	(0x2 << 10)
#define	FUNCTRL1_ADC_RATE_11K	(0x1 << 10)
#define	FUNCTRL1_ADC_RATE_5K	(0x0 << 10)
#define	FUNCTRL1_INTRM		BIT(5)		/* enable MCB intr */
#define	FUNCTRL1_BREQ		BIT(4)		/* bus master enable */
#define	FUNCTRL1_VOICE_EN	BIT(3)
#define	FUNCTRL1_UART_EN	BIT(2)
#define	FUNCTRL1_JYSTK_EN	BIT(1)

#define	CHFORMAT_CHB3D5C	BIT(31)		/* 5 channel surround */
#define	CHFORMAT_CHB3D		BIT(29)		/* 4 channel surround */
#define	CHFORMAT_VER_MASK	(0x1f << 24)
#define	CHFORMAT_VER_033	0
#define	CHFORMAT_VER_037	1
#define	CHFORMAT_CH1_MASK	(0x3 << 2)
#define	CHFORMAT_CH1_16ST	(0x3 << 2)
#define	CHFORMAT_CH1_16MO	(0x2 << 2)
#define	CHFORMAT_CH1_8ST	(0x1 << 2)
#define	CHFORMAT_CH1_8MO	(0x0 << 2)
#define	CHFORMAT_CH0_MASK	(0x3 << 0)
#define	CHFORMAT_CH0_16ST	(0x3 << 0)
#define	CHFORMAT_CH0_16MO	(0x2 << 0)
#define	CHFORMAT_CH0_8ST	(0x1 << 0)
#define	CHFORMAT_CH0_8MO	(0x0 << 0)

#define	INTCTRL_MDL_MASK	(0xffU << 24)
#define	INTCTRL_MDL_068		(0x28 << 24)
#define	INTCTRL_MDL_055		(0x8 << 24)
#define	INTCTRL_MDL_039		(0x4 << 24)
#define	INTCTRL_TDMA_EN		BIT(18)
#define	INTCTRL_CH1_EN		BIT(17)
#define	INTCTRL_CH0_EN		BIT(16)

#define	INTSTAT_INTR		BIT(31)
#define	INTSTAT_MCB_INT		BIT(26)
#define	INTSTAT_UART_INT	BIT(16)
#define	INTSTAT_LTDMA_INT	BIT(15)
#define	INTSTAT_HTDMA_INT	BIT(14)
#define	INTSTAT_LHBTOG		BIT(7)
#define	INTSTAT_LEGDMA		BIT(6)
#define	INTSTAT_LEGHIGH		BIT(5)
#define	INTSTAT_LEGSTEREO	BIT(4)
#define	INTSTAT_CH1_BUSY	BIT(3)
#define	INTSTAT_CH0_BUSY	BIT(2)
#define	INTSTAT_CH1_INT		BIT(1)
#define	INTSTAT_CH0_INT		BIT(0)

#define	LEGACY_NXCHG		BIT(31)
#define	LEGACY_CHB3D6C		BIT(15)	/* 6 channel surround */
#define	LEGACY_CENTR2LN		BIT(14)	/* line in as center out */
#define	LEGACY_BASS2LN		BIT(13)	/* line in as lfe */
#define	LEGACY_EXBASSEN		BIT(12)	/* external bass input enable */

#define	MISC_PWD		BIT(31)	/* power down */
#define	MISC_RESET		BIT(30)
#define	MISC_N4SPK3D		BIT(26)	/* 4 channel emulation */
#define	MISC_ENDBDAC		BIT(23)	/* dual dac */
#define	MISC_XCHGDAC		BIT(22)	/* swap front/rear dacs */
#define	MISC_SPD32SEL		BIT(21)	/* 32-bit SPDIF (default 16-bit) */
#define	MISC_FM_EN		BIT(19)	/* enable legacy FM */
#define	MISC_SPDF_AC97		BIT(15)	/* spdif out 44.1k (0), 48 k (1) */
#define	MISC_ENCENTER		BIT(7)	/* enable center */
#define	MISC_REAR2LN		BIT(6)	/* send rear to line in */

#define	MIX2_FMMUTE		BIT(7)
#define	MIX2_WSMUTE		BIT(6)
#define	MIX2_SPK4		BIT(5)	/* line-in is rear out */
#define	MIX2_REAR2FRONT		BIT(4)	/* swap front and rear */
#define	MIX2_WAVEIN_L		BIT(3)	/* for recording wave out */
#define	MIX2_WAVEIN_R		BIT(2)	/* for recording wave out */
#define	MIX2_X3DEN		BIT(1)	/* 3D surround enable */
#define	MIX2_CDPLAY		BIT(0)	/* spdif-in PCM to DAC */

#define	MIX3_RAUXREN		BIT(7)
#define	MIX3_RAUXLEN		BIT(6)
#define	MIX3_VAUXRM		BIT(5)	/* r-aux mute */
#define	MIX3_VAUXLM		BIT(4)	/* l-aux mute */
#define	MIX3_VADCMIC_MASK	(0x7 << 1)	/* rec mic volume */
#define	MIX3_CEN2MIC		BIT(2)
#define	MIX3_MICGAINZ		BIT(0)	/* mic gain */

#define	VAUX_L_MASK		0xf0
#define	VAUX_R_MASK		0x0f

#define	MISC2_CHB3D8C		BIT(5)	/* 8 channel surround */
#define	MISC2_SPD32FMT		BIT(4)	/* spdif at 32 kHz */
#define	MISC2_ADC2SPDIF		BIT(3)	/* send adc to spdif out */
#define	MISC2_SHAREADC		BIT(2)	/* use adc for cen/lfe */

/* Indexes via SBINDEX */
#define	IDX_MASTER_LEFT		0x30
#define	IDX_MASTER_RIGHT	0x31
#define	IDX_VOICE_LEFT		0x32	/* PCM volume */
#define	IDX_VOICE_RIGHT		0x33
#define	IDX_CDDA_LEFT		0x36
#define	IDX_CDDA_RIGHT		0x37
#define	IDX_LINEIN_LEFT		0x38
#define	IDX_LINEIN_RIGHT	0x39
#define	IDX_MIC			0x3A
#define	IDX_SPEAKER		0x3B
#define	IDX_OUTMIX		0x3C
#define		OUTMIX_MIC	0x01
#define		OUTMIX_CD_R	0x02
#define		OUTMIX_CD_L	0x04
#define		OUTMIX_LINE_R	0x08
#define		OUTMIX_LINE_L	0x10
#define	IDX_INMIX_L		0x3D
#define	IDX_INMIX_R		0x3E
#define		INMIX_LINE_R	0x08
#define		INMIX_LINE_L	0x10
#define		INMIX_CD_R	0x20
#define		INMIX_CD_L	0x40
#define		INMIX_MIC	0x01
#define	IDX_IGAIN_L		0x3F
#define	IDX_IGAIN_R		0x40
#define	IDX_OGAIN_L		0x41
#define	IDX_OGAIN_R		0x42
#define	IDX_AGC			0x43
#define	IDX_TREBLE_L		0x44
#define	IDX_TREBLE_R		0x45
#define	IDX_BASS_L		0x46
#define	IDX_BASS_R		0x47


#define	IDX_EXTENSION		0xf0

#define	EXTENSION_VPHONE_MASK	(0x7 << 5)
#define	EXTENSION_VPHONE_MUTE	BIT(4)
#define	EXTENSION_BEEPER_MUTE	BIT(3)
#define	EXTENSION_VADCMIC3	BIT(0)

enum {
	SRC_MIC = 0,
	SRC_LINE,
	SRC_CD,
	SRC_AUX,
	SRC_MIX,
};

enum {
	CTL_VOLUME = 0,
	CTL_LINEOUT,
	CTL_SPEAKER,
	CTL_MIC,
	CTL_LINEIN,
	CTL_CD,
	CTL_AUX,
	CTL_RECSRCS,
	CTL_MONSRCS,
	CTL_MICBOOST,
	CTL_NUM
};

typedef struct cmpci_port cmpci_port_t;
typedef struct cmpci_dev cmpci_dev_t;
typedef struct cmpci_ctrl cmpci_ctrl_t;

struct cmpci_ctrl {
	cmpci_dev_t		*dev;
	audio_ctrl_t		*ctrl;
	uint64_t		value;
};

struct cmpci_port {
	cmpci_dev_t		*dev;
	audio_engine_t		*engine;
	int			num;
	ddi_acc_handle_t	acch;
	ddi_dma_handle_t	dmah;
	caddr_t			kaddr;
	uint32_t		paddr;
	unsigned		fragfr;
	unsigned		nfrags;
	unsigned		nframes;
	unsigned		bufsz;
	unsigned		nchan;

	boolean_t		capture;
	boolean_t		open;

	/* registers & bit masks */
	uint8_t			reg_paddr;
	uint8_t			reg_bufsz;
	uint8_t			reg_fragsz;

	uint32_t		fc0_rst_bit;
	uint32_t		fc0_rec_bit;
	uint32_t		fc0_en_bit;
	uint32_t		int_en_bit;
	uint32_t		fc1_rate_mask;
	uint32_t		chformat_mask;
	int			sync_dir;

	uint32_t		offset;	/* in bytes */
	uint64_t		count;	/* in bytes */

	void			(*callb)(audio_engine_t *);
	cmpci_ctrl_t		controls[CTL_NUM];
};

#define	PORT_MAX	2

struct cmpci_dev {
	audio_dev_t		*adev;
	dev_info_t		*dip;
	ddi_acc_handle_t	acch;
	caddr_t			regs;

	boolean_t		softvol;

	int			pintrs;
	int			rintrs;
	ddi_intr_handle_t	ihandle;
	kstat_t			*ksp;

	int			maxch;

	boolean_t		suspended;

	kmutex_t		mutex;
	cmpci_port_t		port[PORT_MAX];
	cmpci_ctrl_t		controls[CTL_NUM];
};

/*
 * The hardware appears to be able to address up to 16-bits worth of samples,
 * giving a total address space of 256K.  Note, however, that we will restrict
 * this further when we do fragment and memory allocation.
 */
#define	DEFINTS		175

#define	GET8(dev, offset)	\
	ddi_get8(dev->acch, (uint8_t *)(dev->regs + (offset)))
#define	GET16(dev, offset)	\
	ddi_get16(dev->acch, (uint16_t *)(void *)(dev->regs + (offset)))
#define	GET32(dev, offset)	\
	ddi_get32(dev->acch, (uint32_t *)(void *)(dev->regs + (offset)))
#define	PUT8(dev, offset, v)	\
	ddi_put8(dev->acch, (uint8_t *)(dev->regs + (offset)), v)
#define	PUT16(dev, offset, v)	\
	ddi_put16(dev->acch, (uint16_t *)(void *)(dev->regs + (offset)), v)
#define	PUT32(dev, offset, v)	\
	ddi_put32(dev->acch, (uint32_t *)(void *)(dev->regs + (offset)), v)

#define	CLR8(dev, offset, v)	PUT8(dev, offset, GET8(dev, offset) & ~(v))
#define	SET8(dev, offset, v)	PUT8(dev, offset, GET8(dev, offset) | (v))
#define	CLR16(dev, offset, v)	PUT16(dev, offset, GET16(dev, offset) & ~(v))
#define	SET16(dev, offset, v)	PUT16(dev, offset, GET16(dev, offset) | (v))
#define	CLR32(dev, offset, v)	PUT32(dev, offset, GET32(dev, offset) & ~(v))
#define	SET32(dev, offset, v)	PUT32(dev, offset, GET32(dev, offset) | (v))

#define	KSINTR(dev)	((kstat_intr_t *)((dev)->ksp->ks_data))

#define	BIT(n)		(1U << (n))

#endif	/* _AUDIOCMI_H */
