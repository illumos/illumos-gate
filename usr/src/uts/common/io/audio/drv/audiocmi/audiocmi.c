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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Purpose: Driver for CMEDIA CM8738 PCI audio controller.
 */
/*
 * This file is part of Open Sound System
 *
 * Copyright (C) 4Front Technologies 1996-2008.
 */

#include <sys/audio/audio_driver.h>
#include <sys/note.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include "audiocmi.h"

/*
 * Note: The original 4Front driver had support SPDIF and dual dac
 * options.  Dual dac support is probably not terribly useful. SPDIF
 * on the other hand might be quite useful, we just don't have a card
 * that supports it at present.  Some variants of the chip are also
 * capable of jack retasking, but we're electing to punt on supporting
 * that as well, for now (we don't have any cards that would benefit
 * from this feature.)
 *
 * Note that surround support requires the use of the second DMA
 * engine, and that the same second DMA engine is the only way one can
 * capture from SPDIF.  Rather than support a lot more complexity in
 * the driver, we we will probably just punt on ever supporting
 * capture of SPDIF.  (SPDIF playback should be doable, however.)
 *
 * Adding back support for the advanced features would be an
 * interesting project for someone with access to suitable hardware.
 *
 * Note that each variant (CMI 8338, 8738-033, -037, -055, and 8768)
 * seems to have significant differences in some of the registers.
 * While programming these parts for basic stereo is pretty much the
 * same on all parts, doing anything more than that can be
 * sigificantly different for each part.
 */

static ddi_device_acc_attr_t acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_VERSION,	/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffU,		/* dma_attr_addr_hi */
	0x3ffff,		/* dma_attr_count_max */
	0x8,			/* dma_attr_align */
	0x7f,			/* dma_attr_burstsizes */
	0x1,			/* dma_attr_minxfer */
	0x3ffff,		/* dma_attr_maxxfer */
	0x3ffff,		/* dma_attr_seg */
	0x1,			/* dma_attr_sgllen */
	0x1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};


static int
cmpci_open(void *arg, int flag, uint_t *nframesp, caddr_t *bufp)
{
	cmpci_port_t *port = arg;
	cmpci_dev_t *dev = port->dev;

	_NOTE(ARGUNUSED(flag));

	mutex_enter(&dev->mutex);

	*nframesp = port->nframes;
	*bufp = port->kaddr;

	port->count = 0;
	mutex_exit(&dev->mutex);

	return (0);
}

static void
cmpci_close(void *arg)
{
	_NOTE(ARGUNUSED(arg));
}

static int
cmpci_start(void *arg)
{
	cmpci_port_t	*port = arg;
	cmpci_dev_t	*dev = port->dev;

	mutex_enter(&dev->mutex);

	port->offset = 0;

	/* reset channel */
	SET32(dev, REG_FUNCTRL0, port->fc0_rst_bit);
	drv_usecwait(10);
	CLR32(dev, REG_FUNCTRL0, port->fc0_rst_bit);
	drv_usecwait(10);

	/* Set 48k 16-bit stereo -- these are just with all bits set. */
	SET32(dev, REG_FUNCTRL1, port->fc1_rate_mask);
	SET32(dev, REG_CHFORMAT, port->chformat_mask);

	if ((port->num == 1) && (dev->maxch > 2)) {
		CLR32(dev, REG_LEGACY, LEGACY_NXCHG);

		if (port->nchan > 2) {
			SET32(dev, REG_MISC, MISC_XCHGDAC);
			CLR32(dev, REG_MISC, MISC_N4SPK3D);
		} else {
			CLR32(dev, REG_MISC, MISC_XCHGDAC);
			SET32(dev, REG_MISC, MISC_N4SPK3D);
		}

		switch (port->nchan) {
		case 2:
			if (dev->maxch >= 8) {
				CLR8(dev, REG_MISC2, MISC2_CHB3D8C);
			}
			if (dev->maxch >= 6) {
				CLR32(dev, REG_CHFORMAT, CHFORMAT_CHB3D5C);
				CLR32(dev, REG_LEGACY, LEGACY_CHB3D6C);
			}
			if (dev->maxch >= 4) {
				CLR32(dev, REG_CHFORMAT, CHFORMAT_CHB3D);
			}
			break;
		case 4:
			if (dev->maxch >= 8) {
				CLR8(dev, REG_MISC2, MISC2_CHB3D8C);
			}
			if (dev->maxch >= 6) {
				CLR32(dev, REG_CHFORMAT, CHFORMAT_CHB3D5C);
				CLR32(dev, REG_LEGACY, LEGACY_CHB3D6C);
				CLR32(dev, REG_MISC, MISC_ENCENTER);
				CLR32(dev, REG_LEGACY, LEGACY_EXBASSEN);
			}
			SET32(dev, REG_CHFORMAT, CHFORMAT_CHB3D);
			break;
		case 6:
			if (dev->maxch >= 8) {
				CLR8(dev, REG_MISC2, MISC2_CHB3D8C);
			}
			SET32(dev, REG_CHFORMAT, CHFORMAT_CHB3D5C);
			SET32(dev, REG_LEGACY, LEGACY_CHB3D6C);
			CLR32(dev, REG_MISC, MISC_ENCENTER);
			CLR32(dev, REG_LEGACY, LEGACY_EXBASSEN);
			CLR32(dev, REG_CHFORMAT, CHFORMAT_CHB3D);
			break;

		case 8:
			SET8(dev, REG_MISC2, MISC2_CHB3D8C);
			CLR32(dev, REG_MISC, MISC_ENCENTER);
			CLR32(dev, REG_LEGACY, LEGACY_EXBASSEN);
			CLR32(dev, REG_CHFORMAT, CHFORMAT_CHB3D5C);
			CLR32(dev, REG_LEGACY, LEGACY_CHB3D6C);
			CLR32(dev, REG_CHFORMAT, CHFORMAT_CHB3D);
			break;
		}
	}

	PUT32(dev, port->reg_paddr, port->paddr);
	PUT16(dev, port->reg_bufsz, (port->bufsz / 4) - 1);
	PUT16(dev, port->reg_fragsz, (port->bufsz  / 4) - 1);

	/* Analog output */
	if (port->capture) {
		/* Analog capture */
		SET32(dev, REG_FUNCTRL0, port->fc0_rec_bit);
	} else {
		CLR32(dev, REG_FUNCTRL0, port->fc0_rec_bit);
	}

	SET32(dev, REG_FUNCTRL0, port->fc0_en_bit);
	mutex_exit(&dev->mutex);

	return (0);
}

static void
cmpci_stop(void *arg)
{
	cmpci_port_t	*port = arg;
	cmpci_dev_t	*dev = port->dev;

	mutex_enter(&dev->mutex);
	CLR32(dev, REG_FUNCTRL0, port->fc0_en_bit);
	mutex_exit(&dev->mutex);
}

static uint64_t
cmpci_count(void *arg)
{
	cmpci_port_t	*port = arg;
	cmpci_dev_t	*dev = port->dev;
	uint64_t	count;
	uint32_t	offset;

	mutex_enter(&dev->mutex);

	/* this gives us the offset in dwords */
	offset = (port->bufsz / 4) - (GET16(dev, port->reg_bufsz) + 1);

	/* check for wrap - note that the count is given in dwords */
	if (offset < port->offset) {
		count = ((port->bufsz / 4) - port->offset) + offset;
	} else {
		count = offset - port->offset;
	}
	port->count += count;
	port->offset = offset;
	count = port->count;

	mutex_exit(&dev->mutex);

	/*
	 * convert dwords to frames - unfortunately this requires a
	 * divide
	 */
	return (count / (port->nchan / 2));
}

#define	MASK(nbits)	((1 << (nbits)) - 1)
#define	SCALE(val, nbits)	\
	((uint8_t)((((val) * MASK(nbits)) / 100)) << (8 - (nbits)))

#define	LEFT(dev, ctl)	min(((dev->controls[ctl].value) >> 8), 100)
#define	RIGHT(dev, ctl)	min(((dev->controls[ctl].value) & 0xff), 100)
#define	MONO(dev, ctl)	min(dev->controls[ctl].value, 100)

static void
cmpci_setmixer(cmpci_dev_t *dev, uint8_t idx, uint8_t val)
{
	PUT8(dev, REG_IDXADDR, idx);
	PUT8(dev, REG_IDXDATA, val);
}

static uint8_t
cmpci_getmixer(cmpci_dev_t *dev, uint8_t idx)
{
	PUT8(dev, REG_IDXADDR, idx);
	return (GET8(dev, REG_IDXDATA));
}


static void
cmpci_configure_mixer(cmpci_dev_t *dev)
{
	uint64_t	left, right;
	uint8_t		outmix;
	uint8_t		inmix[2];
	uint64_t	recsrcs;
	uint64_t	monsrcs;

	/* reset all mix values */
	outmix = inmix[0] = inmix[1] = 0;

	outmix = OUTMIX_MIC |
	    OUTMIX_CD_R | OUTMIX_CD_L | OUTMIX_LINE_R | OUTMIX_LINE_L;

	inmix[0] = INMIX_LINE_L | INMIX_CD_L | INMIX_MIC;
	inmix[1] = INMIX_LINE_R | INMIX_CD_R | INMIX_MIC;

	recsrcs = dev->controls[CTL_RECSRCS].value;
	monsrcs = dev->controls[CTL_MONSRCS].value;

	/* program PCM volume */
	left = MONO(dev, CTL_VOLUME);
	if (left) {
		/* left and right are the same */
		cmpci_setmixer(dev, IDX_VOICE_LEFT, SCALE(left, 5));
		cmpci_setmixer(dev, IDX_VOICE_RIGHT, SCALE(left, 5));
		CLR8(dev, REG_MIX2, MIX2_WSMUTE);
	} else {
		cmpci_setmixer(dev, IDX_VOICE_LEFT, 0);
		cmpci_setmixer(dev, IDX_VOICE_RIGHT, 0);
		SET8(dev, REG_MIX2, MIX2_WSMUTE);
	}

	left = LEFT(dev, CTL_LINEOUT);
	right = RIGHT(dev, CTL_LINEOUT);

	/* lineout/master volume - no separate mute */
	cmpci_setmixer(dev, IDX_MASTER_LEFT, SCALE(left, 5));
	cmpci_setmixer(dev, IDX_MASTER_RIGHT, SCALE(right, 5));

	/* speaker volume - mute in extension register, but we don't use */
	left = MONO(dev, CTL_SPEAKER);
	cmpci_setmixer(dev, IDX_SPEAKER, SCALE(left, 2));

	/* mic gain */
	left = MONO(dev, CTL_MIC);
	if (left) {
		cmpci_setmixer(dev, IDX_MIC, SCALE(left, 5));
		/* set record mic gain */
		uint8_t v = GET8(dev, REG_MIX3);
		v &= ~(0x7 << 1);
		v |= ((left * 7) / 100) << 1;
		PUT8(dev, REG_MIX3, v);
		cmpci_setmixer(dev, 0x3f, SCALE(100, 2));
		cmpci_setmixer(dev, 0x40, SCALE(100, 2));
	} else {
		cmpci_setmixer(dev, IDX_MIC, 0);
		outmix &= ~OUTMIX_MIC;
		inmix[0] &= ~INMIX_MIC;
		inmix[1] &= ~INMIX_MIC;
	}

	/* line in */
	left = LEFT(dev, CTL_LINEOUT);
	right = RIGHT(dev, CTL_LINEOUT);
	if (left) {
		cmpci_setmixer(dev, IDX_LINEIN_LEFT, SCALE(left, 5));
	} else {
		cmpci_setmixer(dev, IDX_LINEIN_LEFT, 0);
		inmix[0] &= ~INMIX_LINE_L;
		outmix &= ~OUTMIX_LINE_L;
	}
	if (right) {
		cmpci_setmixer(dev, IDX_LINEIN_RIGHT, SCALE(left, 5));
	} else {
		cmpci_setmixer(dev, IDX_LINEIN_RIGHT, 0);
		inmix[1] &= ~INMIX_LINE_R;
		outmix &= ~OUTMIX_LINE_R;
	}

	/* cd */
	left = LEFT(dev, CTL_CD);
	right = RIGHT(dev, CTL_CD);
	if (left) {
		cmpci_setmixer(dev, IDX_CDDA_LEFT, SCALE(left, 5));
	} else {
		cmpci_setmixer(dev, IDX_CDDA_LEFT, 0);
		inmix[0] &= ~INMIX_CD_L;
		outmix &= ~OUTMIX_CD_L;
	}
	if (right) {
		cmpci_setmixer(dev, IDX_CDDA_RIGHT, SCALE(left, 5));
	} else {
		cmpci_setmixer(dev, IDX_CDDA_RIGHT, 0);
		inmix[1] &= ~INMIX_CD_R;
		outmix &= ~OUTMIX_CD_R;
	}

	/* aux - trickier because it doesn't use regular sbpro mixer */
	left = LEFT(dev, CTL_AUX);
	right = RIGHT(dev, CTL_AUX);
	PUT8(dev, REG_VAUX, (((left * 15) / 100) << 4) | ((right * 15) / 100));
	/* maybe enable recording */
	if ((left || right) && (recsrcs & (1 << SRC_LINE))) {
		SET8(dev, REG_MIX3, MIX3_RAUXREN | MIX3_RAUXLEN);
	} else {
		CLR8(dev, REG_MIX3, MIX3_RAUXREN | MIX3_RAUXLEN);
	}
	/* maybe enable monitoring */
	if ((left || right) && (monsrcs & (1 << SRC_AUX))) {
		CLR8(dev, REG_MIX3, MIX3_VAUXRM | MIX3_VAUXLM);
	} else {
		SET8(dev, REG_MIX3, MIX3_VAUXRM | MIX3_VAUXLM);
	}

	/* now do the recsrcs */
	if ((recsrcs & (1 << SRC_MIC)) == 0) {
		inmix[0] &= ~INMIX_MIC;
		inmix[1] &= ~INMIX_MIC;
	}
	if ((recsrcs & (1 << SRC_LINE)) == 0) {
		inmix[0] &= ~INMIX_LINE_L;
		inmix[1] &= ~INMIX_LINE_R;
	}
	if ((recsrcs & (1 << SRC_CD)) == 0) {
		inmix[0] &= ~INMIX_CD_L;
		inmix[1] &= ~INMIX_CD_R;
	}
	if (recsrcs & (1 << SRC_MIX)) {
		SET8(dev, REG_MIX2, MIX2_WAVEIN_L | MIX2_WAVEIN_R);
	} else {
		CLR8(dev, REG_MIX2, MIX2_WAVEIN_L | MIX2_WAVEIN_R);
	}
	cmpci_setmixer(dev, IDX_INMIX_L, inmix[0]);
	cmpci_setmixer(dev, IDX_INMIX_R, inmix[1]);

	/* now the monsrcs */
	if ((monsrcs & (1 << SRC_MIC)) == 0) {
		outmix &= ~OUTMIX_MIC;
	}
	if ((monsrcs & (1 << SRC_LINE)) == 0) {
		outmix &= ~(OUTMIX_LINE_L | OUTMIX_LINE_R);
	}
	if ((monsrcs & (1 << SRC_CD)) == 0) {
		outmix &= ~(OUTMIX_CD_L | OUTMIX_CD_R);
	}
	cmpci_setmixer(dev, IDX_OUTMIX, outmix);

	/* micboost */
	if (dev->controls[CTL_MICBOOST].value != 0) {
		CLR8(dev, REG_MIX3, MIX3_MICGAINZ);
		cmpci_setmixer(dev, IDX_EXTENSION,
		    cmpci_getmixer(dev, IDX_EXTENSION) & ~0x1);
	} else {
		SET8(dev, REG_MIX3, MIX3_MICGAINZ);
		cmpci_setmixer(dev, IDX_EXTENSION,
		    cmpci_getmixer(dev, IDX_EXTENSION) | 0x1);
	}
}

static int
cmpci_set_ctrl(void *arg, uint64_t val)
{
	cmpci_ctrl_t *cc = arg;
	cmpci_dev_t *dev = cc->dev;

	/*
	 * We don't bother to check for valid values - a bogus value
	 * will give incorrect volumes, but is otherwise harmless.
	 */
	mutex_enter(&dev->mutex);
	cc->value = val;
	cmpci_configure_mixer(dev);
	mutex_exit(&dev->mutex);

	return (0);
}

static int
cmpci_get_ctrl(void *arg, uint64_t *val)
{
	cmpci_ctrl_t *cc = arg;
	cmpci_dev_t *dev = cc->dev;

	mutex_enter(&dev->mutex);
	*val = cc->value;
	mutex_exit(&dev->mutex);
	return (0);
}

#define	PLAYCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_PLAY)
#define	RECCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_REC)
#define	MONCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_MONITOR)
#define	PCMVOL	(PLAYCTL | AUDIO_CTRL_FLAG_PCMVOL)
#define	MAINVOL	(PLAYCTL | AUDIO_CTRL_FLAG_MAINVOL)
#define	RECVOL	(RECCTL | AUDIO_CTRL_FLAG_RECVOL)

static void
cmpci_alloc_ctrl(cmpci_dev_t *dev, uint32_t num, uint64_t val)
{
	audio_ctrl_desc_t	desc;
	cmpci_ctrl_t		*cc;

	cc = &dev->controls[num];
	bzero(&desc, sizeof (desc));
	cc->dev = dev;

	switch (num) {
	case CTL_VOLUME:
		desc.acd_name = AUDIO_CTRL_ID_VOLUME;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		break;

	case CTL_LINEOUT:
		desc.acd_name = AUDIO_CTRL_ID_LINEOUT;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		break;

	case CTL_SPEAKER:
		desc.acd_name = AUDIO_CTRL_ID_SPEAKER;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		break;

	case CTL_MIC:
		desc.acd_name = AUDIO_CTRL_ID_MIC;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;

	case CTL_LINEIN:
		desc.acd_name = AUDIO_CTRL_ID_LINEIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;

	case CTL_CD:
		desc.acd_name = AUDIO_CTRL_ID_CD;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;

	case CTL_AUX:
		desc.acd_name = AUDIO_CTRL_ID_AUX1IN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;

	case CTL_RECSRCS:
		desc.acd_name = AUDIO_CTRL_ID_RECSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_enum[SRC_MIC] = AUDIO_PORT_MIC;
		desc.acd_enum[SRC_LINE] = AUDIO_PORT_LINEIN;
		desc.acd_enum[SRC_CD] = AUDIO_PORT_CD;
		desc.acd_enum[SRC_AUX] = AUDIO_PORT_AUX1IN;
		desc.acd_enum[SRC_MIX] = AUDIO_PORT_STEREOMIX;
		desc.acd_minvalue = (1 << (SRC_MIX + 1)) - 1;
		desc.acd_maxvalue = desc.acd_minvalue;
		desc.acd_flags = RECCTL | AUDIO_CTRL_FLAG_MULTI;
		break;

	case CTL_MONSRCS:
		desc.acd_name = AUDIO_CTRL_ID_MONSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_enum[SRC_MIC] = AUDIO_PORT_MIC;
		desc.acd_enum[SRC_LINE] = AUDIO_PORT_LINEIN;
		desc.acd_enum[SRC_CD] = AUDIO_PORT_CD;
		desc.acd_enum[SRC_AUX] = AUDIO_PORT_AUX1IN;
		desc.acd_minvalue = ((1 << (SRC_AUX + 1)) - 1);
		desc.acd_maxvalue = desc.acd_minvalue;
		desc.acd_flags = MONCTL | AUDIO_CTRL_FLAG_MULTI;
		break;

	case CTL_MICBOOST:
		desc.acd_name = AUDIO_CTRL_ID_MICBOOST;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = RECCTL;
		break;
	}

	cc->value = val;
	cc->ctrl = audio_dev_add_control(dev->adev, &desc,
	    cmpci_get_ctrl, cmpci_set_ctrl, cc);
}

static void
cmpci_add_controls(cmpci_dev_t *dev)
{
	if (dev->softvol) {
		audio_dev_add_soft_volume(dev->adev);
	} else {
		cmpci_alloc_ctrl(dev, CTL_VOLUME, 75);
	}
	cmpci_alloc_ctrl(dev, CTL_LINEOUT, 90 | (90 << 8));
	cmpci_alloc_ctrl(dev, CTL_SPEAKER, 75);
	cmpci_alloc_ctrl(dev, CTL_MIC, 32);
	cmpci_alloc_ctrl(dev, CTL_LINEIN, 64 | (64 << 8));
	cmpci_alloc_ctrl(dev, CTL_CD, 75 | (75 << 8));
	cmpci_alloc_ctrl(dev, CTL_AUX, 75 | (75 << 8));
	cmpci_alloc_ctrl(dev, CTL_RECSRCS, (1 << SRC_MIC));
	cmpci_alloc_ctrl(dev, CTL_MONSRCS, 0);
	cmpci_alloc_ctrl(dev, CTL_MICBOOST, 0);
}

static void
cmpci_del_controls(cmpci_dev_t *dev)
{
	for (int i = 0; i < CTL_NUM; i++) {
		if (dev->controls[i].ctrl) {
			audio_dev_del_control(dev->controls[i].ctrl);
			dev->controls[i].ctrl = NULL;
		}
	}
}

static void
cmpci_reset(cmpci_dev_t *dev)
{
	/* Full reset */
	SET32(dev, REG_MISC, MISC_RESET);
	(void) GET32(dev, REG_MISC);
	drv_usecwait(100);
	CLR32(dev, REG_MISC, MISC_RESET);

	/* reset all channels */
	PUT32(dev, REG_FUNCTRL0, 0);

	/* disable interrupts and such */
	CLR32(dev, REG_FUNCTRL0, FUNCTRL0_CH0_EN | FUNCTRL0_CH1_EN);
	CLR32(dev, REG_INTCTRL, INTCTRL_CH0_EN | INTCTRL_CH1_EN);

	/* disable uart, joystick in Function Control Reg1 */
	CLR32(dev, REG_FUNCTRL1, FUNCTRL1_UART_EN | FUNCTRL1_JYSTK_EN);

	/*
	 * Set DAC and ADC rates to 48 kHz - note that both rates have
	 * all bits set in them, so we can do this with a simple "set".
	 */
	SET32(dev, REG_FUNCTRL1,
	    FUNCTRL1_DAC_RATE_48K | FUNCTRL1_ADC_RATE_48K);

	/* Set 16-bit stereo -- also these are just with all bits set. */
	SET32(dev, REG_CHFORMAT, CHFORMAT_CH0_16ST | CHFORMAT_CH1_16ST);
}

static int
cmpci_format(void *unused)
{
	_NOTE(ARGUNUSED(unused));
	return (AUDIO_FORMAT_S16_LE);
}

static int
cmpci_channels(void *arg)
{
	cmpci_port_t *port = arg;

	return (port->nchan);
}

static void
cmpci_chinfo(void *arg, int chan, unsigned *offset, unsigned *incr)
{
	cmpci_port_t *port = arg;
	static const int map8ch[] = { 0, 1, 4, 5, 2, 3, 6, 7 };
	static const int map4ch[] = { 0, 1, 2, 3 };

	if (port->nchan <= 4) {
		*offset = map4ch[chan];
	} else {
		*offset = map8ch[chan];
	}
	*incr = port->nchan;
}

static int
cmpci_rate(void *unused)
{
	_NOTE(ARGUNUSED(unused));
	return (48000);
}

static void
cmpci_sync(void *arg, unsigned nframes)
{
	cmpci_port_t *port = arg;

	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(port->dmah, 0, 0, port->sync_dir);
}

audio_engine_ops_t cmpci_engine_ops = {
	AUDIO_ENGINE_VERSION,		/* version number */
	cmpci_open,
	cmpci_close,
	cmpci_start,
	cmpci_stop,
	cmpci_count,
	cmpci_format,
	cmpci_channels,
	cmpci_rate,
	cmpci_sync,
	NULL,		/* qlen */
	cmpci_chinfo,
	NULL,		/* playahead */
};

static int
cmpci_init(cmpci_dev_t *dev)
{
	audio_dev_t	*adev = dev->adev;
	int		playch;

	playch  = ddi_prop_get_int(DDI_DEV_T_ANY, dev->dip,
	    DDI_PROP_DONTPASS, "channels", dev->maxch);

	if ((playch % 2) || (playch < 2) || (playch > dev->maxch)) {
		audio_dev_warn(adev,
		    "Invalid channels property (%d), resetting to %d",
		    playch, dev->maxch);
		playch = dev->maxch;
	}

	for (int i = 0; i < PORT_MAX; i++) {

		cmpci_port_t *port;
		unsigned dmaflags;
		unsigned caps;
		size_t rlen;
		ddi_dma_cookie_t c;
		unsigned ccnt;

		port = &dev->port[i];
		port->dev = dev;
		port->num = i;

		/*
		 * Channel 0 is recording channel, unless we are in
		 * dual DAC mode.  The reason for this is simple --
		 * only channel "B" (which I presume to mean channel
		 * 1) supports multichannel configuration.
		 *
		 * However, if we're going to use SPDIF recording,
		 * then recording *must* occur on channel 1.  Yes, the
		 * hardware is "strange".
		 */

		switch (i) {
		case 0:
			caps = ENGINE_INPUT_CAP;
			dmaflags = DDI_DMA_READ | DDI_DMA_CONSISTENT;
			port->reg_paddr = REG_CH0_PADDR;
			port->reg_bufsz = REG_CH0_BUFSZ;
			port->reg_fragsz = REG_CH0_FRAGSZ;
			port->fc0_rst_bit = FUNCTRL0_CH0_RST;
			port->fc0_rec_bit = FUNCTRL0_CH0_REC;
			port->fc0_en_bit = FUNCTRL0_CH0_EN;
			port->sync_dir = DDI_DMA_SYNC_FORKERNEL;
			port->capture = B_TRUE;
			port->fc1_rate_mask = FUNCTRL1_ADC_RATE_48K;
			port->chformat_mask = CHFORMAT_CH0_16ST;
			port->nchan = 2;
			break;

		case 1:
			caps = ENGINE_OUTPUT_CAP;
			dmaflags = DDI_DMA_WRITE | DDI_DMA_CONSISTENT;
			port->reg_paddr = REG_CH1_PADDR;
			port->reg_bufsz = REG_CH1_BUFSZ;
			port->reg_fragsz = REG_CH1_FRAGSZ;
			port->fc0_rst_bit = FUNCTRL0_CH1_RST;
			port->fc0_rec_bit = FUNCTRL0_CH1_REC;
			port->fc0_en_bit = FUNCTRL0_CH1_EN;
			port->sync_dir = DDI_DMA_SYNC_FORDEV;
			port->capture = B_FALSE;
			port->fc1_rate_mask = FUNCTRL1_DAC_RATE_48K;
			port->chformat_mask = CHFORMAT_CH1_16ST;
			port->nchan = playch;
			break;
		}

		/*
		 * For efficiency, we'd like to have the fragments
		 * evenly divisble by 64 bytes.  Since frames are
		 * already evenly divisble by 4 (16-bit stereo), this
		 * is adequate.  For a typical configuration (175 Hz
		 * requested) this will translate to 166 Hz.
		 */
		port->nframes = 2048;
		port->bufsz = port->nframes * port->nchan * 2;

		if (ddi_dma_alloc_handle(dev->dip, &dma_attr, DDI_DMA_DONTWAIT,
		    NULL, &port->dmah) != DDI_SUCCESS) {
			audio_dev_warn(adev, "ch%d: dma hdl alloc failed", i);
			return (DDI_FAILURE);
		}
		if (ddi_dma_mem_alloc(port->dmah, port->bufsz, &buf_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL, &port->kaddr,
		    &rlen, &port->acch) != DDI_SUCCESS) {
			audio_dev_warn(adev, "ch%d: dma mem allcoc failed", i);
			return (DDI_FAILURE);
		}
		bzero(port->kaddr, rlen);

		if (ddi_dma_addr_bind_handle(port->dmah, NULL, port->kaddr,
		    rlen, dmaflags, DDI_DMA_DONTWAIT, NULL, &c, &ccnt) !=
		    DDI_DMA_MAPPED) {
			audio_dev_warn(adev, "ch%d: dma bind failed", i);
			return (DDI_FAILURE);
		}
		port->paddr = c.dmac_address;

		port->engine = audio_engine_alloc(&cmpci_engine_ops, caps);
		if (port->engine == NULL) {
			audio_dev_warn(adev, "ch%d: alloc engine failed", i);
			return (DDI_FAILURE);
		}
		audio_engine_set_private(port->engine, port);
		audio_dev_add_engine(adev, port->engine);
	}

	cmpci_add_controls(dev);

	cmpci_reset(dev);
	cmpci_configure_mixer(dev);

	if (audio_dev_register(adev) != DDI_SUCCESS) {
		audio_dev_warn(adev, "audio_dev_register failed");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
cmpci_destroy(cmpci_dev_t *dev)
{
	mutex_destroy(&dev->mutex);

	/* free up ports, including DMA resources for ports */
	for (int i = 0; i < PORT_MAX; i++) {
		cmpci_port_t	*port = &dev->port[i];

		if (port->paddr != 0)
			(void) ddi_dma_unbind_handle(port->dmah);
		if (port->acch != NULL)
			ddi_dma_mem_free(&port->acch);
		if (port->dmah != NULL)
			ddi_dma_free_handle(&port->dmah);

		if (port->engine != NULL) {
			audio_dev_remove_engine(dev->adev, port->engine);
			audio_engine_free(port->engine);
		}
	}

	if (dev->acch != NULL) {
		ddi_regs_map_free(&dev->acch);
	}

	cmpci_del_controls(dev);

	if (dev->adev != NULL) {
		audio_dev_free(dev->adev);
	}

	kmem_free(dev, sizeof (*dev));
}

int
cmpci_attach(dev_info_t *dip)
{
	uint16_t		vendor, device;
	cmpci_dev_t		*dev;
	ddi_acc_handle_t	pcih;
	audio_dev_t		*adev;
	uint32_t		val;

	if (pci_config_setup(dip, &pcih) != DDI_SUCCESS) {
		audio_dev_warn(NULL, "pci_config_setup failed");
		return (DDI_FAILURE);
	}

	vendor = pci_config_get16(pcih, PCI_CONF_VENID);
	device = pci_config_get16(pcih, PCI_CONF_DEVID);

	if (vendor != CMEDIA_VENDOR_ID ||
	    ((device != CMEDIA_CM8738) && (device != CMEDIA_CM8338A) &&
	    (device != CMEDIA_CM8338B))) {
		pci_config_teardown(&pcih);
		audio_dev_warn(NULL, "device not recognized");
		return (DDI_FAILURE);
	}

	/* enable IO and Master accesses */
	pci_config_put16(pcih, PCI_CONF_COMM,
	    pci_config_get16(pcih, PCI_CONF_COMM) |
	    PCI_COMM_MAE | PCI_COMM_IO);

	pci_config_teardown(&pcih);

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->dip = dip;
	mutex_init(&dev->mutex, NULL, MUTEX_DRIVER, NULL);

	ddi_set_driver_private(dip, dev);

	if ((adev = audio_dev_alloc(dip, 0)) == NULL) {
		goto err_exit;
	}
	dev->adev = adev;

	if (ddi_regs_map_setup(dip, 1, &dev->regs, 0, 0, &acc_attr,
	    &dev->acch) != DDI_SUCCESS) {
		audio_dev_warn(adev, "can't map registers");
		goto err_exit;
	}

	/* setup some initial values */
	dev->maxch = 2;
	audio_dev_set_description(adev, "C-Media PCI Audio");
	switch (device) {
	case CMEDIA_CM8738:
		/*
		 * Crazy 8738 detection scheme.  Reviewing multiple
		 * different open sources gives multiple different
		 * answers here.  Its unclear how accurate this is.
		 * The approach taken here is a bit conservative in
		 * assigning multiple channel support, but for users
		 * with newer 8768 cards should offer the best
		 * capability.
		 */
		val = GET32(dev, REG_INTCTRL) & INTCTRL_MDL_MASK;
		if (val == 0) {

			if (GET32(dev, REG_CHFORMAT & CHFORMAT_VER_MASK)) {
				audio_dev_set_version(adev, "CMI-8738-037");
				dev->maxch = 4;
			} else {
				audio_dev_set_version(adev, "CMI-8738-033");
			}
		} else if ((val & INTCTRL_MDL_068) == INTCTRL_MDL_068) {
			audio_dev_set_version(adev, "CMI-8768");
			dev->maxch = 8;
			dev->softvol = B_TRUE;	/* No hardware PCM volume */
		} else if ((val & INTCTRL_MDL_055) == INTCTRL_MDL_055) {
			audio_dev_set_version(adev, "CMI-8738-055");
			dev->maxch = 6;
		} else if ((val & INTCTRL_MDL_039) == INTCTRL_MDL_039) {
			audio_dev_set_version(adev, "CMI-8738-039");
			dev->maxch = 4;
		} else {
			audio_dev_set_version(adev, "CMI-8738");
		}
		break;

	case CMEDIA_CM8338A:
		audio_dev_set_version(dev->adev, "CMI-8338");
		break;

	case CMEDIA_CM8338B:
		audio_dev_set_version(dev->adev, "CMI-8338B");
		break;
	}

	if (cmpci_init(dev) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "can't init device");
		goto err_exit;
	}

	return (DDI_SUCCESS);

err_exit:
	cmpci_destroy(dev);
	return (DDI_FAILURE);
}

static int
cmpci_resume(cmpci_dev_t *dev)
{
	mutex_enter(&dev->mutex);
	cmpci_reset(dev);
	/* wait one millisecond, to give reset a chance to get up */
	drv_usecwait(1000);
	mutex_exit(&dev->mutex);

	audio_dev_resume(dev->adev);

	return (DDI_SUCCESS);
}

static int
cmpci_detach(cmpci_dev_t *dev)
{
	if (audio_dev_unregister(dev->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	mutex_enter(&dev->mutex);

	/* disable channels */
	PUT32(dev, REG_FUNCTRL0, 0);

	mutex_exit(&dev->mutex);

	cmpci_destroy(dev);

	return (DDI_SUCCESS);
}

static int
cmpci_quiesce(dev_info_t *dip)
{
	cmpci_dev_t	*dev;

	if ((dev = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	/* disable channels */
	PUT32(dev, REG_FUNCTRL0, 0);

	return (DDI_SUCCESS);
}

static int
cmpci_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	cmpci_dev_t *dev;

	switch (cmd) {
	case DDI_ATTACH:
		return (cmpci_attach(dip));

	case DDI_RESUME:
		if ((dev = ddi_get_driver_private(dip)) == NULL) {
			return (DDI_FAILURE);
		}
		return (cmpci_resume(dev));

	default:
		return (DDI_FAILURE);
	}
}

static int
cmpci_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	cmpci_dev_t *dev;

	if ((dev = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		return (cmpci_detach(dev));

	case DDI_SUSPEND:
		audio_dev_suspend(dev->adev);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static struct dev_ops cmpci_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	cmpci_ddi_attach,	/* attach */
	cmpci_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	cmpci_quiesce,		/* quiesce */
};

static struct modldrv cmpci_modldrv = {
	&mod_driverops,			/* drv_modops */
	"C-Media PCI Audio",		/* linkinfo */
	&cmpci_dev_ops,			/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &cmpci_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&cmpci_dev_ops, "audiocmi");
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&cmpci_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;
	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&cmpci_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
