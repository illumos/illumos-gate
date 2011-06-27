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
 * Purpose: Definitions for the CMedia 8788 driver.
 */
/*
 * This file is part of Open Sound System
 *
 * Copyright (C) 4Front Technologies 1996-2011.
 *
 * This software is released under CDDL 1.0 source license.
 * See the COPYING file included in the main directory of this source
 * distribution for the license terms and conditions.
 */
#ifndef	CMEDIAHD_H
#define	CMEDIAHD_H

#define	CMEDIAHD_NAME		"audiocmihd"

#define	CMEDIAHD_NUM_PORTC		2
#define	CMEDIAHD_PLAY			0
#define	CMEDIAHD_REC			1

/*
 * Number of fragments must be multiple of 2 because the
 * hardware supports only full and half buffer interrupts. In
 * addition it looks like 8 fragments is the minimum.
 */
#define	CMEDIAHD_BUF_LEN		(65536)

#define	PCI_VENDOR_ID_CMEDIA 		0x13F6
#define	PCI_DEVICE_ID_CMEDIAHD		0x8788

#define	CMEDIAHD_MAX_INTRS		512
#define	CMEDIAHD_MIN_INTRS		48
#define	CMEDIAHD_INTRS			100

/*
 * PCI registers
 */

#define	RECA_ADDR		(devc->base+0x00)
#define	RECA_SIZE		(devc->base+0x04)
#define	RECA_FRAG		(devc->base+0x06)
#define	RECB_ADDR		(devc->base+0x08)
#define	RECB_SIZE		(devc->base+0x0C)
#define	RECB_FRAG		(devc->base+0x0E)
#define	RECC_ADDR		(devc->base+0x10)
#define	RECC_SIZE		(devc->base+0x14)
#define	RECC_FRAG		(devc->base+0x16)
#define	SPDIF_ADDR		(devc->base+0x18)
#define	SPDIF_SIZE		(devc->base+0x1C)
#define	SPDIF_FRAG		(devc->base+0x1E)
#define	MULTICH_ADDR		(devc->base+0x20)
#define	MULTICH_SIZE		(devc->base+0x24)
#define	MULTICH_FRAG		(devc->base+0x28)
#define	FPOUT_ADDR		(devc->base+0x30)
#define	FPOUT_SIZE		(devc->base+0x34)
#define	FPOUT_FRAG		(devc->base+0x36)

#define	DMA_START		(devc->base+0x40)
#define	CHAN_RESET		(devc->base+0x42)
#define	MULTICH_MODE		(devc->base+0x43)
#define	IRQ_MASK		(devc->base+0x44)
#define	IRQ_STAT		(devc->base+0x46)
#define	MISC_REG		(devc->base+0x48)
#define	REC_FORMAT		(devc->base+0x4A)
#define	PLAY_FORMAT		(devc->base+0x4B)
#define	REC_MODE		(devc->base+0x4C)
#define	FUNCTION		(devc->base+0x50)

#define	I2S_MULTICH_DAC		(devc->base+0x60)
#define	I2S_ADC1		(devc->base+0x62)
#define	I2S_ADC2		(devc->base+0x64)
#define	I2S_ADC3		(devc->base+0x66)

#define	SPDIF_FUNC		(devc->base+0x70)
#define	SPDIFOUT_CHAN_STAT	(devc->base+0x74)
#define	SPDIFIN_CHAN_STAT	(devc->base+0x78)

#define	TWO_WIRE_ADDR		(devc->base+0x90)
#define	TWO_WIRE_MAP		(devc->base+0x91)
#define	TWO_WIRE_DATA		(devc->base+0x92)
#define	TWO_WIRE_CTRL		(devc->base+0x94)

#define	SPI_CONTROL		(devc->base+0x98)
#define	SPI_DATA		(devc->base+0x99)

#define	MPU401_DATA		(devc->base+0xA0)
#define	MPU401_COMMAND		(devc->base+0xA1)
#define	MPU401_CONTROL		(devc->base+0xA2)

#define	GPI_DATA		(devc->base+0xA4)
#define	GPI_IRQ_MASK		(devc->base+0xA5)
#define	GPIO_DATA		(devc->base+0xA6)
#define	GPIO_CONTROL		(devc->base+0xA8)
#define	GPIO_IRQ_MASK		(devc->base+0xAA)
#define	DEVICE_SENSE		(devc->base+0xAC)

#define	PLAY_ROUTING		(devc->base+0xC0)
#define	REC_ROUTING		(devc->base+0xC2)
#define	REC_MONITOR		(devc->base+0xC3)
#define	MONITOR_ROUTING		(devc->base+0xC4)

#define	AC97_CTRL		(devc->base+0xD0)
#define	AC97_INTR_MASK		(devc->base+0xD2)
#define	AC97_INTR_STAT		(devc->base+0xD3)
#define	AC97_OUT_CHAN_CONFIG	(devc->base+0xD4)
#define	AC97_IN_CHAN_CONFIG	(devc->base+0xD8)
#define	AC97_CMD_DATA		(devc->base+0xDC)

#define	CODEC_VERSION		(devc->base+0xE4)
#define	CTRL_VERSION		(devc->base+0xE6)

/* Device IDs */
#define	ASUS_VENDOR_ID		0x1043
#define	SUBID_XONAR_D2		0x8269
#define	SUBID_XONAR_D2X		0x82b7
#define	SUBID_XONAR_D1		0x834f
#define	SUBID_XONAR_DX		0x8275
#define	SUBID_XONAR_STX		0x835c
#define	SUBID_XONAR_DS		0x838e


#define	SUBID_GENERIC		0x0000

/* Xonar specific */
#define	XONAR_DX_FRONTDAC	0x9e
#define	XONAR_DX_SURRDAC	0x30
#define	XONAR_STX_FRONTDAC	0x98
#define	XONAR_DS_FRONTDAC	0x1
#define	XONAR_DS_SURRDAC	0x0

/* defs for AKM 4396 DAC */
#define	AK4396_CTL1		0x00
#define	AK4396_CTL2		0x01
#define	AK4396_CTL3		0x02
#define	AK4396_LchATTCtl	0x03
#define	AK4396_RchATTCtl	0x04

/* defs for CS4398 DAC */
#define	CS4398_CHIP_ID		0x01
#define	CS4398_MODE_CTRL	0x02
#define	CS4398_MIXING		0x03
#define	CS4398_MUTE_CTRL	0x04
#define	CS4398_VOLA		0x05
#define	CS4398_VOLB		0x06
#define	CS4398_RAMP_CTRL	0x07
#define	CS4398_MISC_CTRL	0x08
#define	CS4398_MISC2_CTRL	0x09
#define	CS4398_POWER_DOWN	(1<<7)	/* Obvious */
#define	CS4398_CPEN		(1<<6)  /* Control Port Enable */
#define	CS4398_FREEZE		(1<<5)	/* Freezes registers, unfreeze to */
					/* accept changed registers */
#define	CS4398_MCLKDIV2		(1<<4)	/* Divide MCLK by 2 */
#define	CS4398_MCLKDIV3		(1<<3)	/* Divive MCLK by 3 */
#define	CS4398_I2S		(1<<4)	/* Set I2S mode */

/* defs for CS4362A DAC */
#define	CS4362A_MODE1_CTRL	0x01
#define	CS4362A_MODE2_CTRL	0x02
#define	CS4362A_MODE3_CTRL	0x03
#define	CS4362A_FILTER_CTRL	0x04
#define	CS4362A_INVERT_CTRL	0x05
#define	CS4362A_MIX1_CTRL	0x06
#define	CS4362A_VOLA_1		0x07
#define	CS4362A_VOLB_1		0x08
#define	CS4362A_MIX2_CTRL	0x09
#define	CS4362A_VOLA_2		0x0A
#define	CS4362A_VOLB_2		0x0B
#define	CS4362A_MIX3_CTRL	0x0C
#define	CS4362A_VOLA_3		0x0D
#define	CS4362A_VOLB_3		0x0E
#define	CS4362A_CHIP_REV	0x12

/* CS4362A Reg 01h */
#define	CS4362A_CPEN		(1<<7)
#define	CS4362A_FREEZE		(1<<6)
#define	CS4362A_MCLKDIV		(1<<5)
#define	CS4362A_DAC3_ENABLE	(1<<3)
#define	CS4362A_DAC2_ENABLE	(1<<2)
#define	CS4362A_DAC1_ENABLE	(1<<1)
#define	CS4362A_POWER_DOWN	(1)

/* CS4362A Reg 02h */
#define	CS4362A_DIF_LJUST	0x00
#define	CS4362A_DIF_I2S		0x10
#define	CS4362A_DIF_RJUST16	0x20
#define	CS4362A_DIF_RJUST24	0x30
#define	CS4362A_DIF_RJUST20	0x40
#define	CS4362A_DIF_RJUST18	0x50

/* CS4362A Reg 03h */
#define	CS4362A_RAMP_IMMEDIATE	0x00
#define	CS4362A_RAMP_ZEROCROSS	0x40
#define	CS4362A_RAMP_SOFT	0x80
#define	CS4362A_RAMP_SOFTZERO	0xC0
#define	CS4362A_SINGLE_VOL	0x20
#define	CS4362A_RAMP_ERROR	0x10
#define	CS4362A_MUTEC_POL	0x08
#define	CS4362A_AUTOMUTE	0x04
#define	CS4362A_SIX_MUTE	0x00
#define	CS4362A_ONE_MUTE	0x01
#define	CS4362A_THREE_MUTE	0x03

/* CS4362A Reg 04h */
#define	CS4362A_FILT_SEL	0x10
#define	CS4362A_DEM_NONE	0x00
#define	CS4362A_DEM_44KHZ	0x02
#define	CS4362A_DEM_48KHZ	0x04
#define	CS4362A_DEM_32KHZ	0x06
#define	CS4362A_RAMPDOWN	0x01


/* CS4362A Reg 05h */
#define	CS4362A_INV_A3		(1<<4)
#define	CS4362A_INV_B3		(1<<5)
#define	CS4362A_INV_A2		(1<<2)
#define	CS4362A_INV_B2		(1<<3)
#define	CS4362A_INV_A1		(1)
#define	CS4362A_INV_B1		(1<<1)

/* CS4362A Reg 06h, 09h, 0Ch */
/* ATAPI crap, does anyone still use analog CD playback? */

/* CS4362A Reg 07h, 08h, 0Ah, 0Bh, 0Dh, 0Eh */
/* Volume registers */
#define	CS4362A_VOL_MUTE	0x80

/* 0-100. Start at -96dB. */
#define	CS4398_VOL(x) \
	((x) == 0 ? 0xFF : (0xC0 - ((x)*192/100)))
/* 0-100. Start at -96dB. Bit 7 is mute. */
#define	CS4362A_VOL(x) \
	(char)((x) == 0 ? 0xFF : (0x60 - ((x)*96/100)))

/* Xonar D2/D2X codec remap */
static const char xd2_codec_map[4] = {
	0, 1, 2, 4
};


typedef struct _cmediahd_devc_t cmediahd_devc_t;
typedef struct _cmediahd_portc_t cmediahd_portc_t;

typedef enum {
	CTL_VOLUME = 0,
	CTL_FRONT,
	CTL_REAR,
	CTL_CENTER,
	CTL_LFE,
	CTL_SURROUND,
	CTL_MONITOR,
	CTL_RECSRC,
	CTL_RECGAIN,
	CTL_MICVOL,
	CTL_AUXVOL,
	CTL_CDVOL,
	CTL_LOOP,
	CTL_SPREAD,
	CTL_NUM		/* must be last */
} cmediahd_ctrl_num_t;

typedef struct cmediahd_ctrl
{
	cmediahd_devc_t		*devc;
	audio_ctrl_t		*ctrl;
	cmediahd_ctrl_num_t	num;
	uint64_t		val;
} cmediahd_ctrl_t;

typedef struct cmediahd_regs
{
	caddr_t addr;	/* base address */
	caddr_t size;	/* current count */
	caddr_t frag;	/* terminal count */
	caddr_t i2s;    /* i2s reg */
	int chan; 	/* rec a/b/c, play spdif/multi/front */
#define	REC_A 0
#define	REC_B 1
#define	REC_C 2
#define	PLAY_SPDIF 3
#define	PLAY_MULTI 4
#define	PLAY_FRONT 5
} cmediahd_regs_t;

struct _cmediahd_portc_t
{
	cmediahd_devc_t *devc;
	audio_engine_t *engine;

	int			chans;
	int			direction;

	ddi_dma_handle_t	buf_dmah;	/* dma for buffers */
	ddi_acc_handle_t	buf_acch;
	uint32_t		paddr;
	caddr_t			kaddr;
	size_t			buf_size;
	size_t			buf_frames;	/* Buffer size in frames */
	unsigned		fragfr;
	unsigned		nfrags;
	unsigned		nframes;
	unsigned		bufsz;
	size_t			offset;
	uint64_t		count;
	int			syncdir;
};

struct _cmediahd_devc_t
{
	dev_info_t		*dip;
	audio_dev_t		*adev;
	boolean_t		has_ac97, has_fp_ac97;
	int			model;
	ac97_t			*ac97, *fp_ac97;

	boolean_t		suspended;
	ddi_acc_handle_t	pcih;
	ddi_acc_handle_t	regsh;
	caddr_t			base;
	kmutex_t		mutex;		/* For normal locking */
	kmutex_t		low_mutex;	/* For low level routines */
	cmediahd_regs_t		rec_eng;	/* which rec engine to use */
	cmediahd_portc_t 	*portc[CMEDIAHD_NUM_PORTC];
	int			gpio_mic, gpio_out, gpio_codec, gpio_alt;
	cmediahd_ctrl_t		controls[CTL_NUM];
};

#define	INB(devc, reg)		ddi_get8(devc->regsh, (void *)(reg))
#define	OUTB(devc, val, reg)	ddi_put8(devc->regsh, (void *)(reg), (val))

#define	INW(devc, reg)		ddi_get16(devc->regsh, (void *)(reg))
#define	OUTW(devc, val, reg)	ddi_put16(devc->regsh, (void *)(reg), (val))

#define	INL(devc, reg)		ddi_get32(devc->regsh, (void *)(reg))
#define	OUTL(devc, val, reg)	ddi_put32(devc->regsh, (void *)(reg), (val))

#endif /* CMEDIAHD_H */
