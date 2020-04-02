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
 * Purpose: Driver for the CMedia 8788 sound card
 */
/*
 *
 * Copyright (C) 4Front Technologies 1996-2011.
 *
 * This software is released under CDDL 1.0 source license.
 * See the COPYING file included in the main directory of this source
 * distribution for the license terms and conditions.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include <sys/note.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>

#include "audiocmihd.h"

static struct ddi_device_acc_attr dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static struct ddi_device_acc_attr buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t dma_attr_buf = {
	DMA_ATTR_V0,		/* version number */
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


static int cmediahd_attach(dev_info_t *);
static int cmediahd_resume(dev_info_t *);
static int cmediahd_detach(cmediahd_devc_t *);
static int cmediahd_suspend(cmediahd_devc_t *);

static int cmediahd_open(void *, int, unsigned *, caddr_t *);
static void cmediahd_close(void *);
static int cmediahd_start(void *);
static void cmediahd_stop(void *);
static int cmediahd_format(void *);
static int cmediahd_channels(void *);
static int cmediahd_rate(void *);
static uint64_t cmediahd_count(void *);
static void cmediahd_sync(void *, unsigned);
static void cmediahd_chinfo(void *, int, unsigned *, unsigned *);


static uint16_t cmediahd_read_ac97(void *, uint8_t);
static void cmediahd_write_ac97(void *, uint8_t, uint16_t);
static int cmediahd_alloc_port(cmediahd_devc_t *, int);
static void cmediahd_reset_port(cmediahd_portc_t *);
static void cmediahd_destroy(cmediahd_devc_t *);
static void cmediahd_hwinit(cmediahd_devc_t *);
static void cmediahd_refresh_mixer(cmediahd_devc_t *devc);
static uint32_t mix_scale(uint32_t, int8_t);
static void cmediahd_ac97_hwinit(cmediahd_devc_t *);
static void cmediahd_del_controls(cmediahd_devc_t *);


static audio_engine_ops_t cmediahd_engine_ops = {
	AUDIO_ENGINE_VERSION,
	cmediahd_open,
	cmediahd_close,
	cmediahd_start,
	cmediahd_stop,
	cmediahd_count,
	cmediahd_format,
	cmediahd_channels,
	cmediahd_rate,
	cmediahd_sync,
	NULL,	/* qlen */
	cmediahd_chinfo,
	NULL	/* playahead */
};

#define	PLAYCTL (AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_PLAY)
#define	RECCTL  (AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_REC)
#define	MONCTL  (AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_MONITOR)
#define	PCMVOL  (PLAYCTL | AUDIO_CTRL_FLAG_PCMVOL)
#define	MAINVOL (PLAYCTL | AUDIO_CTRL_FLAG_MAINVOL)
#define	RECVOL  (RECCTL | AUDIO_CTRL_FLAG_RECVOL)

static const char mix_cvt[101] = {
	0, 0, 3, 7, 10, 13, 16, 19,
	21, 23, 26, 28, 30, 32, 34, 35,
	37, 39, 40, 42,	43, 45, 46, 47,
	49, 50, 51, 52, 53, 55, 56, 57,
	58, 59, 60, 61, 62, 63, 64, 65,
	65, 66, 67, 68, 69, 70, 70, 71,
	72, 73, 73, 74, 75, 75, 76, 77,
	77, 78, 79, 79, 80, 81, 81, 82,
	82, 83, 84, 84, 85, 85, 86, 86,
	87, 87, 88, 88, 89, 89, 90, 90,
	91, 91, 92, 92, 93, 93, 94, 94,
	95, 95, 96, 96, 96, 97, 97, 98,
	98, 98, 99, 99, 100
};

static uint32_t
mix_scale(uint32_t vol, int8_t bits)
{
	vol = mix_cvt[vol];
	vol = (vol * ((1 << bits) - 1)) / 100;
	return (vol);
}

static uint16_t
cmediahd_read_ac97(void *arg, uint8_t reg)
{
	cmediahd_devc_t *devc = arg;
	uint32_t val;
	uint16_t data;

	mutex_enter(&devc->low_mutex);
	val = 0L;
	val |= reg << 16;
	val |= 0 << 24;			/* codec 0 or codec 1 */
	val |= 1 << 23;			/* ac97 read the reg address */
	OUTL(devc, val, AC97_CMD_DATA);
	drv_usecwait(100);
	data = INL(devc, AC97_CMD_DATA) & 0xFFFF;
	mutex_exit(&devc->low_mutex);
	return (data);
}

static void
cmediahd_write_ac97(void *arg, uint8_t reg, uint16_t data)
{
	cmediahd_devc_t *devc = arg;
	uint32_t val;

	mutex_enter(&devc->low_mutex);
	val = 0L;
	val |= reg << 16;
	val |= data & 0xFFFF;
	val |= 0 << 24;			/* on board codec or frontpanel */
	val |= 0 << 23;			/* ac97 write operation */
	OUTL(devc, val, AC97_CMD_DATA);
	drv_usecwait(100);
	mutex_exit(&devc->low_mutex);
}

#if 0	/* Front Panel AC'97 not supported yet */
static uint16_t
cmediahd_read_fp_ac97(void *arg, uint8_t reg)
{
	cmediahd_devc_t *devc = arg;
	uint32_t val;
	uint16_t data;

	mutex_enter(&devc->low_mutex);
	val = 0L;
	val |= 1 << 24;			/* front panel */
	val |= 1 << 23;			/* ac97 read the reg address */
	val |= reg << 16;
	OUTL(devc, val, AC97_CMD_DATA);
	drv_usecwait(100);
	data = INL(devc, AC97_CMD_DATA) & 0xFFFF;
	mutex_exit(&devc->low_mutex);

	return (data);
}

static void
cmediahd_write_fp_ac97(void *arg, uint8_t reg, uint16_t data)
{
	cmediahd_devc_t *devc = arg;
	uint32_t val;

	mutex_enter(&devc->low_mutex);
	val = 0L;
	val |= 1 << 24;			/* frontpanel */
	val |= 0 << 23;			/* ac97 write operation */
	val |= reg << 16;
	val |= data & 0xFFFF;
	OUTL(devc, val, AC97_CMD_DATA);
	drv_usecwait(100);
	mutex_exit(&devc->low_mutex);
}
#endif

static void
spi_write(void *arg, int codec_num, unsigned char reg, int val)
{
	cmediahd_devc_t *devc = arg;
	unsigned int tmp;
	int latch, shift, count;

	mutex_enter(&devc->low_mutex);

	/* check if SPI is busy */
	count = 10;
	while ((INB(devc, SPI_CONTROL) & 0x1) && count-- > 0) {
		drv_usecwait(10);
	}

	if (devc->model == SUBID_XONAR_DS) {
		shift = 9;
		latch = 0;
	} else {
		shift = 8;
		latch = 0x80;
	}

	/* 2 byte data/reg info to be written */
	tmp = val;
	tmp |= (reg << shift);

	/* write 2-byte data values */
	OUTB(devc, tmp & 0xff, SPI_DATA + 0);
	OUTB(devc, (tmp >> 8) & 0xff, SPI_DATA + 1);

	/* Latch high, clock=160, Len=2byte, mode=write */
	tmp = (INB(devc, SPI_CONTROL) & ~0x7E) | latch | 0x1;

	/* now address which codec you want to send the data to */
	tmp |= (codec_num << 4);

	/* send the command to write the data */
	OUTB(devc, tmp, SPI_CONTROL);

	mutex_exit(&devc->low_mutex);
}

static void
i2c_write(void *arg, unsigned char codec_num, unsigned char reg,
    unsigned char data)
{
	cmediahd_devc_t *devc = arg;
	int count = 50;

	/* Wait for it to stop being busy */
	mutex_enter(&devc->low_mutex);
	while ((INW(devc, TWO_WIRE_CTRL) & 0x1) && (count > 0)) {
		drv_usecwait(10);
		count--;
	}

	if (count == 0) {
		audio_dev_warn(devc->adev, "Time out on Two-Wire interface");
		mutex_exit(&devc->low_mutex);
		return;
	}

	/* first write the Register Address into the MAP register */
	OUTB(devc, reg, TWO_WIRE_MAP);

	/* now write the data */
	OUTB(devc, data, TWO_WIRE_DATA);

	/* select the codec number to address */
	OUTB(devc, codec_num, TWO_WIRE_ADDR);

	mutex_exit(&devc->low_mutex);
}

static void
cs4398_init(void *arg, int codec)
{
	cmediahd_devc_t *devc = arg;

	/* Fast Two-Wire. Reduces the wire ready time. */
	OUTW(devc, 0x0100, TWO_WIRE_CTRL);

	/* Power down, enable control mode. */
	i2c_write(devc, codec, CS4398_MISC_CTRL,
	    CS4398_CPEN | CS4398_POWER_DOWN);
	/*
	 * Left justified PCM (DAC and 8788 support I2S, but doesn't work.
	 * Setting it introduces clipping like hell).
	 */
	i2c_write(devc, codec, CS4398_MODE_CTRL, 0x00);
	i2c_write(devc, codec, 3, 0x09);
	i2c_write(devc, codec, 4, 0x82);	/* PCM Automute */
	i2c_write(devc, codec, 5, 0x80);	/* Vol A+B to -64dB */
	i2c_write(devc, codec, 6, 0x80);
	i2c_write(devc, codec, 7, 0xf0);	/* soft ramping on */

	/* remove the powerdown flag */
	i2c_write(devc, codec, CS4398_MISC_CTRL, CS4398_CPEN);
}


static void
cs4362a_init(void *arg, int codec)
{

	cmediahd_devc_t *devc = arg;

	OUTW(devc, 0x0100, TWO_WIRE_CTRL);

	/* Power down and enable control port. */
	i2c_write(devc, codec, CS4362A_MODE1_CTRL,
	    CS4362A_CPEN | CS4362A_POWER_DOWN);
	/* Left-justified PCM */
	i2c_write(devc, codec, CS4362A_MODE2_CTRL, CS4362A_DIF_LJUST);
	/* Ramp & Automute, re-set DAC defaults. */
	i2c_write(devc, codec, CS4362A_MODE3_CTRL, 0x84);
	/* Filter control, DAC defs. */
	i2c_write(devc, codec, CS4362A_FILTER_CTRL, 0);
	/* Invert control, DAC defs. */
	i2c_write(devc, codec, CS4362A_INVERT_CTRL, 0);
	/* Mixing control, DAC defs. */
	i2c_write(devc, codec, CS4362A_MIX1_CTRL, 0x24);
	i2c_write(devc, codec, CS4362A_MIX2_CTRL, 0x24);
	i2c_write(devc, codec, CS4362A_MIX3_CTRL, 0x24);
	/* Volume to -64dB. */
	i2c_write(devc, codec, CS4362A_VOLA_1, 0x40);
	i2c_write(devc, codec, CS4362A_VOLB_1, 0x40);
	i2c_write(devc, codec, CS4362A_VOLA_2, 0x40);
	i2c_write(devc, codec, CS4362A_VOLB_2, 0x40);
	i2c_write(devc, codec, CS4362A_VOLA_3, 0x40);
	i2c_write(devc, codec, CS4362A_VOLB_3, 0x40);
	/* Power up. */
	i2c_write(devc, codec, CS4362A_MODE1_CTRL, CS4362A_CPEN);
}


static void
cmediahd_generic_set_play_volume(cmediahd_devc_t *devc, int codec_id,
    int left, int right)
{
	spi_write(devc, codec_id, AK4396_LchATTCtl | 0x20, mix_scale(left, 8));
	spi_write(devc, codec_id, AK4396_RchATTCtl | 0x20, mix_scale(right, 8));
}

static void
xonar_d1_set_play_volume(cmediahd_devc_t *devc, int codec_id,
    int left, int right)
{
	switch (codec_id) {
	case 0:
		i2c_write(devc, XONAR_DX_FRONTDAC, CS4398_VOLA,
		    CS4398_VOL(left));
		i2c_write(devc, XONAR_DX_FRONTDAC, CS4398_VOLB,
		    CS4398_VOL(right));
		break;
	case 1:
		i2c_write(devc, XONAR_DX_SURRDAC, CS4362A_VOLA_1,
		    CS4362A_VOL(left));
		i2c_write(devc, XONAR_DX_SURRDAC, CS4362A_VOLB_1,
		    CS4362A_VOL(right));
		break;
	case 2:
		i2c_write(devc, XONAR_DX_SURRDAC, CS4362A_VOLA_2,
		    CS4362A_VOL(left));
		i2c_write(devc, XONAR_DX_SURRDAC, CS4362A_VOLB_2,
		    CS4362A_VOL(right));
		break;
	case 3:
		i2c_write(devc, XONAR_DX_SURRDAC, CS4362A_VOLA_3,
		    CS4362A_VOL(left));
		i2c_write(devc, XONAR_DX_SURRDAC, CS4362A_VOLB_3,
		    CS4362A_VOL(right));
		break;
	}
}

static void
xonar_d2_set_play_volume(cmediahd_devc_t *devc, int codec_id,
    int left, int right)
{
	spi_write(devc, xd2_codec_map[codec_id], 16, mix_scale(left, 8));
	spi_write(devc, xd2_codec_map[codec_id], 17, mix_scale(right, 8));
}

static void
xonar_stx_set_play_volume(cmediahd_devc_t *devc, int codec_id,
    int left, int right)
{
	if (codec_id == 0) {
		i2c_write(devc, XONAR_STX_FRONTDAC, 16, mix_scale(left, 8));
		i2c_write(devc, XONAR_STX_FRONTDAC, 17, mix_scale(right, 8));
	}
}

static void
xonar_ds_set_play_volume(cmediahd_devc_t *devc, int codec_id,
    int left, int right)
{
	switch (codec_id) {
	case 0:		/* front */
		spi_write(devc, XONAR_DS_FRONTDAC, 0,
		    mix_scale(left, 7) | 0x180);
		spi_write(devc, XONAR_DS_FRONTDAC, 1,
		    mix_scale(right, 7) | 0x180);
		spi_write(devc, XONAR_DS_FRONTDAC, 3,
		    mix_scale(left, 7) |0x180);
		spi_write(devc, XONAR_DS_FRONTDAC, 4,
		    mix_scale(right, 7) | 0x180);
		break;

	case 1:		/* side */
		spi_write(devc, XONAR_DS_SURRDAC, 0,
		    mix_scale(left, 7) | 0x180);
		spi_write(devc, XONAR_DS_SURRDAC, 1,
		    mix_scale(right, 7) | 0x180);
		break;
	case 2:		/* rear */
		spi_write(devc, XONAR_DS_SURRDAC, 4,
		    mix_scale(left, 7) | 0x180);
		spi_write(devc, XONAR_DS_SURRDAC, 5,
		    mix_scale(right, 7) | 0x180);
		break;
	case 3:		/* center */
		spi_write(devc, XONAR_DS_SURRDAC, 6,
		    mix_scale(left, 7) | 0x180);
		spi_write(devc, XONAR_DS_SURRDAC, 7,
		    mix_scale(right, 7) | 0x180);
		break;
	}
}

static void
cmediahd_set_rec_volume(cmediahd_devc_t *devc, int value)
{
	unsigned char left, right;

	left = (value >> 8) & 0xff;
	right = value & 0xff;

	if (left > 100)
		left = 100;
	if (right > 100)
		right = 100;

	spi_write(devc, XONAR_DS_FRONTDAC, 0xe, mix_scale(left, 8));
	spi_write(devc, XONAR_DS_FRONTDAC, 0xf, mix_scale(right, 8));
}

static void
cmediahd_set_play_volume(cmediahd_devc_t *devc, int codec_id, int value)
{
	int left, right;

	left = (value >> 8) & 0xFF;
	right = (value & 0xFF);

	if (left > 100)
		left = 100;
	if (right > 100)
		right = 100;

	switch (devc->model) {
	case SUBID_XONAR_D1:
	case SUBID_XONAR_DX:
		xonar_d1_set_play_volume(devc, codec_id, left, right);
		break;
	case SUBID_XONAR_D2:
	case SUBID_XONAR_D2X:
		xonar_d2_set_play_volume(devc, codec_id, left, right);
		break;
	case SUBID_XONAR_STX:
		xonar_stx_set_play_volume(devc, codec_id, left, right);
		break;
	case SUBID_XONAR_DS:
		xonar_ds_set_play_volume(devc, codec_id, left, right);
		break;
	default:
		cmediahd_generic_set_play_volume(devc, codec_id, left, right);
		break;
	}
}

/*
 * Audio routines
 */

int
cmediahd_open(void *arg, int flag, unsigned *nframesp, caddr_t *bufp)
{
	cmediahd_portc_t *portc = arg;

        _NOTE(ARGUNUSED(flag));

	portc->count = 0;

	*nframesp = portc->nframes;
	*bufp = portc->kaddr;

	return (0);
}

void
cmediahd_close(void *arg)
{
        _NOTE(ARGUNUSED(arg));
}

int
cmediahd_start(void *arg)
{
	cmediahd_portc_t	*portc = arg;
	cmediahd_devc_t		*devc = portc->devc;

	mutex_enter(&devc->mutex);
	portc->offset = 0;

	cmediahd_reset_port(portc);

	switch (portc->direction) {
	case CMEDIAHD_PLAY:
		/* enable the dma */
		OUTW(devc, INW(devc, DMA_START) | 0x10, DMA_START);
		break;

	case CMEDIAHD_REC:
		/* enable the channel */
		OUTW(devc, INW(devc, DMA_START) | (1<<devc->rec_eng.chan),
		    DMA_START);
		break;
	}

	mutex_exit(&devc->mutex);
	return (0);
}

void
cmediahd_stop(void *arg)
{
	cmediahd_portc_t	*portc = arg;
	cmediahd_devc_t		*devc = portc->devc;

	mutex_enter(&devc->mutex);
	switch (portc->direction) {
	case CMEDIAHD_PLAY:
		/* disable dma */
		OUTW(devc, INW(devc, DMA_START) & ~0x10, DMA_START);
		break;

	case CMEDIAHD_REC:
		/* disable dma */
		OUTW(devc, INW(devc, DMA_START) & ~(1<<devc->rec_eng.chan),
		    DMA_START);
		break;
	}
	mutex_exit(&devc->mutex);
}

int
cmediahd_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

int
cmediahd_channels(void *arg)
{
	cmediahd_portc_t	*portc = arg;

	return (portc->chans);
}

int
cmediahd_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}

void
cmediahd_sync(void *arg, unsigned nframes)
{
	cmediahd_portc_t *portc = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(portc->buf_dmah, 0, 0, portc->syncdir);
}

static void
cmediahd_chinfo(void *arg, int chan, unsigned *offset, unsigned *incr)
{
	cmediahd_portc_t *portc = arg;
	static const int map8ch[] = { 0, 1, 4, 5, 2, 3, 6, 7 };
	static const int map4ch[] = { 0, 1, 2, 3 };

	if (portc->chans <= 4) {
		*offset = map4ch[chan];
	} else {
		*offset = map8ch[chan];
	}
	*incr = portc->chans;
}

uint64_t
cmediahd_count(void *arg)
{
	cmediahd_portc_t	*portc = arg;
	cmediahd_devc_t	*devc = portc->devc;
	uint64_t	count;
	uint32_t	offset;

	mutex_enter(&devc->mutex);

	if (portc->direction == CMEDIAHD_PLAY)
		offset = portc->bufsz/4 - INL(devc, MULTICH_SIZE) + 1;
	else
		offset = portc->bufsz/4 - INW(devc, devc->rec_eng.size) + 1;

	/* check for wrap */
	if (offset < portc->offset) {
		count = ((portc->bufsz/4) - portc->offset) + offset;
	} else {
		count = offset - portc->offset;
	}
	portc->count += count;
	portc->offset = offset;

	/* convert from 16-bit stereo */
	count = portc->count / (portc->chans/2);
	mutex_exit(&devc->mutex);

	return (count);
}

/* private implementation bits */


void
cmediahd_reset_port(cmediahd_portc_t *portc)
{
	cmediahd_devc_t *devc = portc->devc;
	int channels;

	if (devc->suspended)
		return;

	portc->offset = 0;

	switch (portc->direction) {

	case CMEDIAHD_PLAY:
		/* reset channel */
		OUTB(devc, INB(devc, CHAN_RESET)|0x10, CHAN_RESET);
		drv_usecwait(10);
		OUTB(devc, INB(devc, CHAN_RESET) & ~0x10, CHAN_RESET);
		drv_usecwait(10);

		OUTL(devc, portc->paddr,  MULTICH_ADDR);
		OUTL(devc, (portc->bufsz/4) - 1, MULTICH_SIZE);
		OUTL(devc, (portc->bufsz/4) - 1, MULTICH_FRAG);

		switch (portc->chans) {
		case 2:
			channels = 0;
			break;
		case 4:
			channels = 1;
			break;
		case 6:
			channels = 2;
			break;
		case 8:
			channels = 3;
			break;
		default:
			channels = 0x0;
			break;
		}
		OUTB(devc, (INB(devc, MULTICH_MODE) & ~0x3) | channels,
		    MULTICH_MODE);

		/* set the format bits in play format register */
		OUTB(devc, (INB(devc, PLAY_FORMAT) & ~0xC) | 0x0, PLAY_FORMAT);
		break;

	case CMEDIAHD_REC:
		OUTB(devc, INB(devc, CHAN_RESET) | (1 << devc->rec_eng.chan),
		    CHAN_RESET);
		drv_usecwait(10);
		OUTB(devc, INB(devc, CHAN_RESET) & ~(1 << devc->rec_eng.chan),
		    CHAN_RESET);
		drv_usecwait(10);

		OUTL(devc, portc->paddr,  devc->rec_eng.addr);
		OUTW(devc, (portc->bufsz/4) - 1, devc->rec_eng.size);
		OUTW(devc, (portc->bufsz/4) - 1, devc->rec_eng.frag);


		switch (portc->chans) {
		case 2:
			channels = 0x0;
			break;
		case 4:
			channels = 0x1;
			break;
		case 6:
			channels = 0x2;
			break;
		case 8:
			channels = 0x4;
			break;
		default:
			/* Stereo - boomer only supports stereo */
			channels = 0x0;
			break;
		}

		OUTB(devc, (INB(devc, REC_MODE) & ~0x3) | channels, REC_MODE);
		OUTB(devc, (INB(devc, REC_FORMAT) & ~0x3) | 0x0, REC_FORMAT);

	}
}

int
cmediahd_alloc_port(cmediahd_devc_t *devc, int num)
{
	cmediahd_portc_t	*portc;
	size_t			len;
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			dir;
	unsigned		caps;
	audio_dev_t		*adev;

	adev = devc->adev;
	portc = kmem_zalloc(sizeof (*portc), KM_SLEEP);
	devc->portc[num] = portc;
	portc->devc = devc;
	portc->direction = num;

	switch (num) {
	case CMEDIAHD_REC:
		portc->syncdir = DDI_DMA_SYNC_FORKERNEL;
		portc->chans = 2;
		caps = ENGINE_INPUT_CAP;
		dir = DDI_DMA_READ;
		break;
	case CMEDIAHD_PLAY:
		portc->syncdir = DDI_DMA_SYNC_FORDEV;
		portc->chans = 8;
		caps = ENGINE_OUTPUT_CAP;
		dir = DDI_DMA_WRITE;
		break;
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Calculate buffer size and frames
	 */
	portc->nframes = 2048;
	portc->bufsz = portc->nframes * portc->chans * 2;

	/* Alloc buffers */
	if (ddi_dma_alloc_handle(devc->dip, &dma_attr_buf, DDI_DMA_SLEEP, NULL,
	    &portc->buf_dmah) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate BUF handle");
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(portc->buf_dmah, CMEDIAHD_BUF_LEN,
	    &buf_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &portc->kaddr, &len, &portc->buf_acch) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate BUF memory");
		return (DDI_FAILURE);
	}

	bzero(portc->kaddr, len);

	if (ddi_dma_addr_bind_handle(portc->buf_dmah, NULL, portc->kaddr,
	    len, DDI_DMA_CONSISTENT | dir, DDI_DMA_SLEEP, NULL, &cookie,
	    &count) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed binding BUF DMA handle");
		return (DDI_FAILURE);
	}
	portc->paddr = cookie.dmac_address;

	portc->engine = audio_engine_alloc(&cmediahd_engine_ops, caps);
	if (portc->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(portc->engine, portc);
	audio_dev_add_engine(adev, portc->engine);

	return (DDI_SUCCESS);
}

void
cmediahd_destroy(cmediahd_devc_t *devc)
{
	mutex_destroy(&devc->mutex);
	mutex_destroy(&devc->low_mutex);

	for (int i = 0; i < CMEDIAHD_NUM_PORTC; i++) {
		cmediahd_portc_t *portc = devc->portc[i];
		if (!portc)
			continue;
		if (portc->engine) {
			audio_dev_remove_engine(devc->adev, portc->engine);
			audio_engine_free(portc->engine);
		}
		if (portc->paddr) {
			(void) ddi_dma_unbind_handle(portc->buf_dmah);
		}
		if (portc->buf_acch) {
			ddi_dma_mem_free(&portc->buf_acch);
		}
		if (portc->buf_dmah) {
			ddi_dma_free_handle(&portc->buf_dmah);
		}
		kmem_free(portc, sizeof (*portc));
	}

	if (devc->ac97) {
		ac97_free(devc->ac97);
	}

	cmediahd_del_controls(devc);

	if (devc->adev != NULL) {
		audio_dev_free(devc->adev);
	}
	if (devc->regsh != NULL) {
		ddi_regs_map_free(&devc->regsh);
	}
	if (devc->pcih != NULL) {
		pci_config_teardown(&devc->pcih);
	}
	kmem_free(devc, sizeof (*devc));
}

void
cmediahd_ac97_hwinit(cmediahd_devc_t *devc)
{
	/* GPIO #0 programmed as output, set CMI9780 Reg0x70 */
	cmediahd_write_ac97(devc, 0x70, 0x100);

	/* LI2LI,MIC2MIC; let them always on, FOE on, ROE/BKOE/CBOE off */
	cmediahd_write_ac97(devc, 0x62, 0x180F);

	/* unmute Master Volume */
	cmediahd_write_ac97(devc, 0x02, 0x0);

	/* change PCBeep path, set Mix2FR on, option for quality issue */
	cmediahd_write_ac97(devc, 0x64, 0x8043);

	/* mute PCBeep, option for quality issues */
	cmediahd_write_ac97(devc, 0x0A, 0x8000);

	/* Record Select Control Register (Index 1Ah) */
	cmediahd_write_ac97(devc, 0x1A, 0x0000);

	/* set Mic Volume Register 0x0Eh umute and enable micboost */
	cmediahd_write_ac97(devc, 0x0E, 0x0848);

	/* set Line in Volume Register 0x10h mute */
	cmediahd_write_ac97(devc, 0x10, 0x8808);

	/* set CD Volume Register 0x12h mute */
	cmediahd_write_ac97(devc, 0x12, 0x8808);

	/* set AUX Volume Register 0x16h max */
	cmediahd_write_ac97(devc, 0x16, 0x0808);

	/* set record gain Register 0x1Ch to max */
	cmediahd_write_ac97(devc, 0x1C, 0x0F0F);

	/* GPIO status  register enable GPO0 */
	cmediahd_write_ac97(devc, 0x72, 0x0001);
}
void
cmediahd_hwinit(cmediahd_devc_t *devc)
{

	unsigned short sVal;
	unsigned short i2s_fmt;
	unsigned char bVal;
	int i, count;

	/* setup the default rec DMA engines to REC_A */
	devc->rec_eng.addr = RECA_ADDR;
	devc->rec_eng.size = RECA_SIZE;
	devc->rec_eng.frag = RECA_FRAG;
	devc->rec_eng.i2s = I2S_ADC1;
	devc->rec_eng.chan = REC_A;

	/* setup GPIOs to 0 */
	devc->gpio_mic = 0;
	devc->gpio_out = 0;
	devc->gpio_codec = 0;
	devc->gpio_alt = 0;

	/* Init CMI Controller */
	sVal = INW(devc, CTRL_VERSION);
	if (!(sVal & 0x0008)) {
		bVal = INB(devc, MISC_REG);
		bVal |= 0x20;
		OUTB(devc, bVal, MISC_REG);
	}

	bVal = INB(devc, FUNCTION);
	bVal |= 0x02; /* Reset codec */
	OUTB(devc, bVal, FUNCTION);

	/* Cold reset onboard AC97 */
	OUTW(devc, 0x1, AC97_CTRL);
	count = 100;
	while ((INW(devc, AC97_CTRL) & 0x2) && (count--)) {
		OUTW(devc, (INW(devc, AC97_CTRL) & ~0x2) | 0x2, AC97_CTRL);
		drv_usecwait(100);
	}

	if (!count)
		audio_dev_warn(devc->adev, "CMI8788 AC97 not ready");

	sVal = INW(devc, AC97_CTRL);
	/* check if there's an onboard AC97 codec (CODEC 0) */
	if (sVal & 0x10) {
		/* disable CODEC0 OUTPUT */
		OUTW(devc, INW(devc, AC97_OUT_CHAN_CONFIG) & ~0xFF00,
		    AC97_OUT_CHAN_CONFIG);

		/* enable CODEC0 INPUT */
		OUTW(devc, INW(devc, AC97_IN_CHAN_CONFIG) | 0x0300,
		    AC97_IN_CHAN_CONFIG);

		devc->has_ac97 = 1;
	}

	/* check if there's an front panel AC97 codec (CODEC1) */
	if (sVal & 0x20) {
		/* enable CODEC1 OUTPUT */
		OUTW(devc, INW(devc, AC97_OUT_CHAN_CONFIG) | 0x0033,
		    AC97_OUT_CHAN_CONFIG);
		/* enable CODEC1 INPUT */
		OUTW(devc, INW(devc, AC97_IN_CHAN_CONFIG) | 0x0033,
		    AC97_IN_CHAN_CONFIG);

		devc->has_fp_ac97 = 1;
	}

	/* Disable AC97 interrupts and initialize AC97 */
	OUTB(devc, 0x0, AC97_INTR_MASK);
	OUTW(devc, INW(devc, IRQ_MASK) & ~0x4000, IRQ_MASK);

	/* I2S to 16bit/48Khz/Master, see below. */
	i2s_fmt = 0x011A;

	/* Setup I2S to use 16bit instead of 24Bit */
	OUTW(devc, i2s_fmt, I2S_MULTICH_DAC);
	OUTW(devc, i2s_fmt, I2S_ADC1);
	OUTW(devc, i2s_fmt, I2S_ADC2);
	OUTW(devc, i2s_fmt, I2S_ADC3);

	/* setup Routing regs (default vals) */
	OUTW(devc, 0xE400, PLAY_ROUTING);
	OUTB(devc, 0x00, REC_ROUTING); /* default routing set to I2S */
	OUTB(devc, 0x00, REC_MONITOR); /* monitor through MULTICH_PLAY */
	OUTB(devc, 0xE4, MONITOR_ROUTING); /* default monitor routing */


	/* Enable Xonar output */
	switch (devc->model) {
	case SUBID_XONAR_D1:
	case SUBID_XONAR_DX:
		/* GPIO8 = 0x100 controls mic/line-in */
		/* GPIO0 = 0x001controls output */
		/* GPIO2/3 = 0x00C codec output control */

		devc->rec_eng.addr = RECB_ADDR;
		devc->rec_eng.size = RECB_SIZE;
		devc->rec_eng.frag = RECB_FRAG;
		devc->rec_eng.i2s = I2S_ADC2;
		devc->rec_eng.chan = REC_B;

		/* disable AC97 mixer - not used */
		devc->has_ac97 = 0;

		/* setup for 2wire communication mode */
		OUTB(devc, INB(devc, FUNCTION) | 0x40, FUNCTION);

		/* setup GPIO direction */
		OUTW(devc, INW(devc, GPIO_CONTROL) | 0x10D, GPIO_CONTROL);
		/* setup GPIO pins */
		OUTW(devc, INW(devc, GPIO_DATA) | 0x101, GPIO_DATA);

		/* init the front and rear dacs */
		cs4398_init(devc, XONAR_DX_FRONTDAC);
		cs4362a_init(devc, XONAR_DX_SURRDAC);
		break;

	case SUBID_XONAR_D2:
	case SUBID_XONAR_D2X:
		/* GPIO7 = 0x0080 controls mic/line-in */
		/* GPIO8 = 0x0100 controls output */
		/* GPIO2/3 = 0x000C codec output control */

		devc->rec_eng.addr = RECB_ADDR;
		devc->rec_eng.size = RECB_SIZE;
		devc->rec_eng.frag = RECB_FRAG;
		devc->rec_eng.i2s = I2S_ADC2;
		devc->rec_eng.chan = REC_B;

		/* disable the AC97 mixer - it's not useful */
		devc->has_ac97 = 0;

		/* setup for spi communication mode */
		OUTB(devc, (INB(devc, FUNCTION) & ~0x40) | 0x80, FUNCTION);
		/* setup the GPIO direction */
		OUTW(devc, INW(devc, GPIO_CONTROL) | 0x18c, GPIO_CONTROL);

		/* setup GPIO Pins */
		OUTW(devc, INW(devc, GPIO_DATA) | 0x100,  GPIO_DATA);

		/* for all 4 codecs: unmute, set to 24Bit SPI */
		for (i = 0; i < 4; ++i) {
			/* left vol */
			spi_write(devc, i, 16, mix_scale(75, 8));
			/* right vol */
			spi_write(devc, i, 17, mix_scale(75, 8));
			/* unmute/24LSB/ATLD */
			spi_write(devc, i, 18, 0x30 | 0x80);
		}
		break;

	case SUBID_XONAR_STX:
		devc->rec_eng.addr = RECB_ADDR;
		devc->rec_eng.size = RECB_SIZE;
		devc->rec_eng.frag = RECB_FRAG;
		devc->rec_eng.i2s = I2S_ADC2;
		devc->rec_eng.chan = REC_B;

		/* disable the AC97 mixer - it's not useful */
		devc->has_ac97 = 0;

		/* setup for spi communication mode */
		OUTB(devc, (INB(devc, FUNCTION) & ~0x40) | 0x80, FUNCTION);
		/* setup the GPIO direction */
		OUTW(devc, INW(devc, GPIO_CONTROL) | 0x18F, GPIO_CONTROL);
		/* setup GPIO Pins */
		OUTW(devc, INW(devc, GPIO_DATA) | 0x111, GPIO_DATA);

		/* init front DAC */
		/* left vol */
		i2c_write(devc, XONAR_STX_FRONTDAC, 16, mix_scale(75, 8));
		/* right vol */
		i2c_write(devc, XONAR_STX_FRONTDAC, 17, mix_scale(75, 8));
		/* unmute/24LSB/ATLD */
		i2c_write(devc, XONAR_STX_FRONTDAC, 18, 0x30 | 0x80);
		i2c_write(devc, XONAR_STX_FRONTDAC, 19, 0); /* ATS1/FLT_SHARP */
		i2c_write(devc, XONAR_STX_FRONTDAC, 20, 0); /* OS_64 */
		i2c_write(devc, XONAR_STX_FRONTDAC, 21, 0);
		break;

	case SUBID_XONAR_DS:
		/* GPIO 8 = 1 output enabled 0 mute */
		/* GPIO 7 = 1 lineout enabled 0 mute */
		/* GPIO 6 = 1 mic select 0 line-in select */
		/* GPIO 4 = 1 FP Headphone plugged in */
		/* GPIO 3 = 1 FP Mic plugged in */

		devc->rec_eng.addr = RECA_ADDR;
		devc->rec_eng.size = RECA_SIZE;
		devc->rec_eng.frag = RECA_FRAG;
		devc->rec_eng.i2s = I2S_ADC1;
		devc->rec_eng.chan = REC_A;

		/* disable the AC97 mixer - it's not useful */
		devc->has_ac97 = 0;

		/* setup for spi communication mode */
		OUTB(devc, (INB(devc, FUNCTION) & ~0x40) | 0x80, FUNCTION);
		/* setup the GPIO direction */
		OUTW(devc, INW(devc, GPIO_CONTROL) | 0x1D0, GPIO_CONTROL);
		/* setup GPIO Pins */
		OUTW(devc, INW(devc, GPIO_DATA) | 0x1D0, GPIO_DATA);
		spi_write(devc, XONAR_DS_FRONTDAC, 0x17, 0x1); /* reset */
		spi_write(devc, XONAR_DS_FRONTDAC, 0x7, 0x90); /* dac control */
		spi_write(devc, XONAR_DS_FRONTDAC, 0x8, 0); /* unmute */
		/* powerdown hp */
		spi_write(devc, XONAR_DS_FRONTDAC, 0xC, 0x22);
		spi_write(devc, XONAR_DS_FRONTDAC, 0xD, 0x8); /* powerdown hp */
		spi_write(devc, XONAR_DS_FRONTDAC, 0xA, 0x1); /* LJust/16bit */
		spi_write(devc, XONAR_DS_FRONTDAC, 0xB, 0x1); /* LJust/16bit */
		spi_write(devc, XONAR_DS_SURRDAC, 0x1f, 1); /* reset */
		/* LJust/24bit */
		spi_write(devc, XONAR_DS_SURRDAC, 0x3, 0x1|0x20);
		break;


	default:
		/* SPI default for anything else, including the */
		OUTB(devc, (INB(devc, FUNCTION) & ~0x40) | 0x80, FUNCTION);
		OUTB(devc, 0x18, REC_ROUTING); /* default routing set to I2S */
		break;
	}

	/* only initialize AC97 if not defined */
	if (devc->has_ac97)
		cmediahd_ac97_hwinit(devc);
}

static int
cmediahd_set_control(void *arg, uint64_t val)
{
	cmediahd_ctrl_t	*pc = arg;
	cmediahd_devc_t	*devc = pc->devc;

	mutex_enter(&devc->mutex);

	pc->val = val;

	switch (pc->num) {

	case CTL_VOLUME:
	case CTL_FRONT:
		cmediahd_set_play_volume(devc, 0, val);
		break;

	case CTL_REAR:
		cmediahd_set_play_volume(devc, 1, val);
		break;

	case CTL_CENTER:
		val &= 0xff;
		val |= ((devc->controls[CTL_LFE].val) << 8);
		cmediahd_set_play_volume(devc, 2, val);
		break;

	case CTL_LFE:
		val &= 0xff;
		val <<= 8;
		val |= (devc->controls[CTL_CENTER].val);
		cmediahd_set_play_volume(devc, 2, val);
		break;

	case CTL_SURROUND:
		cmediahd_set_play_volume(devc, 3, val);
		break;

	case CTL_MONITOR:
		/* enable recording  monitor rec 1 and rec2 */
		if (val)
			OUTB(devc, INB(devc, REC_MONITOR) | 0xF, REC_MONITOR);
		else
			OUTB(devc, INB(devc, REC_MONITOR) & ~0xF, REC_MONITOR);
		break;

	case CTL_RECSRC:
		switch (val) {
		case 1: /* Line */
			if (devc->model == SUBID_XONAR_DS)
				OUTW(devc, INW(devc, GPIO_DATA) & ~0x40,
				    GPIO_DATA);

			if (devc->model == SUBID_XONAR_D1 ||
			    devc->model == SUBID_XONAR_DX)
				OUTW(devc, INW(devc, GPIO_DATA) &
				    ~devc->gpio_mic, GPIO_DATA);
			cmediahd_write_ac97(devc, 0x72,
			    cmediahd_read_ac97(devc, 0x72) & ~0x1);
			cmediahd_write_ac97(devc, 0x1A, 0x0404);
			break;

		case 2:  /* Mic */
			if (devc->model == SUBID_XONAR_DS)
				OUTW(devc, INW(devc, GPIO_DATA) | 0x40,
				    GPIO_DATA);

			if (devc->model == SUBID_XONAR_D1 ||
			    devc->model == SUBID_XONAR_DX)
				OUTW(devc, INW(devc, GPIO_DATA) |
				    devc->gpio_mic, GPIO_DATA);
			cmediahd_write_ac97(devc, 0x72,
			    cmediahd_read_ac97(devc, 0x72) | 0x1);
			/* Unmute Mic */
			cmediahd_write_ac97(devc, 0xE,
			    cmediahd_read_ac97(devc, 0xE) & ~0x8000);
			/* Mute AUX and Video */
			cmediahd_write_ac97(devc, 0x12,
			    cmediahd_read_ac97(devc, 0x12) | 0x8000);
			cmediahd_write_ac97(devc, 0x16,
			    cmediahd_read_ac97(devc, 0x16) | 0x8000);
			cmediahd_write_ac97(devc, 0x1A, 0x0000);
			break;

		case 4: /* AUX */
			if (devc->model == SUBID_XONAR_D1 ||
			    devc->model == SUBID_XONAR_DX)
				OUTW(devc, INW(devc, GPIO_DATA) |
				    devc->gpio_mic, GPIO_DATA);
			cmediahd_write_ac97(devc, 0x72,
			    cmediahd_read_ac97(devc, 0x72) | 0x1);
			/* Unmute AUX */
			cmediahd_write_ac97(devc, 0x16,
			    cmediahd_read_ac97(devc, 0x16) & ~0x8000);
			/* Mute CD and Mic */
			cmediahd_write_ac97(devc, 0x14,
			    cmediahd_read_ac97(devc, 0x14) | 0x8000);
			cmediahd_write_ac97(devc, 0x0E,
			    cmediahd_read_ac97(devc, 0x0E) | 0x8000);
			cmediahd_write_ac97(devc, 0x1A, 0x0303);
			break;

		case 8: /* Video (CD) */
			if (devc->model == SUBID_XONAR_D1 ||
			    devc->model == SUBID_XONAR_DX)
				OUTW(devc, INW(devc, GPIO_DATA) |
				    devc->gpio_mic, GPIO_DATA);
			cmediahd_write_ac97(devc, 0x72,
			    cmediahd_read_ac97(devc, 0x72) | 0x1);
			/* Unmute Video (CD) */
			cmediahd_write_ac97(devc, 0x14,
			    cmediahd_read_ac97(devc, 0x14) & ~0x8000);
			/* Mute AUX and Mic */
			cmediahd_write_ac97(devc, 0x16,
			    cmediahd_read_ac97(devc, 0x16) | 0x8000);
			cmediahd_write_ac97(devc, 0x0E,
			    cmediahd_read_ac97(devc, 0x0E) | 0x8000);
			/* set input to video */
			cmediahd_write_ac97(devc, 0x1A, 0x0202);
			break;
		}
		break;

	case CTL_LOOP:
		if (val)
			OUTW(devc, INW(devc, GPIO_DATA) | devc->gpio_alt,
			    GPIO_DATA);
		else
			OUTW(devc, (INW(devc, GPIO_DATA) & ~devc->gpio_alt),
			    GPIO_DATA);
		break;

	case CTL_SPREAD:
		if (val)
			OUTW(devc, INW(devc, PLAY_ROUTING) & 0x00FF,
			    PLAY_ROUTING);
		else
			OUTW(devc, (INW(devc, PLAY_ROUTING) & 0x00FF) |
			    0xE400, PLAY_ROUTING);
		break;

	case CTL_RECGAIN:
		cmediahd_set_rec_volume(devc, val);
		break;

	case CTL_MICVOL:
		if (val)
			cmediahd_write_ac97(devc, 0x0E,
			    (0x40 | mix_scale(val, -5)) & ~0x8000);
		else
			cmediahd_write_ac97(devc, 0x0E, 0x8000);
		break;

	case CTL_AUXVOL:
		if (val)
			cmediahd_write_ac97(devc, 0x16,
			    mix_scale(val, -5) & ~0x8000);
		else
			cmediahd_write_ac97(devc, 0x16, 0x8000);
		break;


	case CTL_CDVOL:
		if (val)
			cmediahd_write_ac97(devc, 0x14,
			    mix_scale(val, -5) & ~0x8000);
		else
			cmediahd_write_ac97(devc, 0x14, 0x8000);
		break;
	}

	mutex_exit(&devc->mutex);
	return (0);
}

static int
cmediahd_get_control(void *arg, uint64_t *val)
{
	cmediahd_ctrl_t	*pc = arg;
	cmediahd_devc_t	*devc = pc->devc;

	mutex_enter(&devc->mutex);
	*val = pc->val;
	mutex_exit(&devc->mutex);
	return (0);
}

static void
cmediahd_alloc_ctrl(cmediahd_devc_t *devc, uint32_t num, uint64_t val)
{
	audio_ctrl_desc_t	desc;
	cmediahd_ctrl_t		*pc;

	bzero(&desc, sizeof (desc));

	pc = &devc->controls[num];
	pc->num = num;
	pc->devc = devc;


	switch (num) {

	case CTL_VOLUME:
		desc.acd_name = AUDIO_CTRL_ID_VOLUME;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		break;

	case CTL_FRONT:
		desc.acd_name = AUDIO_CTRL_ID_FRONT;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		break;

	case CTL_REAR:
		desc.acd_name = AUDIO_CTRL_ID_REAR;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		break;

	case CTL_SURROUND:
		desc.acd_name = AUDIO_CTRL_ID_SURROUND;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		break;

	case CTL_CENTER:
		desc.acd_name = AUDIO_CTRL_ID_CENTER;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		break;

	case CTL_LFE:
		desc.acd_name = AUDIO_CTRL_ID_LFE;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		break;

	case CTL_MONITOR:
		desc.acd_name = AUDIO_CTRL_ID_MONSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = RECCTL;
		break;

	case CTL_RECSRC:
		desc.acd_name = AUDIO_CTRL_ID_RECSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_flags = RECCTL;
		desc.acd_enum[0] = AUDIO_PORT_LINEIN;
		desc.acd_enum[1] = AUDIO_PORT_MIC;

		if (devc->model == SUBID_XONAR_D2 ||
		    devc->model == SUBID_XONAR_D2X) {
			desc.acd_minvalue = 0xF;
			desc.acd_maxvalue = 0xF;
			desc.acd_enum[2] = AUDIO_PORT_AUX1IN;
			desc.acd_enum[3] = AUDIO_PORT_CD;
		} else {
			desc.acd_minvalue = 0x3;
			desc.acd_maxvalue = 0x3;
		}
		break;

	case CTL_LOOP:
		desc.acd_name = AUDIO_CTRL_ID_LOOPBACK;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = RECCTL;
		break;

	case CTL_SPREAD:
		desc.acd_name = AUDIO_CTRL_ID_SPREAD;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = PLAYCTL;
		break;

	case CTL_RECGAIN:
		desc.acd_name = AUDIO_CTRL_ID_RECGAIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;

	case CTL_MICVOL:
		desc.acd_name = AUDIO_CTRL_ID_MIC;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;

	case CTL_AUXVOL:
		desc.acd_name = AUDIO_CTRL_ID_AUX1IN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;
	case CTL_CDVOL:
		desc.acd_name = AUDIO_CTRL_ID_CD;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;

	}

	pc->val = val;
	pc->ctrl = audio_dev_add_control(devc->adev, &desc,
	    cmediahd_get_control, cmediahd_set_control, pc);
}

static void
cmediahd_refresh_mixer(cmediahd_devc_t *devc)
{
	int ctl;

	for (ctl = 0; ctl < CTL_NUM; ctl++) {
		if (devc->controls[ctl].ctrl == NULL)
			continue;
		(void) cmediahd_set_control(&devc->controls[ctl],
		    devc->controls[ctl].val);
	}
}

static void
cmediahd_add_controls(cmediahd_devc_t *devc)
{
	cmediahd_alloc_ctrl(devc, CTL_VOLUME, 80 | (80 << 8));
	cmediahd_alloc_ctrl(devc, CTL_FRONT, 80 | (80<<8));
	cmediahd_alloc_ctrl(devc, CTL_REAR, 80 | (80<<8));
	cmediahd_alloc_ctrl(devc, CTL_CENTER, 80);
	cmediahd_alloc_ctrl(devc, CTL_LFE, 80);
	cmediahd_alloc_ctrl(devc, CTL_SURROUND, 80 | (80<<8));
	cmediahd_alloc_ctrl(devc, CTL_SPREAD, 0);
	cmediahd_alloc_ctrl(devc, CTL_MONITOR, 0);
	cmediahd_alloc_ctrl(devc, CTL_LOOP, 0);
	cmediahd_alloc_ctrl(devc, CTL_RECSRC, 2);

	switch (devc->model) {
	case SUBID_XONAR_DS:
		cmediahd_alloc_ctrl(devc, CTL_RECGAIN, 80|80<<8);
		break;
	case SUBID_XONAR_D2:
	case SUBID_XONAR_D2X:
		cmediahd_alloc_ctrl(devc, CTL_MICVOL, 80|80<<8);
		cmediahd_alloc_ctrl(devc, CTL_AUXVOL, 80|80<<8);
		cmediahd_alloc_ctrl(devc, CTL_CDVOL, 80|80<<8);
		break;
	}

	cmediahd_refresh_mixer(devc);
}

void
cmediahd_del_controls(cmediahd_devc_t *dev)
{
	for (int i = 0; i < CTL_NUM; i++) {
		if (dev->controls[i].ctrl) {
			audio_dev_del_control(dev->controls[i].ctrl);
			dev->controls[i].ctrl = NULL;
		}
	}
}

int
cmediahd_attach(dev_info_t *dip)
{
	uint16_t	pci_command, vendor, device, subvendor, subdevice;
	cmediahd_devc_t	*devc;
	ddi_acc_handle_t pcih;

	devc = kmem_zalloc(sizeof (*devc), KM_SLEEP);
	devc->dip = dip;
	ddi_set_driver_private(dip, devc);

	mutex_init(&devc->mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&devc->low_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((devc->adev = audio_dev_alloc(dip, 0)) == NULL) {
		cmn_err(CE_WARN, "audio_dev_alloc failed");
		goto error;
	}

	if (pci_config_setup(dip, &pcih) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "pci_config_setup failed");
		goto error;
	}
	devc->pcih = pcih;

	vendor = pci_config_get16(pcih, PCI_CONF_VENID);
	device = pci_config_get16(pcih, PCI_CONF_DEVID);
	subvendor = pci_config_get16(pcih, PCI_CONF_SUBVENID);
	subdevice = pci_config_get16(pcih, PCI_CONF_SUBSYSID);
	if (vendor != PCI_VENDOR_ID_CMEDIA ||
	    device != PCI_DEVICE_ID_CMEDIAHD) {
		audio_dev_warn(devc->adev, "Hardware not recognized "
		    "(vendor=%x, dev=%x)", vendor, device);
		goto error;
	}


	pci_command = pci_config_get16(pcih, PCI_CONF_COMM);
	pci_command |= PCI_COMM_ME | PCI_COMM_IO;
	pci_config_put16(pcih, PCI_CONF_COMM, pci_command);

	if ((ddi_regs_map_setup(dip, 1, &devc->base, 0, 0, &dev_attr,
	    &devc->regsh)) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "failed to map registers");
		goto error;
	}

	audio_dev_set_description(devc->adev, "CMedia 8788");

	/* Detect Xonar device */
	if (subvendor == ASUS_VENDOR_ID) {
		switch (subdevice) {
		case SUBID_XONAR_D1:
			audio_dev_set_description(devc->adev,
			    "Asus Xonar D1 (AV100)");
			break;
		case SUBID_XONAR_DX:
			audio_dev_set_description(devc->adev,
			    "Asus Xonar DX (AV100)");
			break;
		case SUBID_XONAR_D2:
			audio_dev_set_description(devc->adev,
			    "Asus Xonar D2 (AV200)");
			break;
		case SUBID_XONAR_D2X:
			audio_dev_set_description(devc->adev,
			    "Asus Xonar D2X (AV200)");
			break;
		case SUBID_XONAR_STX:
			audio_dev_set_description(devc->adev,
			    "Asus Xonar STX (AV100)");
			break;
		case SUBID_XONAR_DS:
			audio_dev_set_description(devc->adev,
			    "Asus Xonar DS (AV66)");
			break;
		default:
			audio_dev_set_description(devc->adev,
			    "Asus Xonar Unknown Model");
			subdevice = SUBID_GENERIC;
			break;
		}
		devc->model = subdevice;
	}

	cmediahd_hwinit(devc);

	if (cmediahd_alloc_port(devc, CMEDIAHD_PLAY) != DDI_SUCCESS)
		goto error;
	if (cmediahd_alloc_port(devc, CMEDIAHD_REC) != DDI_SUCCESS)
		goto error;

	/* Add the AC97 Mixer if there is an onboard AC97 device */
	if (devc->has_ac97) {
		devc->ac97 = ac97_alloc(dip, cmediahd_read_ac97,
		    cmediahd_write_ac97, devc);
		if (ac97_init(devc->ac97, devc->adev) != DDI_SUCCESS) {
			audio_dev_warn(devc->adev, "failed to init ac97");
			goto error;
		}
	}
#if 0
	/* Add the front panel AC97 device if one exists */
	if (devc->has_fp_ac97) {
		devc->fp_ac97 = ac97_alloc(dip, cmediahd_read_fp_ac97,
		    cmediahd_write_fp_ac97, devc);
		if (ac97_init(devc->fp_ac97, devc->adev) != DDI_SUCCESS) {
			audio_dev_warn(devc->adev, "failed to init fp_ac97");
			goto error;
		}
	}
#endif
	/* Add the standard CMI8788 Mixer panel */
	cmediahd_add_controls(devc);

	if (audio_dev_register(devc->adev) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "unable to register with framework");
		goto error;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	cmediahd_destroy(devc);
	return (DDI_FAILURE);
}

int
cmediahd_resume(dev_info_t *dip)
{
	cmediahd_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	cmediahd_hwinit(devc);

	if (devc->ac97)
		ac97_reset(devc->ac97);

	cmediahd_refresh_mixer(devc);

	audio_dev_resume(devc->adev);

	return (DDI_SUCCESS);
}

int
cmediahd_detach(cmediahd_devc_t *devc)
{
	if (audio_dev_unregister(devc->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	cmediahd_destroy(devc);
	return (DDI_SUCCESS);
}

int
cmediahd_suspend(cmediahd_devc_t *devc)
{
	audio_dev_suspend(devc->adev);
	return (DDI_SUCCESS);
}

static int cmediahd_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int cmediahd_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int cmediahd_ddi_quiesce(dev_info_t *);

static struct dev_ops cmediahd_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	cmediahd_ddi_attach,	/* attach */
	cmediahd_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	cmediahd_ddi_quiesce,	/* quiesce */
};

static struct modldrv cmediahd_modldrv = {
	&mod_driverops,			/* drv_modops */
	"CMedia 8788",			/* linkinfo */
	&cmediahd_dev_ops,		/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &cmediahd_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&cmediahd_dev_ops, CMEDIAHD_NAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&cmediahd_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&cmediahd_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
cmediahd_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (cmediahd_attach(dip));

	case DDI_RESUME:
		return (cmediahd_resume(dip));

	default:
		return (DDI_FAILURE);
	}
}

int
cmediahd_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	cmediahd_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		return (cmediahd_detach(devc));

	case DDI_SUSPEND:
		return (cmediahd_suspend(devc));

	default:
		return (DDI_FAILURE);
	}
}

int
cmediahd_ddi_quiesce(dev_info_t *dip)
{
	cmediahd_devc_t	*devc;

	devc = ddi_get_driver_private(dip);

	OUTW(devc, 0x0, DMA_START);

	/*
	 * Turn off the hardware
	 */


	return (DDI_SUCCESS);
}
