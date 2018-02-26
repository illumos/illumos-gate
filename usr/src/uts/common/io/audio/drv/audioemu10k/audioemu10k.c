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

/*
 * Copyright (C) 4Front Technologies 1996-2009.
 */

/*
 * Purpose: Driver for the Creative Sound Blaster Live! and Audigy/2/4
 * sound cards
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/stdbool.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>

#include "audioemu10k.h"
#include <sys/promif.h>

/*
 * Include the DSP files for emu10k1 (Live!) and emu10k2 (Audigy)
 */
#include "emu10k_gpr.h"
#include "emu10k1_dsp.h"
#include "emu10k2_dsp.h"

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


/*
 * EMU10K routing stuff.
 */
#define	MAX_SENDS		4
#define	SEND_L			0
#define	SEND_R			1
#define	SEND_SURRL		2
#define	SEND_SURRR		3
#define	SEND_CEN		4
#define	SEND_LFE		5
#define	SEND_SIDEL		6
#define	SEND_SIDER		7

#define	SPDIF_L			20
#define	SPDIF_R			21

/*
 * Recording sources... we start from 16 to ensure that the
 * record sources don't collide with AC'97 record sources in
 * the control value.
 */
#define	INPUT_AC97		1
#define	INPUT_SPD1		2
#define	INPUT_SPD2		3
#define	INPUT_DIGCD		4
#define	INPUT_AUX2		5
#define	INPUT_LINE2		6
#define	INPUT_STEREOMIX		7

static uint8_t front_routing[MAX_SENDS] = {
	SEND_L, SEND_R, 0x3f, 0x3f
};
static uint8_t surr_routing[MAX_SENDS] = {
	SEND_SURRL, SEND_SURRR, 0x3f, 0x3f
};
static uint8_t clfe_routing[MAX_SENDS] = {
	SEND_CEN, SEND_LFE, 0x3f, 0x3f
};
static uint8_t side_routing[MAX_SENDS] = {
	SEND_SIDEL, SEND_SIDER, 0x3f, 0x3f
};

/*
 * SB Live! cannot do DMA above 2G addresses. Audigy/2/4 have special 8k page
 * mode that supports high addresses.  However, we should not need this except
 * on SPARC.  For simplicity's sake, we are only delivering this driver for
 * x86 platforms.  If SPARC support is desired, then the code will have to
 * be modified to support full 32-bit addressing.  (And again, SB Live!
 * can't do it anyway.)
 */

static ddi_dma_attr_t dma_attr_buf = {
	DMA_ATTR_V0,		/* Version */
	0x00000000ULL,		/* Address low */
	0x7ffffff0ULL,		/* Address high */
	0xffffffffULL,		/* Counter max */
	1ULL,			/* Default byte align */
	0x7f,			/* Burst size */
	0x1,			/* Minimum xfer size */
	0xffffffffULL,		/* Maximum xfer size */
	0xffffffffULL,		/* Max segment size */
	1,			/* S/G list length */
	1,			/* Granularity */
	0			/* Flag */
};

static int emu10k_attach(dev_info_t *);
static int emu10k_resume(dev_info_t *);
static int emu10k_detach(emu10k_devc_t *);
static int emu10k_suspend(emu10k_devc_t *);

static int emu10k_open(void *, int, unsigned *, caddr_t *);
static void emu10k_close(void *);
static int emu10k_start(void *);
static void emu10k_stop(void *);
static int emu10k_format(void *);
static int emu10k_channels(void *);
static int emu10k_rate(void *);
static uint64_t emu10k_count(void *);
static void emu10k_sync(void *, unsigned);
static void emu10k_chinfo(void *, int, unsigned *, unsigned *);

static uint16_t emu10k_read_ac97(void *, uint8_t);
static void emu10k_write_ac97(void *, uint8_t, uint16_t);
static int emu10k_alloc_port(emu10k_devc_t *, int);
static void emu10k_destroy(emu10k_devc_t *);
static int emu10k_hwinit(emu10k_devc_t *);
static void emu10k_init_effects(emu10k_devc_t *);

static audio_engine_ops_t emu10k_engine_ops = {
	AUDIO_ENGINE_VERSION,
	emu10k_open,
	emu10k_close,
	emu10k_start,
	emu10k_stop,
	emu10k_count,
	emu10k_format,
	emu10k_channels,
	emu10k_rate,
	emu10k_sync,
	NULL,
	emu10k_chinfo,
	NULL
};

static uint16_t
emu10k_read_ac97(void *arg, uint8_t index)
{
	emu10k_devc_t *devc = arg;
	int dtemp = 0, i;

	mutex_enter(&devc->mutex);
	OUTB(devc, index, devc->regs + 0x1e);
	for (i = 0; i < 10000; i++)
		if (INB(devc, devc->regs + 0x1e) & 0x80)
			break;

	if (i == 1000) {
		mutex_exit(&devc->mutex);
		return (0);			/* Timeout */
	}
	dtemp = INW(devc, devc->regs + 0x1c);

	mutex_exit(&devc->mutex);

	return (dtemp & 0xffff);
}

static void
emu10k_write_ac97(void *arg, uint8_t index, uint16_t data)
{
	emu10k_devc_t *devc = arg;
	int i;

	mutex_enter(&devc->mutex);

	OUTB(devc, index, devc->regs + 0x1e);
	for (i = 0; i < 10000; i++)
		if (INB(devc, devc->regs + 0x1e) & 0x80)
			break;
	OUTW(devc, data, devc->regs + 0x1c);

	mutex_exit(&devc->mutex);
}

static uint32_t
emu10k_read_reg(emu10k_devc_t *devc, int reg, int chn)
{
	uint32_t ptr, ptr_addr_mask, val, mask, size, offset;

	ptr_addr_mask = (devc->feature_mask &
	    (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) ?
	    0x0fff0000 : 0x07ff0000;
	ptr = ((reg << 16) & ptr_addr_mask) | (chn & 0x3f);
	OUTL(devc, ptr, devc->regs + 0x00);	/* Pointer */
	val = INL(devc, devc->regs + 0x04);	/* Data */
	if (reg & 0xff000000) {
		size = (reg >> 24) & 0x3f;
		offset = (reg >> 16) & 0x1f;
		mask = ((1 << size) - 1) << offset;
		val &= mask;
		val >>= offset;
	}

	return (val);
}

static void
emu10k_write_reg(emu10k_devc_t *devc, int reg, int chn, uint32_t value)
{
	uint32_t ptr, ptr_addr_mask, mask, size, offset;

	ptr_addr_mask = (devc->feature_mask &
	    (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) ?
	    0x0fff0000 : 0x07ff0000;
	ptr = ((reg << 16) & ptr_addr_mask) | (chn & 0x3f);
	OUTL(devc, ptr, devc->regs + 0x00);	/* Pointer */
	if (reg & 0xff000000) {
		size = (reg >> 24) & 0x3f;
		offset = (reg >> 16) & 0x1f;
		mask = ((1 << size) - 1) << offset;
		value <<= offset;
		value &= mask;
		value |= INL(devc, devc->regs + 0x04) & ~mask;	/* data */
	}
	OUTL(devc, value, devc->regs + 0x04);	/* Data */
}

static void
emu10k_write_routing(emu10k_devc_t *devc, int voice, unsigned char *routing)
{
	int i;

	ASSERT(routing != NULL);

	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) {
		unsigned int srda = 0;

		for (i = 0; i < 4; i++)
			srda |= routing[i] << (i * 8);

		emu10k_write_reg(devc, SRDA, voice, srda);
	} else {
		int fxrt = 0;

		for (i = 0; i < 4; i++)
			fxrt |= routing[i] << ((i * 4) + 16);
		emu10k_write_reg(devc, FXRT, voice, fxrt);
	}
}

static void
emu10k_write_efx(emu10k_devc_t *devc, int reg, unsigned int value)
{
	emu10k_write_reg(devc, reg, 0, value);
}

/*
 * Audio routines
 */

static void
emu10k_update_output_volume(emu10k_portc_t *portc, int voice, int chn)
{
	emu10k_devc_t *devc = portc->devc;
	unsigned int tmp;
	unsigned char send[2];

	/*
	 * Each voice operator of EMU10k has 4 sends (0=left, 1=right,
	 * 2=surround_left, 3=surround_right). The original OSS driver
	 * used all of them to spread stereo output to two different
	 * speaker pairs. This Boomer version uses only the first two
	 * sends. The other sends are set to 0.
	 *
	 * Boomer uses multiple voice pairs to play multichannel
	 * audio. This function is used to update only one of these
	 * pairs.
	 */

	send[0] = 0xff;		/* Max */
	send[1] = 0xff;		/* Max */

	/* Analog voice */
	if (chn == LEFT_CH) {
		send[1] = 0;
	} else {
		send[0] = 0;
	}

	tmp = emu10k_read_reg(devc, PTAB, voice) & 0xffff0000;
	emu10k_write_reg(devc, PTAB, voice, tmp | (send[0] << 8) | send[1]);
}

static void
emu10k_setup_voice(emu10k_portc_t *portc, int voice, int chn, int buf_offset)
{
	emu10k_devc_t *devc = portc->devc;
	unsigned int nCRA = 0;

	unsigned int loop_start, loop_end, buf_size;

	int sz;
	int start_pos;

	emu10k_write_reg(devc, VEDS, voice, 0x0);	/* OFF */
	emu10k_write_reg(devc, VTFT, voice, 0xffff);
	emu10k_write_reg(devc, CVCF, voice, 0xffff);

	sz = 2;			/* Shift value for 16 bits stereo */

	/* Size of one stereo sub buffer */
	buf_size = (portc->buf_size / portc->channels) * 2;
	loop_start = (portc->memptr + buf_offset) >> sz;
	loop_end = (portc->memptr + buf_offset + buf_size) >> sz;

	/* set stereo */
	emu10k_write_reg(devc, CPF, voice, 0x8000);

	nCRA = 28;			/* Stereo (16 bits) */
	start_pos = loop_start + nCRA;

	/* SDL, ST, CA */

	emu10k_write_reg(devc, SDL, voice, loop_end);
	emu10k_write_reg(devc, SCSA, voice, loop_start);
	emu10k_write_reg(devc, PTAB, voice, 0);

	emu10k_update_output_volume(portc, voice, chn);	/* Set volume */

	emu10k_write_reg(devc, QKBCA, voice, start_pos);

	emu10k_write_reg(devc, Z1, voice, 0);
	emu10k_write_reg(devc, Z2, voice, 0);

	/* This is really a physical address */
	emu10k_write_reg(devc, MAPA, voice,
	    0x1fff | (devc->silence_paddr << 1));
	emu10k_write_reg(devc, MAPB, voice,
	    0x1fff | (devc->silence_paddr << 1));

	emu10k_write_reg(devc, VTFT, voice, 0x0000ffff);
	emu10k_write_reg(devc, CVCF, voice, 0x0000ffff);
	emu10k_write_reg(devc, MEHA, voice, 0);
	emu10k_write_reg(devc, MEDS, voice, 0x7f);
	emu10k_write_reg(devc, MLV, voice, 0x8000);
	emu10k_write_reg(devc, VLV, voice, 0x8000);
	emu10k_write_reg(devc, VFM, voice, 0);
	emu10k_write_reg(devc, TMFQ, voice, 0);
	emu10k_write_reg(devc, VVFQ, voice, 0);
	emu10k_write_reg(devc, MEV, voice, 0x8000);
	emu10k_write_reg(devc, VEHA, voice, 0x7f7f);	/* OK */
	/* No volume envelope delay (OK) */
	emu10k_write_reg(devc, VEV, voice, 0x8000);
	emu10k_write_reg(devc, PEFE_FILTERAMOUNT, voice, 0x7f);
	emu10k_write_reg(devc, PEFE_PITCHAMOUNT, voice, 0x00);
}

int
emu10k_open(void *arg, int flag, unsigned *nframes, caddr_t *bufp)
{
	emu10k_portc_t *portc = arg;
	emu10k_devc_t *devc = portc->devc;

	_NOTE(ARGUNUSED(flag));

	portc->active = B_FALSE;
	*nframes = portc->nframes;
	*bufp = portc->buf_kaddr;

	mutex_enter(&devc->mutex);
	portc->count = 0;
	mutex_exit(&devc->mutex);

	return (0);
}

void
emu10k_close(void *arg)
{
	_NOTE(ARGUNUSED(arg));
}

int
emu10k_start(void *arg)
{
	emu10k_portc_t *portc = arg;
	emu10k_devc_t *devc = portc->devc;

	mutex_enter(&devc->mutex);
	portc->reset_port(portc);
	portc->start_port(portc);
	mutex_exit(&devc->mutex);
	return (0);
}

void
emu10k_stop(void *arg)
{
	emu10k_portc_t *portc = arg;
	emu10k_devc_t *devc = portc->devc;

	mutex_enter(&devc->mutex);
	portc->stop_port(portc);
	mutex_exit(&devc->mutex);
}

int
emu10k_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

int
emu10k_channels(void *arg)
{
	emu10k_portc_t *portc = arg;

	return (portc->channels);
}

int
emu10k_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (SAMPLE_RATE);
}

void
emu10k_sync(void *arg, unsigned nframes)
{
	emu10k_portc_t *portc = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(portc->buf_dmah, 0, 0, portc->syncdir);
}

uint64_t
emu10k_count(void *arg)
{
	emu10k_portc_t *portc = arg;
	emu10k_devc_t *devc = portc->devc;
	uint64_t count;

	mutex_enter(&devc->mutex);
	portc->update_port(portc);
	count = portc->count;
	mutex_exit(&devc->mutex);

	return (count);
}

static void
emu10k_chinfo(void *arg, int chan, unsigned *offset, unsigned *incr)
{
	emu10k_portc_t *portc = arg;

	*offset = portc->nframes * (chan / 2) * 2 + (chan % 2);
	*incr = 2;
}

/* private implementation bits */

static void
emu10k_set_loop_stop(emu10k_devc_t *devc, int voice, int s)
{
	unsigned int tmp;
	int offs, bit;

	offs = voice / 32;
	bit = voice % 32;
	s = !!s;

	tmp = emu10k_read_reg(devc, SOLL + offs, 0);
	tmp &= ~(1 << bit);

	if (s)
		tmp |= (1 << bit);
	emu10k_write_reg(devc, SOLL + offs, 0, tmp);
}

static unsigned int
emu10k_rate_to_pitch(unsigned int rate)
{
	static unsigned int logMagTable[128] = {
		0x00000, 0x02dfc, 0x05b9e, 0x088e6,
		0x0b5d6, 0x0e26f, 0x10eb3, 0x13aa2,
		0x1663f, 0x1918a, 0x1bc84, 0x1e72e,
		0x2118b, 0x23b9a, 0x2655d, 0x28ed5,
		0x2b803, 0x2e0e8, 0x30985, 0x331db,
		0x359eb, 0x381b6, 0x3a93d, 0x3d081,
		0x3f782, 0x41e42, 0x444c1, 0x46b01,
		0x49101, 0x4b6c4, 0x4dc49, 0x50191,
		0x5269e, 0x54b6f, 0x57006, 0x59463,
		0x5b888, 0x5dc74, 0x60029, 0x623a7,
		0x646ee, 0x66a00, 0x68cdd, 0x6af86,
		0x6d1fa, 0x6f43c, 0x7164b, 0x73829,
		0x759d4, 0x77b4f, 0x79c9a, 0x7bdb5,
		0x7dea1, 0x7ff5e, 0x81fed, 0x8404e,
		0x86082, 0x88089, 0x8a064, 0x8c014,
		0x8df98, 0x8fef1, 0x91e20, 0x93d26,
		0x95c01, 0x97ab4, 0x9993e, 0x9b79f,
		0x9d5d9, 0x9f3ec, 0xa11d8, 0xa2f9d,
		0xa4d3c, 0xa6ab5, 0xa8808, 0xaa537,
		0xac241, 0xadf26, 0xafbe7, 0xb1885,
		0xb3500, 0xb5157, 0xb6d8c, 0xb899f,
		0xba58f, 0xbc15e, 0xbdd0c, 0xbf899,
		0xc1404, 0xc2f50, 0xc4a7b, 0xc6587,
		0xc8073, 0xc9b3f, 0xcb5ed, 0xcd07c,
		0xceaec, 0xd053f, 0xd1f73, 0xd398a,
		0xd5384, 0xd6d60, 0xd8720, 0xda0c3,
		0xdba4a, 0xdd3b4, 0xded03, 0xe0636,
		0xe1f4e, 0xe384a, 0xe512c, 0xe69f3,
		0xe829f, 0xe9b31, 0xeb3a9, 0xecc08,
		0xee44c, 0xefc78, 0xf148a, 0xf2c83,
		0xf4463, 0xf5c2a, 0xf73da, 0xf8b71,
		0xfa2f0, 0xfba57, 0xfd1a7, 0xfe8df
	};
	static char logSlopeTable[128] = {
		0x5c, 0x5c, 0x5b, 0x5a, 0x5a, 0x59, 0x58, 0x58,
		0x57, 0x56, 0x56, 0x55, 0x55, 0x54, 0x53, 0x53,
		0x52, 0x52, 0x51, 0x51, 0x50, 0x50, 0x4f, 0x4f,
		0x4e, 0x4d, 0x4d, 0x4d, 0x4c, 0x4c, 0x4b, 0x4b,
		0x4a, 0x4a, 0x49, 0x49, 0x48, 0x48, 0x47, 0x47,
		0x47, 0x46, 0x46, 0x45, 0x45, 0x45, 0x44, 0x44,
		0x43, 0x43, 0x43, 0x42, 0x42, 0x42, 0x41, 0x41,
		0x41, 0x40, 0x40, 0x40, 0x3f, 0x3f, 0x3f, 0x3e,
		0x3e, 0x3e, 0x3d, 0x3d, 0x3d, 0x3c, 0x3c, 0x3c,
		0x3b, 0x3b, 0x3b, 0x3b, 0x3a, 0x3a, 0x3a, 0x39,
		0x39, 0x39, 0x39, 0x38, 0x38, 0x38, 0x38, 0x37,
		0x37, 0x37, 0x37, 0x36, 0x36, 0x36, 0x36, 0x35,
		0x35, 0x35, 0x35, 0x34, 0x34, 0x34, 0x34, 0x34,
		0x33, 0x33, 0x33, 0x33, 0x32, 0x32, 0x32, 0x32,
		0x32, 0x31, 0x31, 0x31, 0x31, 0x31, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f
	};
	int i;

	if (rate == 0)
		return (0);			/* Bail out if no leading "1" */
	rate *= 11185;		/* Scale 48000 to 0x20002380 */
	for (i = 31; i > 0; i--) {
		if (rate & 0x80000000) {	/* Detect leading "1" */
			return (((unsigned int) (i - 15) << 20) +
			    logMagTable[0x7f & (rate >> 24)] +
			    (0x7f & (rate >> 17)) *
			    logSlopeTable[0x7f & (rate >> 24)]);
		}
		rate <<= 1;
	}

	return (0);			/* Should never reach this point */
}

static unsigned int
emu10k_rate_to_linearpitch(unsigned int rate)
{
	rate = (rate << 8) / 375;
	return (rate >> 1) + (rate & 1);
}

static void
emu10k_prepare_voice(emu10k_devc_t *devc, int voice)
{
	unsigned int sample, initial_pitch, pitch_target;
	unsigned int cra, cs, ccis, i;

	/* setup CCR regs */
	cra = 64;
	cs = 4;			/* Stereo */
	ccis = 28;		/* Stereo */
	sample = 0;		/* 16 bit silence */

	for (i = 0; i < cs; i++)
		emu10k_write_reg(devc, CD0 + i, voice, sample);

	emu10k_write_reg(devc, CCR_CACHEINVALIDSIZE, voice, 0);
	emu10k_write_reg(devc, CCR_READADDRESS, voice, cra);
	emu10k_write_reg(devc, CCR_CACHEINVALIDSIZE, voice, ccis);

	/* Set current pitch */
	emu10k_write_reg(devc, IFA, voice, 0xff00);
	emu10k_write_reg(devc, VTFT, voice, 0xffffffff);
	emu10k_write_reg(devc, CVCF, voice, 0xffffffff);
	emu10k_set_loop_stop(devc, voice, 0);

	pitch_target = emu10k_rate_to_linearpitch(SAMPLE_RATE);
	initial_pitch = emu10k_rate_to_pitch(SAMPLE_RATE) >> 8;
	emu10k_write_reg(devc, PTRX_PITCHTARGET, voice, pitch_target);
	emu10k_write_reg(devc, CPF_CURRENTPITCH, voice, pitch_target);
	emu10k_write_reg(devc, IP, voice, initial_pitch);
}

static void
emu10k_stop_voice(emu10k_devc_t *devc, int voice)
{
	emu10k_write_reg(devc, IFA, voice, 0xffff);
	emu10k_write_reg(devc, VTFT, voice, 0xffff);
	emu10k_write_reg(devc, PTRX_PITCHTARGET, voice, 0);
	emu10k_write_reg(devc, CPF_CURRENTPITCH, voice, 0);
	emu10k_write_reg(devc, IP, voice, 0);
	emu10k_set_loop_stop(devc, voice, 1);
}

static void
emu10k_reset_pair(emu10k_portc_t *portc, int voice, uint8_t *routing,
    int buf_offset)
{
	emu10k_devc_t *devc = portc->devc;

	/* Left channel */
	/* Intial filter cutoff and attenuation */
	emu10k_write_reg(devc, IFA, voice, 0xffff);
	/* Volume envelope decay and sustain */
	emu10k_write_reg(devc, VEDS, voice, 0x0);
	/* Volume target and Filter cutoff target */
	emu10k_write_reg(devc, VTFT, voice, 0xffff);
	/* Pitch target and sends A and B */
	emu10k_write_reg(devc, PTAB, voice, 0x0);

	/* The same for right channel */
	emu10k_write_reg(devc, IFA, voice + 1, 0xffff);
	emu10k_write_reg(devc, VEDS, voice + 1, 0x0);
	emu10k_write_reg(devc, VTFT, voice + 1, 0xffff);
	emu10k_write_reg(devc, PTAB, voice + 1, 0x0);

	/* now setup the voices and go! */
	emu10k_setup_voice(portc, voice, LEFT_CH, buf_offset);
	emu10k_setup_voice(portc, voice + 1, RIGHT_CH, buf_offset);

	emu10k_write_routing(devc, voice, routing);
	emu10k_write_routing(devc, voice + 1, routing);
}

void
emu10k_start_play(emu10k_portc_t *portc)
{
	emu10k_devc_t *devc = portc->devc;

	ASSERT(mutex_owned(&devc->mutex));
	emu10k_prepare_voice(devc, 0);
	emu10k_prepare_voice(devc, 1);

	emu10k_prepare_voice(devc, 2);
	emu10k_prepare_voice(devc, 3);

	emu10k_prepare_voice(devc, 4);
	emu10k_prepare_voice(devc, 5);

	emu10k_prepare_voice(devc, 6);
	emu10k_prepare_voice(devc, 7);

	/* Trigger playback on all voices */
	emu10k_write_reg(devc, VEDS, 0, 0x7f7f);
	emu10k_write_reg(devc, VEDS, 1, 0x7f7f);
	emu10k_write_reg(devc, VEDS, 2, 0x7f7f);
	emu10k_write_reg(devc, VEDS, 3, 0x7f7f);
	emu10k_write_reg(devc, VEDS, 4, 0x7f7f);
	emu10k_write_reg(devc, VEDS, 5, 0x7f7f);
	emu10k_write_reg(devc, VEDS, 6, 0x7f7f);
	emu10k_write_reg(devc, VEDS, 7, 0x7f7f);

	portc->active = B_TRUE;
}

void
emu10k_stop_play(emu10k_portc_t *portc)
{
	emu10k_devc_t *devc = portc->devc;

	emu10k_stop_voice(devc, 0);
	emu10k_stop_voice(devc, 1);
	emu10k_stop_voice(devc, 2);
	emu10k_stop_voice(devc, 3);
	emu10k_stop_voice(devc, 4);
	emu10k_stop_voice(devc, 5);
	emu10k_stop_voice(devc, 6);
	emu10k_stop_voice(devc, 7);

	portc->active = B_FALSE;
}

void
emu10k_reset_play(emu10k_portc_t *portc)
{
	emu10k_devc_t *devc = portc->devc;
	uint32_t offs;

	offs = (portc->buf_size / portc->channels) * 2;

	if (devc->feature_mask & SB_71) {
		emu10k_reset_pair(portc, 0, front_routing, 0);
		emu10k_reset_pair(portc, 2, clfe_routing, offs);
		emu10k_reset_pair(portc, 4, surr_routing, 2 * offs);
		emu10k_reset_pair(portc, 6, side_routing, 3 * offs);
	} else if (devc->feature_mask & SB_51) {
		emu10k_reset_pair(portc, 0, front_routing, 0);
		emu10k_reset_pair(portc, 2, clfe_routing, offs);
		emu10k_reset_pair(portc, 4, surr_routing, 2 * offs);
	} else {
		emu10k_reset_pair(portc, 0, front_routing, 0);
		emu10k_reset_pair(portc, 2, surr_routing, offs);
	}

	portc->pos = 0;
}

uint32_t emu10k_vars[5];

void
emu10k_update_play(emu10k_portc_t *portc)
{
	emu10k_devc_t *devc = portc->devc;
	uint32_t cnt, pos;

	/*
	 * Note: position is given as stereo samples, i.e. frames.
	 */
	pos = emu10k_read_reg(devc, QKBCA, 0) & 0xffffff;
	pos -= (portc->memptr >> 2);
	if (pos > portc->nframes) {
		/*
		 * This should never happen!  If it happens, we should
		 * throw an FMA fault.  (When we support FMA.)  For now
		 * we just assume the device is stuck, and report no
		 * change in position.
		 */
		pos = portc->pos;
	}
	ASSERT(pos <= portc->nframes);

	if (pos < portc->pos) {
		cnt = (portc->nframes - portc->pos) + pos;
	} else {
		cnt = (pos - portc->pos);
	}
	ASSERT(cnt <= portc->nframes);
	if (portc->dopos) {
		emu10k_vars[0] = portc->pos;
		emu10k_vars[1] = pos;
		emu10k_vars[2] = (uint32_t)portc->count;
		emu10k_vars[3] = cnt;
		portc->dopos = 0;
	}
	portc->count += cnt;
	portc->pos = pos;
}

void
emu10k_start_rec(emu10k_portc_t *portc)
{
	emu10k_devc_t *devc = portc->devc;
	uint32_t tmp;

	tmp = 0;			/* setup 48Kz */
	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL))
		tmp |= 0x30;		/* Left/right channel enable */
	else
		tmp |= 0x18;		/* Left/right channel enable */
	emu10k_write_reg(devc, ADCSR, 0, tmp);	/* GO */

	portc->active = B_TRUE;
}

void
emu10k_stop_rec(emu10k_portc_t *portc)
{
	emu10k_devc_t *devc = portc->devc;

	ASSERT(mutex_owned(&devc->mutex));
	emu10k_write_reg(devc, ADCSR, 0, 0);

	portc->active = B_FALSE;
}
void
emu10k_reset_rec(emu10k_portc_t *portc)
{
	emu10k_devc_t *devc = portc->devc;
	uint32_t sz;

	switch (portc->buf_size) {
	case 4096:
		sz = 15;
		break;
	case 8192:
		sz = 19;
		break;
	case 16384:
		sz = 23;
		break;
	case 32768:
		sz = 27;
		break;
	case 65536:
		sz = 31;
		break;
	}
	emu10k_write_reg(devc, ADCBA, 0, portc->buf_paddr);
	emu10k_write_reg(devc, ADCBS, 0, sz);
	emu10k_write_reg(devc, ADCSR, 0, 0);	/* reset for phase */
	portc->pos = 0;
}

void
emu10k_update_rec(emu10k_portc_t *portc)
{
	emu10k_devc_t *devc = portc->devc;
	uint32_t cnt, pos;

	/* given in bytes, we divide all counts by 4 to get samples */
	pos = emu10k_read_reg(devc,
	    (devc->feature_mask & SB_LIVE) ? MIDX : ADCIDX, 0);
	if (pos <= portc->pos) {
		cnt = ((portc->buf_size) - portc->pos) >> 2;
		cnt += (pos >> 2);
	} else {
		cnt = ((pos - portc->pos) >> 2);
	}
	portc->count += cnt;
	portc->pos = pos;
}

int
emu10k_alloc_port(emu10k_devc_t *devc, int num)
{
	emu10k_portc_t *portc;
	size_t len;
	ddi_dma_cookie_t cookie;
	uint_t count;
	int dir;
	unsigned caps;
	audio_dev_t *adev;
	int i, n;

	adev = devc->adev;
	portc = kmem_zalloc(sizeof (*portc), KM_SLEEP);
	devc->portc[num] = portc;
	portc->devc = devc;

	portc->memptr = devc->audio_memptr;
	devc->audio_memptr += (DMABUF_SIZE + 4095) & ~4095;

	switch (num) {
	case EMU10K_REC:
		portc->syncdir = DDI_DMA_SYNC_FORKERNEL;
		caps = ENGINE_INPUT_CAP;
		dir = DDI_DMA_READ;
		portc->channels = 2;
		portc->start_port = emu10k_start_rec;
		portc->stop_port = emu10k_stop_rec;
		portc->reset_port = emu10k_reset_rec;
		portc->update_port = emu10k_update_rec;
		/* This is the minimum record buffer size. */
		portc->buf_size = 4096;
		portc->nframes = portc->buf_size / 4;
		break;
	case EMU10K_PLAY:
		portc->syncdir = DDI_DMA_SYNC_FORDEV;
		caps = ENGINE_OUTPUT_CAP;
		dir = DDI_DMA_WRITE;
		portc->channels = 8;
		portc->start_port = emu10k_start_play;
		portc->stop_port = emu10k_stop_play;
		portc->reset_port = emu10k_reset_play;
		portc->update_port = emu10k_update_play;
		/* This could probably be tunable. */
		portc->nframes = 2048;
		portc->buf_size = portc->nframes * portc->channels * 2;
		break;
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Fragments that are not powers of two don't seem to work
	 * at all with EMU10K.  For simplicity's sake, we eliminate
	 * the question and fix the interrupt rate.  This is also the
	 * logical minimum for record, which requires at least 4K for
	 * the record size.
	 */

	if (portc->buf_size > DMABUF_SIZE) {
		cmn_err(CE_NOTE, "Buffer size %d is too large (max %d)",
		    (int)portc->buf_size, DMABUF_SIZE);
		portc->buf_size = DMABUF_SIZE;
	}

	/* Alloc buffers */
	if (ddi_dma_alloc_handle(devc->dip, &dma_attr_buf, DDI_DMA_SLEEP, NULL,
	    &portc->buf_dmah) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate BUF handle");
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(portc->buf_dmah, portc->buf_size,
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &portc->buf_kaddr, &len, &portc->buf_acch) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate BUF memory");
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(portc->buf_dmah, NULL, portc->buf_kaddr,
	    len, DDI_DMA_CONSISTENT | dir, DDI_DMA_SLEEP,
	    NULL, &cookie, &count) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed binding BUF DMA handle");
		return (DDI_FAILURE);
	}
	portc->buf_paddr = cookie.dmac_address;

	if ((devc->feature_mask & SB_LIVE) &&
	    (portc->buf_paddr & 0x80000000)) {
		audio_dev_warn(adev, "Got DMA buffer beyond 2G limit.");
		return (DDI_FAILURE);
	}

	if (num == EMU10K_PLAY) {	/* Output device */
		n = portc->memptr / 4096;
		/*
		 * Fill the page table
		 */
		for (i = 0; i < portc->buf_size / 4096; i++) {
			FILL_PAGE_MAP_ENTRY(n + i,
			    portc->buf_paddr + i * 4096);
		}

		(void) ddi_dma_sync(devc->pt_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	}

	portc->engine = audio_engine_alloc(&emu10k_engine_ops, caps);
	if (portc->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(portc->engine, portc);
	audio_dev_add_engine(adev, portc->engine);

	return (DDI_SUCCESS);
}

void
emu10k_destroy(emu10k_devc_t *devc)
{
	mutex_destroy(&devc->mutex);

	if (devc->silence_paddr) {
		(void) ddi_dma_unbind_handle(devc->silence_dmah);
	}
	if (devc->silence_acch) {
		ddi_dma_mem_free(&devc->silence_acch);
	}
	if (devc->silence_dmah) {
		ddi_dma_free_handle(&devc->silence_dmah);
	}

	if (devc->pt_paddr) {
		(void) ddi_dma_unbind_handle(devc->pt_dmah);
	}
	if (devc->pt_acch) {
		ddi_dma_mem_free(&devc->pt_acch);
	}
	if (devc->pt_dmah) {
		ddi_dma_free_handle(&devc->pt_dmah);
	}


	for (int i = 0; i < CTL_MAX; i++) {
		emu10k_ctrl_t *ec = &devc->ctrls[i];
		if (ec->ctrl != NULL) {
			audio_dev_del_control(ec->ctrl);
			ec->ctrl = NULL;
		}
	}

	for (int i = 0; i < EMU10K_NUM_PORTC; i++) {
		emu10k_portc_t *portc = devc->portc[i];
		if (!portc)
			continue;
		if (portc->engine) {
			audio_dev_remove_engine(devc->adev, portc->engine);
			audio_engine_free(portc->engine);
		}
		if (portc->buf_paddr) {
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

	if (devc->ac97 != NULL) {
		ac97_free(devc->ac97);
	}
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

static void
emu10k_init_voice(emu10k_devc_t *devc, int voice)
{
	emu10k_set_loop_stop(devc, voice, 1);

	emu10k_write_reg(devc, VEDS, voice, 0x0);
	emu10k_write_reg(devc, IP, voice, 0x0);
	emu10k_write_reg(devc, VTFT, voice, 0xffff);
	emu10k_write_reg(devc, CVCF, voice, 0xffff);
	emu10k_write_reg(devc, PTAB, voice, 0x0);
	emu10k_write_reg(devc, CPF, voice, 0x0);
	emu10k_write_reg(devc, CCR, voice, 0x0);
	emu10k_write_reg(devc, SCSA, voice, 0x0);
	emu10k_write_reg(devc, SDL, voice, 0x10);
	emu10k_write_reg(devc, QKBCA, voice, 0x0);
	emu10k_write_reg(devc, Z1, voice, 0x0);
	emu10k_write_reg(devc, Z2, voice, 0x0);

	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL))
		emu10k_write_reg(devc, SRDA, voice, 0x03020100);
	else
		emu10k_write_reg(devc, FXRT, voice, 0x32100000);

	emu10k_write_reg(devc, MEHA, voice, 0x0);
	emu10k_write_reg(devc, MEDS, voice, 0x0);
	emu10k_write_reg(devc, IFA, voice, 0xffff);
	emu10k_write_reg(devc, PEFE, voice, 0x0);
	emu10k_write_reg(devc, VFM, voice, 0x0);
	emu10k_write_reg(devc, TMFQ, voice, 24);
	emu10k_write_reg(devc, VVFQ, voice, 24);
	emu10k_write_reg(devc, TMPE, voice, 0x0);
	emu10k_write_reg(devc, VLV, voice, 0x0);
	emu10k_write_reg(devc, MLV, voice, 0x0);
	emu10k_write_reg(devc, VEHA, voice, 0x0);
	emu10k_write_reg(devc, VEV, voice, 0x0);
	emu10k_write_reg(devc, MEV, voice, 0x0);

	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) {
		emu10k_write_reg(devc, CSBA, voice, 0x0);
		emu10k_write_reg(devc, CSDC, voice, 0x0);
		emu10k_write_reg(devc, CSFE, voice, 0x0);
		emu10k_write_reg(devc, CSHG, voice, 0x0);
		emu10k_write_reg(devc, SRHE, voice, 0x3f3f3f3f);
	}
}

int
emu10k_hwinit(emu10k_devc_t *devc)
{

	unsigned int tmp, i;
	unsigned int reg;

	ASSERT(mutex_owned(&devc->mutex));

	emu10k_write_reg(devc, AC97SLOT, 0, AC97SLOT_CENTER | AC97SLOT_LFE);

	OUTL(devc, 0x00000000, devc->regs + 0x0c);	/* Intr disable */
	OUTL(devc, HCFG_LOCKSOUNDCACHE | HCFG_LOCKTANKCACHE_MASK |
	    HCFG_MUTEBUTTONENABLE,
	    devc->regs + HCFG);

	emu10k_write_reg(devc, MBS, 0, 0x0);
	emu10k_write_reg(devc, MBA, 0, 0x0);
	emu10k_write_reg(devc, FXBS, 0, 0x0);
	emu10k_write_reg(devc, FXBA, 0, 0x0);
	emu10k_write_reg(devc, ADCBS, 0, 0x0);
	emu10k_write_reg(devc, ADCBA, 0, 0x0);

	/* Ensure all interrupts are disabled */
	OUTL(devc, 0, devc->regs + IE);
	emu10k_write_reg(devc, CLIEL, 0, 0x0);
	emu10k_write_reg(devc, CLIEH, 0, 0x0);
	if (!(devc->feature_mask & SB_LIVE)) {
		emu10k_write_reg(devc, HLIEL, 0, 0x0);
		emu10k_write_reg(devc, HLIEH, 0, 0x0);
	}
	emu10k_write_reg(devc, CLIPL, 0, 0xffffffff);
	emu10k_write_reg(devc, CLIPH, 0, 0xffffffff);
	emu10k_write_reg(devc, SOLL, 0, 0xffffffff);
	emu10k_write_reg(devc, SOLH, 0, 0xffffffff);


	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) {
		emu10k_write_reg(devc, SOC, 0, 0xf00);	/* ?? */
		emu10k_write_reg(devc, AC97SLOT, 0, 0x3);	/* ?? */
	}

	for (i = 0; i < 64; i++)
		emu10k_init_voice(devc, i);

	emu10k_write_reg(devc, SCS0, 0, 0x2109204);
	emu10k_write_reg(devc, SCS1, 0, 0x2109204);
	emu10k_write_reg(devc, SCS2, 0, 0x2109204);

	emu10k_write_reg(devc, PTBA, 0, devc->pt_paddr);
	tmp = emu10k_read_reg(devc, PTBA, 0);

	emu10k_write_reg(devc, TCBA, 0, 0x0);
	emu10k_write_reg(devc, TCBS, 0, 0x4);

	reg = 0;
	if (devc->feature_mask & SB_71) {
		reg = AC97SLOT_CENTER | AC97SLOT_LFE | AC97SLOT_REAR_LEFT |
		    AC97SLOT_REAR_RIGHT;
	} else if (devc->feature_mask & SB_51) {
		reg = AC97SLOT_CENTER | AC97SLOT_LFE;
	}
	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL))
		reg |= 0x40;
	emu10k_write_reg(devc, AC97SLOT, 0, reg);

	if (devc->feature_mask & SB_AUDIGY2) {
		/* Enable analog outputs on Audigy2 */
		int tmp;

		/* Setup SRCMulti_I2S SamplingRate */
		tmp = emu10k_read_reg(devc, EHC, 0);
		tmp &= 0xfffff1ff;
		tmp |= (0x2 << 9);
		emu10k_write_reg(devc, EHC, 0, tmp);
		/* emu10k_write_reg (devc, SOC, 0, 0x00000000); */

		/* Setup SRCSel (Enable Spdif,I2S SRCMulti) */
		OUTL(devc, 0x600000, devc->regs + 0x20);
		OUTL(devc, 0x14, devc->regs + 0x24);

		/* Setup SRCMulti Input Audio Enable */
		OUTL(devc, 0x6E0000, devc->regs + 0x20);

		OUTL(devc, 0xFF00FF00, devc->regs + 0x24);

		/* Setup I2S ASRC Enable  (HC register) */
		tmp = INL(devc, devc->regs + HCFG);
		tmp |= 0x00000070;
		OUTL(devc, tmp, devc->regs + HCFG);

		/*
		 * Unmute Analog now.  Set GPO6 to 1 for Apollo.
		 * This has to be done after init ALice3 I2SOut beyond 48KHz.
		 * So, sequence is important
		 */
		tmp = INL(devc, devc->regs + 0x18);
		tmp |= 0x0040;

		OUTL(devc, tmp, devc->regs + 0x18);
	}

	if (devc->feature_mask & SB_AUDIGY2VAL) {
		/* Enable analog outputs on Audigy2 */
		int tmp;

		/* Setup SRCMulti_I2S SamplingRate */
		tmp = emu10k_read_reg(devc, EHC, 0);
		tmp &= 0xfffff1ff;
		tmp |= (0x2 << 9);
		emu10k_write_reg(devc, EHC, 0, tmp);

		/* Setup SRCSel (Enable Spdif,I2S SRCMulti) */
		OUTL(devc, 0x600000, devc->regs + 0x20);
		OUTL(devc, 0x14, devc->regs + 0x24);

		/* Setup SRCMulti Input Audio Enable */
		OUTL(devc, 0x7B0000, devc->regs + 0x20);
		OUTL(devc, 0xFF000000, devc->regs + 0x24);

		/* SPDIF output enable */
		OUTL(devc, 0x7A0000, devc->regs + 0x20);
		OUTL(devc, 0xFF000000, devc->regs + 0x24);

		tmp = INL(devc, devc->regs + 0x18) & ~0x8;
		OUTL(devc, tmp, devc->regs + 0x18);
	}

	emu10k_write_reg(devc, SOLL, 0, 0xffffffff);
	emu10k_write_reg(devc, SOLH, 0, 0xffffffff);

	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) {
		unsigned int mode = 0;

		if (devc->feature_mask & (SB_AUDIGY2|SB_AUDIGY2VAL))
			mode |= HCFG_AC3ENABLE_GPSPDIF | HCFG_AC3ENABLE_CDSPDIF;
		OUTL(devc,
		    HCFG_AUDIOENABLE | HCFG_AUTOMUTE |
		    HCFG_JOYENABLE | A_HCFG_VMUTE |
		    A_HCFG_AUTOMUTE | mode, devc->regs + HCFG);

		OUTL(devc, INL(devc, devc->regs + 0x18) |
		    0x0004, devc->regs + 0x18);	/* GPIO (S/PDIF enable) */


		/* enable IR port */
		tmp = INL(devc, devc->regs + 0x18);
		OUTL(devc, tmp | A_IOCFG_GPOUT2, devc->regs + 0x18);
		drv_usecwait(500);
		OUTL(devc, tmp | A_IOCFG_GPOUT1 | A_IOCFG_GPOUT2,
		    devc->regs + 0x18);
		drv_usecwait(100);
		OUTL(devc, tmp, devc->regs + 0x18);
	} else {
		OUTL(devc,
		    HCFG_AUDIOENABLE | HCFG_LOCKTANKCACHE_MASK |
		    HCFG_AUTOMUTE | HCFG_JOYENABLE, devc->regs + HCFG);
	}


	/* enable IR port */
	tmp = INL(devc, devc->regs + HCFG);
	OUTL(devc, tmp | HCFG_GPOUT2, devc->regs + HCFG);
	drv_usecwait(500);
	OUTL(devc, tmp | HCFG_GPOUT1 | HCFG_GPOUT2, devc->regs + HCFG);
	drv_usecwait(100);
	OUTL(devc, tmp, devc->regs + HCFG);


	/*
	 * Start by configuring for analog mode.
	 */
	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) {
		reg = INL(devc, devc->regs + 0x18) & ~A_IOCFG_GPOUT0;
		reg |= ((devc->feature_mask & SB_INVSP) ? 0x4 : 0);
		OUTL(devc, reg, devc->regs + 0x18);
	}
	if (devc->feature_mask & SB_LIVE) {	/* SBLIVE */
		reg = INL(devc, devc->regs + HCFG) & ~HCFG_GPOUT0;
		reg |= ((devc->feature_mask & SB_INVSP) ? HCFG_GPOUT0 : 0);
		OUTL(devc, reg, devc->regs + HCFG);
	}

	if (devc->feature_mask & SB_AUDIGY2VAL) {
		OUTL(devc, INL(devc, devc->regs + 0x18) | 0x0060,
		    devc->regs + 0x18);
	} else if (devc->feature_mask & SB_AUDIGY2) {
		OUTL(devc, INL(devc, devc->regs + 0x18) | 0x0040,
		    devc->regs + 0x18);
	} else if (devc->feature_mask & SB_AUDIGY) {
		OUTL(devc, INL(devc, devc->regs + 0x18) | 0x0080,
		    devc->regs + 0x18);
	}

	emu10k_init_effects(devc);

	return (DDI_SUCCESS);
}

static const int db2lin_101[101] = {
	0x00000000,
	0x0024B53A, 0x002750CA, 0x002A1BC6, 0x002D198D, 0x00304DBA, 0x0033BC2A,
	0x00376901, 0x003B58AF, 0x003F8FF1, 0x004413DF, 0x0048E9EA, 0x004E17E9,
	0x0053A419, 0x0059952C, 0x005FF24E, 0x0066C32A, 0x006E0FFB, 0x0075E18D,
	0x007E414F, 0x0087395B, 0x0090D482, 0x009B1E5B, 0x00A6234F, 0x00B1F0A7,
	0x00BE94A1, 0x00CC1E7C, 0x00DA9E8D, 0x00EA2650, 0x00FAC881, 0x010C9931,
	0x011FADDC, 0x01341D87, 0x014A00D8, 0x01617235, 0x017A8DE6, 0x01957233,
	0x01B23F8D, 0x01D118B1, 0x01F222D4, 0x021585D1, 0x023B6C57, 0x0264041D,
	0x028F7E19, 0x02BE0EBD, 0x02EFEE33, 0x032558A2, 0x035E8E7A, 0x039BD4BC,
	0x03DD7551, 0x0423BF61, 0x046F07B5, 0x04BFA91B, 0x051604D5, 0x0572830D,
	0x05D59354, 0x063FAD27, 0x06B15080, 0x072B0673, 0x07AD61CD, 0x0838FFCA,
	0x08CE88D3, 0x096EB147, 0x0A1A3A53, 0x0AD1F2E0, 0x0B96B889, 0x0C6978A5,
	0x0D4B316A, 0x0E3CF31B, 0x0F3FE155, 0x10553469, 0x117E3AD9, 0x12BC5AEA,
	0x14111457, 0x157E0219, 0x1704DC5E, 0x18A77A97, 0x1A67D5B6, 0x1C480A87,
	0x1E4A5C45, 0x2071374D, 0x22BF3412, 0x25371A37, 0x27DBE3EF, 0x2AB0C18F,
	0x2DB91D6F, 0x30F89FFD, 0x34733433, 0x382D0C46, 0x3C2AA6BD, 0x4070D3D9,
	0x4504BB66, 0x49EBE2F1, 0x4F2C346F, 0x54CC0565, 0x5AD21E86, 0x6145C3E7,
	0x682EBDBD, 0x6F9561C4, 0x77829D4D,
	0x7fffffff
};

static int
emu10k_convert_fixpoint(int val)
{
	if (val < 0)
		val = 0;
	if (val > 100)
		val = 100;
	return (db2lin_101[val]);
}

static void
emu10k_write_gpr(emu10k_devc_t *devc, int gpr, uint32_t value)
{
	ASSERT(gpr < MAX_GPR);
	devc->gpr_shadow[gpr].valid = B_TRUE;
	devc->gpr_shadow[gpr].value = value;
	emu10k_write_reg(devc, gpr + GPR0, 0, value);
}

static int
emu10k_set_stereo(void *arg, uint64_t val)
{
	emu10k_ctrl_t *ec = arg;
	emu10k_devc_t *devc = ec->devc;
	uint32_t left, right;

	left = (val >> 8) & 0xff;
	right = val & 0xff;
	if ((left > 100) || (right > 100) || (val & ~(0xffff)))
		return (EINVAL);

	left = emu10k_convert_fixpoint(left);
	right = emu10k_convert_fixpoint(right);

	mutex_enter(&devc->mutex);
	ec->val = val;

	emu10k_write_gpr(devc, ec->gpr_num, left);
	emu10k_write_gpr(devc, ec->gpr_num + 1, right);

	mutex_exit(&devc->mutex);
	return (0);
}

static int
emu10k_set_mono(void *arg, uint64_t val)
{
	emu10k_ctrl_t *ec = arg;
	emu10k_devc_t *devc = ec->devc;
	uint32_t v;

	if (val > 100)
		return (EINVAL);

	v = emu10k_convert_fixpoint(val & 0xff);

	mutex_enter(&devc->mutex);
	ec->val = val;
	emu10k_write_gpr(devc, ec->gpr_num, v);
	mutex_exit(&devc->mutex);
	return (0);
}

static int
emu10k_get_control(void *arg, uint64_t *val)
{
	emu10k_ctrl_t *ec = arg;
	emu10k_devc_t *devc = ec->devc;

	mutex_enter(&devc->mutex);
	*val = ec->val;
	mutex_exit(&devc->mutex);
	return (0);
}

#define	PLAYCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_PLAY)
#define	RECCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_REC)
#define	MONCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_MONITOR)
#define	MAINVOL	(PLAYCTL | AUDIO_CTRL_FLAG_MAINVOL)
#define	PCMVOL	(PLAYCTL | AUDIO_CTRL_FLAG_PCMVOL)
#define	RECVOL	(RECCTL | AUDIO_CTRL_FLAG_RECVOL)
#define	MONVOL	(MONCTL | AUDIO_CTRL_FLAG_MONVOL)

static int
emu10k_get_ac97src(void *arg, uint64_t *valp)
{
	ac97_ctrl_t *ctrl = arg;

	return (ac97_control_get(ctrl, valp));
}

static int
emu10k_set_ac97src(void *arg, uint64_t value)
{
	ac97_ctrl_t	*ctrl = arg;

	return (ac97_control_set(ctrl, value));
}

static int
emu10k_set_jack3(void *arg, uint64_t value)
{
	emu10k_ctrl_t	*ec = arg;
	emu10k_devc_t	*devc = ec->devc;
	uint32_t	set_val;
	uint32_t	val;

	set_val = ddi_ffs(value & 0xffffffffU);
	set_val--;
	mutex_enter(&devc->mutex);
	switch (set_val) {
	case 0:
	case 1:
		break;
	default:
		mutex_exit(&devc->mutex);
		return (EINVAL);
	}
	ec->val = value;
	/* center/lfe */
	if (devc->feature_mask & SB_INVSP) {
		set_val = !set_val;
	}
	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) {
		val = INL(devc, devc->regs + 0x18);
		val &= ~A_IOCFG_GPOUT0;
		val |= set_val ? 0x44 : 0x40;
		OUTL(devc, val, devc->regs + 0x18);

	} else if (devc->feature_mask & SB_LIVE) {
		val = INL(devc, devc->regs + HCFG);
		val &= ~HCFG_GPOUT0;
		val |= set_val ? HCFG_GPOUT0 : 0;
		OUTL(devc, val, devc->regs + HCFG);
	}
	mutex_exit(&devc->mutex);
	return (0);
}

static int
emu10k_set_recsrc(void *arg, uint64_t value)
{
	emu10k_ctrl_t	*ec = arg;
	emu10k_devc_t	*devc = ec->devc;
	uint32_t	set_val;

	set_val = ddi_ffs(value & 0xffffffffU);
	set_val--;

	/*
	 * We start assuming well set up AC'97 for stereomix recording.
	 */
	switch (set_val) {
	case INPUT_AC97:
	case INPUT_SPD1:
	case INPUT_SPD2:
	case INPUT_DIGCD:
	case INPUT_AUX2:
	case INPUT_LINE2:
	case INPUT_STEREOMIX:
		break;
	default:
		return (EINVAL);
	}

	mutex_enter(&devc->mutex);
	ec->val = value;

	emu10k_write_gpr(devc, GPR_REC_AC97, (set_val == INPUT_AC97));
	emu10k_write_gpr(devc, GPR_REC_SPDIF1, (set_val == INPUT_SPD1));
	emu10k_write_gpr(devc, GPR_REC_SPDIF2, (set_val == INPUT_SPD2));
	emu10k_write_gpr(devc, GPR_REC_DIGCD, (set_val == INPUT_DIGCD));
	emu10k_write_gpr(devc, GPR_REC_AUX2, (set_val == INPUT_AUX2));
	emu10k_write_gpr(devc, GPR_REC_LINE2, (set_val == INPUT_LINE2));
	emu10k_write_gpr(devc, GPR_REC_PCM, (set_val == INPUT_STEREOMIX));

	mutex_exit(&devc->mutex);

	return (0);
}

static void
emu10k_create_stereo(emu10k_devc_t *devc, int ctl, int gpr,
    const char *id, int flags, int defval)
{
	emu10k_ctrl_t *ec;
	audio_ctrl_desc_t desc;

	bzero(&desc, sizeof (desc));

	ec = &devc->ctrls[ctl];
	ec->devc = devc;
	ec->gpr_num = gpr;

	desc.acd_name = id;
	desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
	desc.acd_minvalue = 0;
	desc.acd_maxvalue = 100;
	desc.acd_flags = flags;

	ec->val = (defval << 8) | defval;
	ec->ctrl = audio_dev_add_control(devc->adev, &desc,
	    emu10k_get_control, emu10k_set_stereo, ec);

	mutex_enter(&devc->mutex);
	emu10k_write_gpr(devc, gpr, emu10k_convert_fixpoint(defval));
	emu10k_write_gpr(devc, gpr + 1, emu10k_convert_fixpoint(defval));
	mutex_exit(&devc->mutex);
}

static void
emu10k_create_mono(emu10k_devc_t *devc, int ctl, int gpr,
    const char *id, int flags, int defval)
{
	emu10k_ctrl_t *ec;
	audio_ctrl_desc_t desc;

	bzero(&desc, sizeof (desc));

	ec = &devc->ctrls[ctl];
	ec->devc = devc;
	ec->gpr_num = gpr;

	desc.acd_name = id;
	desc.acd_type = AUDIO_CTRL_TYPE_MONO;
	desc.acd_minvalue = 0;
	desc.acd_maxvalue = 100;
	desc.acd_flags = flags;

	ec->val = defval;
	ec->ctrl = audio_dev_add_control(devc->adev, &desc,
	    emu10k_get_control, emu10k_set_mono, ec);

	mutex_enter(&devc->mutex);
	emu10k_write_gpr(devc, gpr, emu10k_convert_fixpoint(defval));
	mutex_exit(&devc->mutex);
}

/*
 * AC'97 source.  The AC'97 PCM record channel is routed to our
 * mixer.  While we could support the direct monitoring capability of
 * the AC'97 part itself, this would not work correctly with outputs
 * that are not routed via AC'97 (such as the Live Drive headphones
 * or digital outputs.)  So we just offer the ability to select one
 * AC'97 source, and then offer independent ability to either monitor
 * or record from the AC'97 mixer's PCM record channel.
 */
static void
emu10k_create_ac97src(emu10k_devc_t *devc)
{
	emu10k_ctrl_t *ec;
	audio_ctrl_desc_t desc;
	ac97_ctrl_t *ac;
	const audio_ctrl_desc_t *acd;

	bzero(&desc, sizeof (desc));

	ec = &devc->ctrls[CTL_AC97SRC];
	desc.acd_name = "ac97-source";
	desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
	desc.acd_flags = RECCTL;
	ec->devc = devc;
	ac = ac97_control_find(devc->ac97, AUDIO_CTRL_ID_RECSRC);
	if (ac == NULL) {
		return;
	}

	acd = ac97_control_desc(ac);

	for (int i = 0; i < 64; i++) {
		const char *n;
		if (((acd->acd_minvalue & (1ULL << i)) == 0) ||
		    ((n = acd->acd_enum[i]) == NULL)) {
			continue;
		}
		desc.acd_enum[i] = acd->acd_enum[i];
		/* we suppress some port options */
		if ((strcmp(n, AUDIO_PORT_STEREOMIX) == 0) ||
		    (strcmp(n, AUDIO_PORT_MONOMIX) == 0) ||
		    (strcmp(n, AUDIO_PORT_VIDEO) == 0)) {
			continue;
		}
		desc.acd_minvalue |= (1ULL << i);
		desc.acd_maxvalue |= (1ULL << i);
	}

	ec->ctrl = audio_dev_add_control(devc->adev, &desc,
	    emu10k_get_ac97src, emu10k_set_ac97src, ac);
}

/*
 * Record source... this one is tricky.  While the chip will
 * conceivably let us *mix* some of the audio streams for recording,
 * the AC'97 inputs don't have this capability.  Offering it to users
 * is likely to be confusing, so we offer a single record source
 * selection option.  Its not ideal, but it ought to be good enough
 * for the vast majority of users.
 */
static void
emu10k_create_recsrc(emu10k_devc_t *devc)
{
	emu10k_ctrl_t *ec;
	audio_ctrl_desc_t desc;
	ac97_ctrl_t *ac;

	bzero(&desc, sizeof (desc));

	ec = &devc->ctrls[CTL_RECSRC];
	desc.acd_name = AUDIO_CTRL_ID_RECSRC;
	desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
	desc.acd_flags = RECCTL;
	desc.acd_minvalue = 0;
	desc.acd_maxvalue = 0;
	bzero(desc.acd_enum, sizeof (desc.acd_enum));
	ec->devc = devc;
	ac = ac97_control_find(devc->ac97, AUDIO_CTRL_ID_RECSRC);

	/* only low order bits set by AC'97 */
	ASSERT(desc.acd_minvalue == desc.acd_maxvalue);
	ASSERT((desc.acd_minvalue & ~0xffff) == 0);

	/*
	 * It would be really cool if we could detect whether these
	 * options are all sensible on a given configuration.  Units
	 * without live-drive support, and units without a physical
	 * live-drive, simply can't do all these.
	 */
	if (ac != NULL) {
		desc.acd_minvalue |= (1 << INPUT_AC97);
		desc.acd_maxvalue |= (1 << INPUT_AC97);
		desc.acd_enum[INPUT_AC97] = "ac97";
		ec->val = (1 << INPUT_AC97);
	} else {
		/* next best guess */
		ec->val = (1 << INPUT_LINE2);
	}

	desc.acd_minvalue |= (1 << INPUT_SPD1);
	desc.acd_maxvalue |= (1 << INPUT_SPD1);
	desc.acd_enum[INPUT_SPD1] = AUDIO_PORT_SPDIFIN;

	desc.acd_minvalue |= (1 << INPUT_SPD2);
	desc.acd_maxvalue |= (1 << INPUT_SPD2);
	desc.acd_enum[INPUT_SPD2] = "spdif2-in";

	desc.acd_minvalue |= (1 << INPUT_DIGCD);
	desc.acd_maxvalue |= (1 << INPUT_DIGCD);
	desc.acd_enum[INPUT_DIGCD] = "digital-cd";

	desc.acd_minvalue |= (1 << INPUT_AUX2);
	desc.acd_maxvalue |= (1 << INPUT_AUX2);
	desc.acd_enum[INPUT_AUX2] = AUDIO_PORT_AUX2IN;

	desc.acd_minvalue |= (1 << INPUT_LINE2);
	desc.acd_maxvalue |= (1 << INPUT_LINE2);
	desc.acd_enum[INPUT_LINE2] = "line2-in";

	desc.acd_minvalue |= (1 << INPUT_STEREOMIX);
	desc.acd_maxvalue |= (1 << INPUT_STEREOMIX);
	desc.acd_enum[INPUT_STEREOMIX] = AUDIO_PORT_STEREOMIX;

	emu10k_write_gpr(devc, GPR_REC_SPDIF1, 0);
	emu10k_write_gpr(devc, GPR_REC_SPDIF2, 0);
	emu10k_write_gpr(devc, GPR_REC_DIGCD, 0);
	emu10k_write_gpr(devc, GPR_REC_AUX2, 0);
	emu10k_write_gpr(devc, GPR_REC_LINE2, 0);
	emu10k_write_gpr(devc, GPR_REC_PCM, 0);
	emu10k_write_gpr(devc, GPR_REC_AC97, 1);

	ec->ctrl = audio_dev_add_control(devc->adev, &desc,
	    emu10k_get_control, emu10k_set_recsrc, ec);
}

static void
emu10k_create_jack3(emu10k_devc_t *devc)
{
	emu10k_ctrl_t *ec;
	audio_ctrl_desc_t desc;

	bzero(&desc, sizeof (desc));

	ec = &devc->ctrls[CTL_JACK3];
	desc.acd_name = AUDIO_CTRL_ID_JACK3;
	desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
	desc.acd_flags = AUDIO_CTRL_FLAG_RW;
	desc.acd_minvalue = 0x3;
	desc.acd_maxvalue = 0x3;
	bzero(desc.acd_enum, sizeof (desc.acd_enum));
	ec->devc = devc;
	ec->val = 0x1;

	desc.acd_enum[0] = AUDIO_PORT_CENLFE;
	desc.acd_enum[1] = AUDIO_PORT_SPDIFOUT;

	ec->ctrl = audio_dev_add_control(devc->adev, &desc,
	    emu10k_get_control, emu10k_set_jack3, ec);
}


static void
emu10k_create_controls(emu10k_devc_t *devc)
{
	ac97_t		*ac97;
	ac97_ctrl_t	*ac;

	emu10k_create_mono(devc, CTL_VOLUME, GPR_VOL_PCM,
	    AUDIO_CTRL_ID_VOLUME, PCMVOL, 75);

	emu10k_create_stereo(devc, CTL_FRONT, GPR_VOL_FRONT,
	    AUDIO_CTRL_ID_FRONT, MAINVOL, 100);
	emu10k_create_stereo(devc, CTL_SURROUND, GPR_VOL_SURR,
	    AUDIO_CTRL_ID_SURROUND, MAINVOL, 100);
	if (devc->feature_mask & (SB_51 | SB_71)) {
		emu10k_create_mono(devc, CTL_CENTER, GPR_VOL_CEN,
		    AUDIO_CTRL_ID_CENTER, MAINVOL, 100);
		emu10k_create_mono(devc, CTL_LFE, GPR_VOL_LFE,
		    AUDIO_CTRL_ID_LFE, MAINVOL, 100);
	}
	if (devc->feature_mask & SB_71) {
		emu10k_create_stereo(devc, CTL_SIDE, GPR_VOL_SIDE,
		    "side", MAINVOL, 100);
	}

	emu10k_create_stereo(devc, CTL_RECGAIN, GPR_VOL_REC,
	    AUDIO_CTRL_ID_RECGAIN, RECVOL, 50);

	emu10k_create_ac97src(devc);
	emu10k_create_recsrc(devc);
	/*
	 * 5.1 devices have versa jack.  Note that from what we can
	 * tell, none of the 7.1 devices have or need this versa jack,
	 * as they all seem to have a dedicated digital I/O port.
	 */
	if ((devc->feature_mask & SB_51) &&
	    !(devc->feature_mask & SB_AUDIGY2VAL)) {
		emu10k_create_jack3(devc);
	}

	/* these ones AC'97 can manage directly */
	ac97 = devc->ac97;

	if ((ac = ac97_control_find(ac97, AUDIO_CTRL_ID_MICBOOST)) != NULL)
		ac97_control_register(ac);
	if ((ac = ac97_control_find(ac97, AUDIO_CTRL_ID_MICGAIN)) != NULL)
		ac97_control_register(ac);

	/* set any AC'97 analog outputs to full volume (no attenuation) */
	if ((ac = ac97_control_find(ac97, AUDIO_CTRL_ID_FRONT)) != NULL)
		(void) ac97_control_set(ac, (100 << 8) | 100);
	if ((ac = ac97_control_find(ac97, AUDIO_CTRL_ID_LINEOUT)) != NULL)
		(void) ac97_control_set(ac, (100 << 8) | 100);
	if ((ac = ac97_control_find(ac97, AUDIO_CTRL_ID_SURROUND)) != NULL)
		(void) ac97_control_set(ac, (100 << 8) | 100);
	if ((ac = ac97_control_find(ac97, AUDIO_CTRL_ID_CENTER)) != NULL)
		(void) ac97_control_set(ac, 100);
	if ((ac = ac97_control_find(ac97, AUDIO_CTRL_ID_LFE)) != NULL)
		(void) ac97_control_set(ac, 100);

	/* Monitor sources */
	emu10k_create_stereo(devc, CTL_AC97, GPR_MON_AC97,
	    "ac97-monitor", MONVOL, 0);
	emu10k_create_stereo(devc, CTL_SPD1, GPR_MON_SPDIF1,
	    AUDIO_PORT_SPDIFIN, MONVOL, 0);
	emu10k_create_stereo(devc, CTL_DIGCD, GPR_MON_DIGCD,
	    "digital-cd", MONVOL, 0);
	emu10k_create_stereo(devc, CTL_SPD1, GPR_MON_SPDIF1,
	    AUDIO_PORT_SPDIFIN, MONVOL, 0);

	if ((devc->feature_mask & SB_NOEXP) == 0) {
		/*
		 * These ports are only available via an external
		 * expansion box.  Don't expose them for cards  that
		 * don't have support for it.
		 */
		emu10k_create_stereo(devc, CTL_HEADPH, GPR_VOL_HEADPH,
		    AUDIO_CTRL_ID_HEADPHONE, MAINVOL, 100);
		emu10k_create_stereo(devc, CTL_SPD2, GPR_MON_SPDIF2,
		    "spdif2-in", MONVOL, 0);
		emu10k_create_stereo(devc, CTL_LINE2, GPR_MON_LINE2,
		    "line2-in", MONVOL, 0);
		emu10k_create_stereo(devc, CTL_AUX2, GPR_MON_AUX2,
		    AUDIO_PORT_AUX2IN, MONVOL, 0);
	}
}

static void
emu10k_load_dsp(emu10k_devc_t *devc, uint32_t *code, int ncode,
    uint32_t *init, int ninit)
{
	int i;

	if (ncode > 1024) {
		audio_dev_warn(devc->adev, "DSP file size too big");
		return;
	}
	if (ninit > MAX_GPR) {
		audio_dev_warn(devc->adev, "Too many inits");
		return;
	}

	/* Upload our DSP code */
	for (i = 0; i < ncode; i++) {
		emu10k_write_efx(devc, UC0 + i, code[i]);
	}

	/* Upload the initialization settings */
	for (i = 0; i < ninit; i += 2) {
		emu10k_write_reg(devc, init[i] + GPR0, 0, init[i + 1]);
	}
}

#define	LIVE_NOP()					\
	emu10k_write_efx(devc, UC0 + (pc * 2), 0x10040);	\
	emu10k_write_efx(devc, UC0 + (pc * 2 + 1), 0x610040);	\
	pc++
#define	LIVE_ACC3(r, a, x, y) /* z=w+x+y */				\
	emu10k_write_efx(devc, UC0 + (pc * 2), (x << 10) | y);		\
	emu10k_write_efx(devc, UC0 + (pc * 2 + 1), (6 << 20) | (r << 10) | a); \
	pc++

#define	AUDIGY_ACC3(r, a, x, y) /* z=w+x+y */				\
	emu10k_write_efx(devc, UC0 + (pc * 2), (x << 12) | y);		\
	emu10k_write_efx(devc, UC0 + (pc * 2+1), (6 << 24) | (r << 12) | a); \
	pc++
#define	AUDIGY_NOP() AUDIGY_ACC3(0xc0, 0xc0, 0xc0, 0xc0)

static void
emu10k_init_effects(emu10k_devc_t *devc)
{
	int i;
	unsigned short pc;

	ASSERT(mutex_owned(&devc->mutex));

	if (devc->feature_mask & (SB_AUDIGY|SB_AUDIGY2|SB_AUDIGY2VAL)) {
		pc = 0;
		for (i = 0; i < 512; i++) {
			AUDIGY_NOP();
		}

		for (i = 0; i < 256; i++)
			emu10k_write_efx(devc, GPR0 + i, 0);
		emu10k_write_reg(devc, AUDIGY_DBG, 0, 0);
		emu10k_load_dsp(devc,
		    emu10k2_code,
		    sizeof (emu10k2_code) / sizeof (emu10k2_code[0]),
		    emu10k2_init,
		    sizeof (emu10k2_init) / sizeof (emu10k2_init[0]));

	} else {
		pc = 0;
		for (i = 0; i < 512; i++) {
			LIVE_NOP();
		}

		for (i = 0; i < 256; i++)
			emu10k_write_efx(devc, GPR0 + i, 0);
		emu10k_write_reg(devc, DBG, 0, 0);
		emu10k_load_dsp(devc,
		    emu10k1_code,
		    sizeof (emu10k1_code) / sizeof (emu10k1_code[0]),
		    emu10k1_init,
		    sizeof (emu10k1_init) / sizeof (emu10k1_init[0]));
	}
}

/* mixer */

static struct {
	uint16_t	devid;
	uint16_t	subid;
	const char	*model;
	const char	*prod;
	unsigned	feature_mask;
} emu10k_cards[] = {
	{ 0x2, 0x0020, "CT4670", "Live! Value", SB_LIVE | SB_NOEXP },
	{ 0x2, 0x0021, "CT4621", "Live!", SB_LIVE },
	{ 0x2, 0x100a, "SB0220", "Live! 5.1 Digital",
	    SB_LIVE | SB_51 | SB_NOEXP },
	{ 0x2, 0x8022, "CT4780", "Live! Value", SB_LIVE },
	{ 0x2, 0x8023, "CT4790", "PCI512", SB_LIVE | SB_NOEXP },
	{ 0x2, 0x8026, "CT4830", "Live! Value", SB_LIVE },
	{ 0x2, 0x8028, "CT4870", "Live! Value", SB_LIVE },
	{ 0x2, 0x8031, "CT4831", "Live! Value", SB_LIVE },
	{ 0x2, 0x8040, "CT4760", "Live!", SB_LIVE },
	{ 0x2, 0x8051, "CT4850", "Live! Value", SB_LIVE },
	{ 0x2, 0x8061, "SB0060", "Live! 5.1", SB_LIVE | SB_51 },
	{ 0x2, 0x8064, "SB0100", "Live! 5.1", SB_LIVE | SB_51 },
	{ 0x2, 0x8065, "SB0220", "Live! 5.1", SB_LIVE | SB_51 },
	{ 0x2, 0x8066, "SB0228", "Live! 5.1", SB_LIVE | SB_51 },
	{ 0x4, 0x0051, "SB0090", "Audigy", SB_AUDIGY | SB_51 },
	{ 0x4, 0x0052, "SB0160", "Audigy ES", SB_AUDIGY | SB_51 },
	{ 0x4, 0x0053, "SB0092", "Audigy", SB_AUDIGY | SB_51 },
	{ 0x4, 0x1002, "SB0240P", "Audigy 2 Platinum",
	    SB_AUDIGY2 | SB_71 | SB_INVSP },
	{ 0x4, 0x1003, "SB0353", "Audigy 2 ZS", SB_AUDIGY2 | SB_71 | SB_INVSP },
	{ 0x4, 0x1005, "SB0280", "Audigy 2 Platinum EX", SB_AUDIGY2 | SB_71 },
	{ 0x4, 0x1007, "SB0240", "Audigy 2", SB_AUDIGY2 | SB_71 },
	{ 0x4, 0x2001, "SB0360", "Audigy 2 ZS", SB_AUDIGY2 | SB_71 | SB_INVSP },
	{ 0x4, 0x2002, "SB0350", "Audigy 2 ZS", SB_AUDIGY2 | SB_71 | SB_INVSP },
	{ 0x4, 0x2006, "SB0350", "Audigy 2", SB_AUDIGY2 | SB_71 | SB_INVSP },
	{ 0x4, 0x2007, "SB0380", "Audigy 4 Pro", SB_AUDIGY2 | SB_71 },
	{ 0x8, 0x1001, "SB0400", "Audigy 2 Value",
	    SB_AUDIGY2VAL | SB_71 | SB_NOEXP },
	{ 0x8, 0x1021, "SB0610", "Audigy 4",
	    SB_AUDIGY2VAL | SB_71 | SB_NOEXP },
	{ 0x8, 0x1024, "SB1550", "Audigy RX",
	    SB_AUDIGY2VAL | SB_71 | SB_NOEXP },
	{ 0x8, 0x2001, "SB0530", "Audigy 2 ZS Notebook",
	    SB_AUDIGY2VAL | SB_71 },
	{ 0, 0, NULL, NULL, 0 },
};

int
emu10k_attach(dev_info_t *dip)
{
	uint16_t pci_command;
	uint16_t subid;
	uint16_t devid;
	emu10k_devc_t *devc;
	ddi_acc_handle_t pcih;
	ddi_dma_cookie_t cookie;
	uint_t count;
	ulong_t len;
	int i;
	const char *name;
	const char *model;
	char namebuf[64];
	int feature_mask;

	devc = kmem_zalloc(sizeof (*devc), KM_SLEEP);
	devc->dip = dip;
	ddi_set_driver_private(dip, devc);

	if ((devc->adev = audio_dev_alloc(dip, 0)) == NULL) {
		cmn_err(CE_WARN, "audio_dev_alloc failed");
		goto error;
	}

	if (pci_config_setup(dip, &pcih) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "pci_config_setup failed");
		goto error;
	}
	devc->pcih = pcih;

	devid = pci_config_get16(pcih, PCI_CONF_DEVID);
	subid = pci_config_get16(pcih, PCI_CONF_SUBSYSID);

	pci_command = pci_config_get16(pcih, PCI_CONF_COMM);
	pci_command |= PCI_COMM_ME | PCI_COMM_IO;
	pci_config_put16(pcih, PCI_CONF_COMM, pci_command);

	if ((ddi_regs_map_setup(dip, 1, &devc->regs, 0, 0, &dev_attr,
	    &devc->regsh)) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "failed to map registers");
		goto error;
	}

	switch (devid) {
	case PCI_DEVICE_ID_SBLIVE:
		name = "Live!";
		model = "CT????";
		feature_mask = SB_LIVE;
		break;

	case PCI_DEVICE_ID_AUDIGYVALUE:
		name = "Audigy 2 Value";
		model = "SB????";
		feature_mask = SB_AUDIGY2VAL;
		break;

	case PCI_DEVICE_ID_AUDIGY:
		if (subid >= 0x1002 && subid <= 0x2005) {
			name = "Audigy 2";
			model = "SB????";
			feature_mask = SB_AUDIGY2;
		} else {
			name = "Audigy";
			model = "SB????";
			feature_mask = SB_AUDIGY;
		}
		break;

	default:
		audio_dev_warn(devc->adev, "Unrecognized device");
		goto error;
	}

	for (i = 0; emu10k_cards[i].prod; i++) {
		if ((devid == emu10k_cards[i].devid) &&
		    (subid == emu10k_cards[i].subid)) {
			name = emu10k_cards[i].prod;
			model = emu10k_cards[i].model;
			feature_mask = emu10k_cards[i].feature_mask;
			break;
		}
	}
	devc->feature_mask = feature_mask;

	(void) snprintf(namebuf, sizeof (namebuf), "Sound Blaster %s", name);

	audio_dev_set_description(devc->adev, namebuf);
	audio_dev_set_version(devc->adev, model);

	mutex_init(&devc->mutex, NULL, MUTEX_DRIVER, 0);

	/* allocate static page table memory */

	devc->max_mem = AUDIO_MEMSIZE;

	/* SB Live/Audigy supports at most 32M of memory) */
	if (devc->max_mem > 32 * 1024 * 1024)
		devc->max_mem = 32 * 1024 * 1024;

	devc->max_pages = devc->max_mem / 4096;
	if (devc->max_pages < 1024)
		devc->max_pages = 1024;

	/* Allocate page table */
	if (ddi_dma_alloc_handle(devc->dip, &dma_attr_buf, DDI_DMA_SLEEP, NULL,
	    &devc->pt_dmah) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev,
		    "failed to allocate page table handle");
		goto error;
	}

	if (ddi_dma_mem_alloc(devc->pt_dmah, devc->max_pages * 4,
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &devc->pt_kaddr, &len, &devc->pt_acch) !=
	    DDI_SUCCESS) {
		audio_dev_warn(devc->adev,
		    "failed to allocate memory for page table");
		goto error;
	}

	if (ddi_dma_addr_bind_handle(devc->pt_dmah, NULL,
	    devc->pt_kaddr, len, DDI_DMA_CONSISTENT | DDI_DMA_WRITE,
	    DDI_DMA_SLEEP, NULL, &cookie, &count) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev,
		    "failed binding page table DMA handle");
		goto error;
	}

	devc->page_map = (void *)devc->pt_kaddr;
	devc->pt_paddr = cookie.dmac_address;
	bzero(devc->pt_kaddr, devc->max_pages * 4);

	/* Allocate silent page */
	if (ddi_dma_alloc_handle(devc->dip, &dma_attr_buf, DDI_DMA_SLEEP, NULL,
	    &devc->silence_dmah) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev,
		    "failed to allocate silent page handle");
		goto error;
	}

	if (ddi_dma_mem_alloc(devc->silence_dmah, 4096,
	    &buf_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &devc->silence_kaddr, &len,
	    &devc->silence_acch) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev,
		    "failed to allocate silent page memory");
		goto error;
	}

	(void) ddi_dma_sync(devc->silence_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	if (ddi_dma_addr_bind_handle(devc->silence_dmah, NULL,
	    devc->silence_kaddr, len, DDI_DMA_CONSISTENT | DDI_DMA_WRITE,
	    DDI_DMA_SLEEP, NULL, &cookie, &count) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev,
		    "failed binding silent page DMA handle");
		goto error;
	}

	devc->silence_paddr = cookie.dmac_address;
	bzero(devc->silence_kaddr, 4096);
	devc->audio_memptr = 4096;	/* Skip the silence page */

	for (i = 0; i < devc->max_pages; i++)
		FILL_PAGE_MAP_ENTRY(i, devc->silence_paddr);

	(void) ddi_dma_sync(devc->pt_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	devc->ac97 = ac97_allocate(devc->adev, dip,
	    emu10k_read_ac97, emu10k_write_ac97, devc);
	if (devc->ac97 == NULL) {
		audio_dev_warn(devc->adev, "failed to allocate ac97 handle");
		goto error;
	}

	ac97_probe_controls(devc->ac97);

	/* allocate voice 0 for play */
	if (emu10k_alloc_port(devc, EMU10K_REC) != DDI_SUCCESS)
		goto error;

	if (emu10k_alloc_port(devc, EMU10K_PLAY) != DDI_SUCCESS)
		goto error;

	/* now initialize the hardware */
	mutex_enter(&devc->mutex);
	if (emu10k_hwinit(devc) != DDI_SUCCESS) {
		mutex_exit(&devc->mutex);
		goto error;
	}
	mutex_exit(&devc->mutex);

	emu10k_create_controls(devc);

	if (audio_dev_register(devc->adev) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "unable to register audio device");
		goto error;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	emu10k_destroy(devc);
	return (DDI_FAILURE);
}

int
emu10k_resume(dev_info_t *dip)
{
	emu10k_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	mutex_enter(&devc->mutex);
	if (emu10k_hwinit(devc) != DDI_SUCCESS) {
		mutex_exit(&devc->mutex);
		/*
		 * In case of failure, we leave the chip suspended,
		 * but don't panic.  Audio service is not normally a a
		 * critical service.
		 */
		audio_dev_warn(devc->adev, "FAILED to RESUME device");
		return (DDI_SUCCESS);
	}

	mutex_exit(&devc->mutex);

	/* resume ac97 */
	ac97_reset(devc->ac97);

	audio_dev_resume(devc->adev);

	return (DDI_SUCCESS);
}

int
emu10k_detach(emu10k_devc_t *devc)
{
	if (audio_dev_unregister(devc->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	emu10k_destroy(devc);
	return (DDI_SUCCESS);
}

int
emu10k_suspend(emu10k_devc_t *devc)
{
	audio_dev_suspend(devc->adev);

	return (DDI_SUCCESS);
}

static int emu10k_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int emu10k_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int emu10k_ddi_quiesce(dev_info_t *);

static struct dev_ops emu10k_dev_ops = {
	DEVO_REV,			/* rev */
	0,				/* refcnt */
	NULL,				/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	emu10k_ddi_attach,		/* attach */
	emu10k_ddi_detach,		/* detach */
	nodev,				/* reset */
	NULL,				/* cb_ops */
	NULL,				/* bus_ops */
	NULL,				/* power */
	emu10k_ddi_quiesce,		/* quiesce */
};

static struct modldrv emu10k_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Creative EMU10K Audio",	/* linkinfo */
	&emu10k_dev_ops,		/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &emu10k_modldrv, NULL }
};

int
_init(void)
{
	int rv;

	audio_init_ops(&emu10k_dev_ops, EMU10K_NAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&emu10k_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&emu10k_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
emu10k_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (emu10k_attach(dip));

	case DDI_RESUME:
		return (emu10k_resume(dip));

	default:
		return (DDI_FAILURE);
	}
}

int
emu10k_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	emu10k_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		return (emu10k_detach(devc));

	case DDI_SUSPEND:
		return (emu10k_suspend(devc));

	default:
		return (DDI_FAILURE);
	}
}

int
emu10k_ddi_quiesce(dev_info_t *dip)
{
	emu10k_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	/* stop all voices */
	for (int i = 0; i < 64; i++) {
		emu10k_write_reg(devc, VEDS, i, 0);
	}
	for (int i = 0; i < 64; i++) {
		emu10k_write_reg(devc, VTFT, i, 0);
		emu10k_write_reg(devc, CVCF, i, 0);
		emu10k_write_reg(devc, PTAB, i, 0);
		emu10k_write_reg(devc, CPF, i, 0);
	}

	/*
	 * Turn off the hardware
	 */
	OUTL(devc,
	    HCFG_LOCKSOUNDCACHE | HCFG_LOCKTANKCACHE_MASK |
	    HCFG_MUTEBUTTONENABLE, devc->regs + HCFG);

	/* stop ADC recording */
	emu10k_write_reg(devc, ADCSR, 0, 0x0);
	emu10k_write_reg(devc, ADCBA, 0, 0x0);
	emu10k_write_reg(devc, ADCBA, 0, 0x0);

	emu10k_write_reg(devc, PTBA, 0, 0);

	return (DDI_SUCCESS);
}
