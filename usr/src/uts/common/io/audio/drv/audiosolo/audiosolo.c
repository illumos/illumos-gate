/*
 * Copyright (c) 1999 Cameron Grant <cg@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (C) 4Front Technologies 1996-2008.
 */

#include <sys/audio/audio_driver.h>
#include <sys/note.h>
#include <sys/pci.h>
#include <sys/stdbool.h>


/*
 * NB: The Solo-1 is a bit schizophrenic compared to most devices.
 * It has two separate DMA engines for PCM data.  The first can do
 * either capture or playback, and supports various Sound Blaster
 * compatibility features.  The second is dedicated to playback.  The
 * two engines have very little in common when it comes to programming
 * them.
 *
 * We configure engine 1 for record, and engine 2 for playback.  Both
 * are configured for 48 kHz stereo 16-bit signed PCM.
 */

/*
 * ESS Solo-1 only implements the low 24-bits on Audio1, and requires
 * 64KB alignment.  For Audio2, it implements the full 32-bit address
 * space, but requires a 1MB address boundary.  Audio1 is used for
 * recording, and Audio2 is used for playback.
 */
static struct ddi_dma_attr dma_attr_audio1 = {
	DMA_ATTR_VERSION,	/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0x00ffffffU,		/* dma_attr_addr_hi */
	0xffff,			/* dma_attr_count_max */
	0x10000,		/* dma_attr_align */
	0x7f,			/* dma_attr_burstsizes */
	0x4,			/* dma_attr_minxfer */
	0xffff,			/* dma_attr_maxxfer */
	0xffff,			/* dma_attr_seg */
	0x1,			/* dma_attr_sgllen */
	0x1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static struct ddi_dma_attr dma_attr_audio2 = {
	DMA_ATTR_VERSION,	/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffU,		/* dma_attr_addr_hi */
	0xfff0,			/* dma_attr_count_max */
	0x100000,		/* dma_attr_align */
	0x7f,			/* dma_attr_burstsizes */
	0x4,			/* dma_attr_minxfer */
	0xfff0,			/* dma_attr_maxxfer */
	0xffff,			/* dma_attr_seg */
	0x1,			/* dma_attr_sgllen */
	0x1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

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


/*
 * For the sake of simplicity, this driver fixes a few parameters with
 * constants.
 */
#define	SOLO_RATE	48000
#define	SOLO_FRAGFR	1024
#define	SOLO_NFRAGS	2
#define	SOLO_NCHAN	2
#define	SOLO_SAMPSZ	2
#define	SOLO_FRAGSZ	(SOLO_FRAGFR * (SOLO_NCHAN * SOLO_SAMPSZ))
#define	SOLO_BUFFR	(SOLO_NFRAGS * SOLO_FRAGFR)
#define	SOLO_BUFSZ	(SOLO_NFRAGS * SOLO_FRAGSZ)

#define	INPUT_MIC	0
#define	INPUT_LINE	1
#define	INPUT_CD	2
#define	INPUT_AUX	3
#define	INPUT_MONO	4
#define	INSRCS		0x1f		/* bits 0-4 */

#define	DRVNAME		"audiosolo"

static const char *solo_insrcs[] = {
	AUDIO_PORT_MIC,
	AUDIO_PORT_LINEIN,
	AUDIO_PORT_CD,
	AUDIO_PORT_AUX1IN,
	AUDIO_PORT_AUX2IN,	/* this is really mono-in */
	NULL
};

typedef struct solo_regs {
	ddi_acc_handle_t	acch;
	caddr_t			base;
} solo_regs_t;

typedef struct solo_engine {
	struct solo_dev		*dev;
	audio_engine_t		*engine;
	ddi_dma_handle_t	dmah;
	ddi_acc_handle_t	acch;
	caddr_t			kaddr;
	uint32_t		paddr;

	bool			started;
	bool			trigger;
	uint64_t		count;
	uint16_t		offset;
	int			syncdir;
	int			format;
	bool			swapped;

	void			(*start)(struct solo_engine *);
	void			(*stop)(struct solo_engine *);
	void			(*update)(struct solo_engine *);
} solo_engine_t;

typedef enum {
	CTL_FRONT = 0,
	CTL_VOLUME,
	CTL_MIC,
	CTL_LINE,
	CTL_CD,
	CTL_AUX,
	CTL_MONO,
	CTL_MICBOOST,
	CTL_RECGAIN,
	CTL_RECSRC,
	CTL_MONSRC,
	CTL_SPEAKER,
	CTL_LOOPBACK,
	CTL_NUM,			/* must be last */
} solo_ctrl_num_t;

typedef struct solo_ctrl {
	struct solo_dev		*dev;
	audio_ctrl_t		*ctrl;
	solo_ctrl_num_t		num;
	uint64_t		val;
} solo_ctrl_t;

typedef struct solo_dev {
	dev_info_t		*dip;
	audio_dev_t		*adev;
	kmutex_t		mutex;
	ddi_intr_handle_t	ihandle;

	bool			suspended;

	/*
	 * Audio engines
	 */
	solo_engine_t		rec;
	solo_engine_t		play;
	uint32_t		last_capture;

	/*
	 * Controls.
	 */
	solo_ctrl_t		ctrls[CTL_NUM];

	/*
	 * Mapped registers
	 */
	ddi_acc_handle_t	pcih;
	solo_regs_t		io;
	solo_regs_t		sb;
	solo_regs_t		vc;

} solo_dev_t;

/*
 * Common code for the pcm function
 *
 * solo_cmd write a single byte to the CMD port.
 * solo_cmd1 write a CMD + 1 byte arg
 * ess_get_byte returns a single byte from the DSP data port
 *
 * solo_write is actually solo_cmd1
 * solo_read access ext. regs via solo_cmd(0xc0, reg) followed by solo_get_byte
 */

#define	PORT_RD8(port, regno)		\
	ddi_get8(port.acch, (void *)(port.base + (regno)))
#define	PORT_RD16(port, regno)		\
	ddi_get16(port.acch, (void *)(port.base + (regno)))
#define	PORT_RD32(port, regno)		\
	ddi_get32(port.acch, (void *)(port.base + (regno)))
#define	PORT_WR8(port, regno, data)	\
	ddi_put8(port.acch, (void *)(port.base + (regno)), data)
#define	PORT_WR16(port, regno, data)	\
	ddi_put16(port.acch, (void *)(port.base + (regno)), data)
#define	PORT_WR32(port, regno, data)	\
	ddi_put32(port.acch, (void *)(port.base + (regno)), data)

static bool
solo_dspready(solo_dev_t *dev)
{
	return ((PORT_RD8(dev->sb, 0xc) & 0x80) == 0 ? true : false);
}

static bool
solo_dspwr(solo_dev_t *dev, uint8_t val)
{
	int  i;

	for (i = 0; i < 1000; i++) {
		if (solo_dspready(dev)) {
			PORT_WR8(dev->sb, 0xc, val);
			return (true);
		}
		if (i > 10)
			drv_usecwait((i > 100)? 1000 : 10);
	}
	audio_dev_warn(dev->adev, "solo_dspwr(0x%02x) timed out", val);
	return (false);
}

static bool
solo_cmd(solo_dev_t *dev, uint8_t val)
{
	return (solo_dspwr(dev, val));
}

static void
solo_cmd1(solo_dev_t *dev, uint8_t cmd, uint8_t val)
{
	if (solo_dspwr(dev, cmd)) {
		(void) solo_dspwr(dev, val);
	}
}

static void
solo_setmixer(solo_dev_t *dev, uint8_t port, uint8_t value)
{
	PORT_WR8(dev->sb, 0x4, port); /* Select register */
	drv_usecwait(10);
	PORT_WR8(dev->sb, 0x5, value);
	drv_usecwait(10);
}

static uint8_t
solo_getmixer(solo_dev_t *dev, uint8_t port)
{
	uint8_t val;

	PORT_WR8(dev->sb, 0x4, port); /* Select register */
	drv_usecwait(10);
	val = PORT_RD8(dev->sb, 0x5);
	drv_usecwait(10);

	return (val);
}

static uint8_t
solo_get_byte(solo_dev_t *dev)
{
	for (int i = 1000; i > 0; i--) {
		if (PORT_RD8(dev->sb, 0xc) & 0x40)
			return (PORT_RD8(dev->sb, 0xa));
		else
			drv_usecwait(20);
	}
	audio_dev_warn(dev->adev, "timeout waiting to read DSP port");
	return (0xff);
}

static void
solo_write(solo_dev_t *dev, uint8_t reg, uint8_t val)
{
	solo_cmd1(dev, reg, val);
}

static uint8_t
solo_read(solo_dev_t *dev, uint8_t reg)
{
	if (solo_cmd(dev, 0xc0) && solo_cmd(dev, reg)) {
		return (solo_get_byte(dev));
	}
	return (0xff);
}

static bool
solo_reset_dsp(solo_dev_t *dev)
{
	PORT_WR8(dev->sb, 0x6, 3);
	drv_usecwait(100);
	PORT_WR8(dev->sb, 0x6, 0);
	if (solo_get_byte(dev) != 0xAA) {
		audio_dev_warn(dev->adev, "solo_reset_dsp failed");
		return (false);	/* Sorry */
	}
	return (true);
}

static uint_t
solo_intr(caddr_t arg1, caddr_t arg2)
{
	solo_dev_t	*dev = (void *)arg1;
	uint8_t		status;
	uint_t		rv = DDI_INTR_UNCLAIMED;

	_NOTE(ARGUNUSED(arg2));

	mutex_enter(&dev->mutex);

	if (dev->suspended) {
		mutex_exit(&dev->mutex);
		return (rv);
	}

	status = PORT_RD8(dev->io, 0x7);
	if (status & 0x20) {
		rv = DDI_INTR_CLAIMED;
		/* ack the interrupt */
		solo_setmixer(dev, 0x7a, solo_getmixer(dev, 0x7a) & ~0x80);
	}

	if (status & 0x10) {
		rv = DDI_INTR_CLAIMED;
		/* ack the interrupt */
		(void) PORT_RD8(dev->sb, 0xe);
	}
	mutex_exit(&dev->mutex);

	return (rv);
}

static uint8_t
solo_mixer_scale(solo_dev_t *dev, solo_ctrl_num_t num)
{
	uint32_t	l, r;
	uint64_t	value = dev->ctrls[num].val;

	l = (value >> 8) & 0xff;
	r = value & 0xff;

	l = (l * 15) / 100;
	r = (r * 15) / 100;
	return ((uint8_t)((l << 4) | (r)));
}

static void
solo_configure_mixer(solo_dev_t *dev)
{
	uint32_t v;
	uint32_t mon, rec;

	/*
	 * We disable hardware volume control (i.e. async updates to volume).
	 * We could in theory support this, but making it work right can be
	 * tricky, and we doubt it is widely used.
	 */
	solo_setmixer(dev, 0x64, solo_getmixer(dev, 0x64) | 0xc);
	solo_setmixer(dev, 0x66, 0);

	/* master volume has 6 bits per channel, bit 6 indicates mute  */
	/* left */
	v = (dev->ctrls[CTL_FRONT].val >> 8) & 0xff;
	v = v ? (v * 63) / 100 : 64;
	solo_setmixer(dev, 0x60, v & 0xff);

	/* right */
	v = dev->ctrls[CTL_FRONT].val & 0xff;
	v = v ? (v * 63) / 100 : 64;
	solo_setmixer(dev, 0x62, v & 0xff);

	v = solo_mixer_scale(dev, CTL_VOLUME);
	v = v | (v << 4);
	solo_setmixer(dev, 0x7c, v & 0xff);
	solo_setmixer(dev, 0x14, v & 0xff);

	mon = dev->ctrls[CTL_MONSRC].val;
	rec = dev->ctrls[CTL_RECSRC].val;

	/*
	 * The Solo-1 has dual stereo mixers (one for input and one for output),
	 * with separate volume controls for each.
	 */
	v = solo_mixer_scale(dev, CTL_MIC);
	solo_setmixer(dev, 0x68, rec & (1 << INPUT_MIC) ? v : 0);
	solo_setmixer(dev, 0x1a, mon & (1 << INPUT_MIC) ? v : 0);

	v = solo_mixer_scale(dev, CTL_LINE);
	solo_setmixer(dev, 0x6e, rec & (1 << INPUT_LINE) ? v : 0);
	solo_setmixer(dev, 0x3e, mon & (1 << INPUT_LINE) ? v : 0);

	v = solo_mixer_scale(dev, CTL_CD);
	solo_setmixer(dev, 0x6a, rec & (1 << INPUT_CD) ? v : 0);
	solo_setmixer(dev, 0x38, mon & (1 << INPUT_CD) ? v : 0);

	v = solo_mixer_scale(dev, CTL_AUX);
	solo_setmixer(dev, 0x6c, rec & (1 << INPUT_AUX) ? v : 0);
	solo_setmixer(dev, 0x3a, mon & (1 << INPUT_AUX) ? v : 0);

	v = solo_mixer_scale(dev, CTL_MONO);
	v = v | (v << 4);
	solo_setmixer(dev, 0x6f, rec & (1 << INPUT_MONO) ? v : 0);
	solo_setmixer(dev, 0x6d, mon & (1 << INPUT_MONO) ? v : 0);

	if (dev->ctrls[CTL_MICBOOST].val) {
		solo_setmixer(dev, 0x7d, solo_getmixer(dev, 0x7d) | 0x8);
	} else {
		solo_setmixer(dev, 0x7d, solo_getmixer(dev, 0x7d) & ~(0x8));
	}

	v = solo_mixer_scale(dev, CTL_RECGAIN);
	v = v | (v << 4);
	solo_write(dev, 0xb4, v & 0xff);

	v = dev->ctrls[CTL_SPEAKER].val & 0xff;
	v = (v * 7) / 100;
	solo_setmixer(dev, 0x3c, v & 0xff);

	if (dev->ctrls[CTL_LOOPBACK].val) {
		/* record-what-you-hear mode */
		solo_setmixer(dev, 0x1c, 0x3);
	} else {
		/* use record mixer */
		solo_setmixer(dev, 0x1c, 0x5);
	}

}

static int
solo_set_mixsrc(void *arg, uint64_t val)
{
	solo_ctrl_t	*pc = arg;
	solo_dev_t	*dev = pc->dev;

	if ((val & ~INSRCS) != 0)
		return (EINVAL);

	mutex_enter(&dev->mutex);
	pc->val = val;
	solo_configure_mixer(dev);
	mutex_exit(&dev->mutex);
	return (0);
}

static int
solo_set_mono(void *arg, uint64_t val)
{
	solo_ctrl_t	*pc = arg;
	solo_dev_t	*dev = pc->dev;

	val &= 0xff;
	if (val > 100)
		return (EINVAL);

	val = (val & 0xff) | ((val & 0xff) << 8);

	mutex_enter(&dev->mutex);
	pc->val = val;
	solo_configure_mixer(dev);
	mutex_exit(&dev->mutex);
	return (0);
}

static int
solo_set_stereo(void *arg, uint64_t val)
{
	solo_ctrl_t	*pc = arg;
	solo_dev_t	*dev = pc->dev;
	uint8_t		l;
	uint8_t		r;

	l = (val & 0xff00) >> 8;
	r = val & 0xff;

	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&dev->mutex);
	pc->val = val;
	solo_configure_mixer(dev);
	mutex_exit(&dev->mutex);
	return (0);
}

static int
solo_set_bool(void *arg, uint64_t val)
{
	solo_ctrl_t	*pc = arg;
	solo_dev_t	*dev = pc->dev;

	mutex_enter(&dev->mutex);
	pc->val = val;
	solo_configure_mixer(dev);
	mutex_exit(&dev->mutex);
	return (0);
}

static int
solo_get_value(void *arg, uint64_t *val)
{
	solo_ctrl_t	*pc = arg;
	solo_dev_t	*dev = pc->dev;

	mutex_enter(&dev->mutex);
	*val = pc->val;
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
solo_alloc_ctrl(solo_dev_t *dev, uint32_t num, uint64_t val)
{
	audio_ctrl_desc_t	desc;
	audio_ctrl_wr_t		fn;
	solo_ctrl_t		*pc;

	bzero(&desc, sizeof (desc));

	pc = &dev->ctrls[num];
	pc->num = num;
	pc->dev = dev;

	switch (num) {
	case CTL_VOLUME:
		desc.acd_name = AUDIO_CTRL_ID_VOLUME;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		fn = solo_set_mono;
		break;

	case CTL_FRONT:
		desc.acd_name = AUDIO_CTRL_ID_LINEOUT;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = solo_set_stereo;
		break;

	case CTL_SPEAKER:
		desc.acd_name = AUDIO_CTRL_ID_SPEAKER;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = solo_set_mono;
		break;

	case CTL_MIC:
		desc.acd_name = AUDIO_CTRL_ID_MIC;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = solo_set_stereo;
		break;

	case CTL_LINE:
		desc.acd_name = AUDIO_CTRL_ID_LINEIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = solo_set_stereo;
		break;

	case CTL_CD:
		desc.acd_name = AUDIO_CTRL_ID_CD;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = solo_set_stereo;
		break;

	case CTL_AUX:
		desc.acd_name = AUDIO_CTRL_ID_AUX1IN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = solo_set_stereo;
		break;

	case CTL_MONO:
		desc.acd_name = AUDIO_CTRL_ID_AUX2IN;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = solo_set_mono;
		break;

	case CTL_RECSRC:
		desc.acd_name = AUDIO_CTRL_ID_RECSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_minvalue = INSRCS;
		desc.acd_maxvalue = INSRCS;
		desc.acd_flags = RECCTL | AUDIO_CTRL_FLAG_MULTI;
		for (int i = 0; solo_insrcs[i]; i++) {
			desc.acd_enum[i] = solo_insrcs[i];
		}
		fn = solo_set_mixsrc;
		break;

	case CTL_MONSRC:
		desc.acd_name = AUDIO_CTRL_ID_MONSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_minvalue = INSRCS;
		desc.acd_maxvalue = INSRCS;
		desc.acd_flags = MONCTL | AUDIO_CTRL_FLAG_MULTI;
		for (int i = 0; solo_insrcs[i]; i++) {
			desc.acd_enum[i] = solo_insrcs[i];
		}
		fn = solo_set_mixsrc;
		break;

	case CTL_MICBOOST:
		desc.acd_name = AUDIO_CTRL_ID_MICBOOST;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = RECCTL;
		fn = solo_set_bool;
		break;

	case CTL_LOOPBACK:
		desc.acd_name = AUDIO_CTRL_ID_LOOPBACK;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = RECCTL;
		fn = solo_set_bool;
		break;

	case CTL_RECGAIN:
		desc.acd_name = AUDIO_CTRL_ID_RECGAIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECCTL;
		fn = solo_set_stereo;
		break;
	}

	pc->val = val;
	pc->ctrl = audio_dev_add_control(dev->adev, &desc,
	    solo_get_value, fn, pc);
}

static bool
solo_add_controls(solo_dev_t *dev)
{
	solo_alloc_ctrl(dev, CTL_VOLUME, 0x4b);
	solo_alloc_ctrl(dev, CTL_FRONT, 0x5a5a);
	solo_alloc_ctrl(dev, CTL_SPEAKER, 0x4b);
	solo_alloc_ctrl(dev, CTL_MIC, 0x3232);
	solo_alloc_ctrl(dev, CTL_LINE, 0x4b4b);
	solo_alloc_ctrl(dev, CTL_CD, 0x4b4b);
	solo_alloc_ctrl(dev, CTL_AUX, 0);
	solo_alloc_ctrl(dev, CTL_MONO, 0);
	solo_alloc_ctrl(dev, CTL_RECSRC, (1U << INPUT_MIC));
	solo_alloc_ctrl(dev, CTL_MONSRC, 0);
	solo_alloc_ctrl(dev, CTL_RECGAIN, 0x4b4b);
	solo_alloc_ctrl(dev, CTL_MICBOOST, 1);
	solo_alloc_ctrl(dev, CTL_LOOPBACK, 0);

	return (true);
}


/* utility functions for ESS */
static uint8_t
solo_calcfilter(int spd)
{
	int cutoff;

	cutoff = (spd * 9 * 82) / 20;
	return (256 - (7160000 / cutoff));
}

static void
solo_aud1_update(solo_engine_t *e)
{
	solo_dev_t	*dev = e->dev;
	uint16_t	offset, n;
	uint32_t	ptr;
	uint32_t	count;
	uint32_t	diff;
	int		tries;

	ASSERT(mutex_owned(&dev->mutex));

	/*
	 * During recording, this register is known to give back
	 * garbage if it's not quiescent while being read.  This hack
	 * attempts to work around it.  We also suspend the DMA
	 * while we do this, to minimize record distortion.
	 */
	if (e->trigger) {
		drv_usecwait(20);
	}
	for (tries = 10; tries; tries--) {
		drv_usecwait(10);
		ptr = PORT_RD32(dev->vc, 0);
		count = PORT_RD16(dev->vc, 4);
		diff = e->paddr + SOLO_BUFSZ - ptr - count;
		if ((diff > 3) || (ptr < e->paddr) ||
		    (ptr >= (e->paddr + SOLO_BUFSZ))) {
			ptr = dev->last_capture;
		} else {
			break;
		}
	}
	if (e->trigger) {
		PORT_WR8(dev->vc, 0xf, 0);	/* restart DMA */
	}
	if (!tries) {
		/*
		 * Note, this is a pretty bad situation, because we'll
		 * not have an accurate idea of our position.  But its
		 * better than making a bad alteration.  If we had FMA
		 * for audio devices, this would be a good point to
		 * raise a fault.
		 */
		return;
	}
	dev->last_capture = ptr;
	offset = ptr - e->paddr;
	offset /= (SOLO_NCHAN * SOLO_SAMPSZ);

	n = offset >= e->offset ?
	    offset - e->offset :
	    offset + SOLO_BUFSZ - e->offset;

	e->offset = offset;
	e->count += n / (SOLO_NCHAN * SOLO_SAMPSZ);
}

static void
solo_aud1_start(solo_engine_t *e)
{
	solo_dev_t	*dev = e->dev;
	int		len;
	uint32_t	v;

	ASSERT(mutex_owned(&dev->mutex));

	e->offset = 0;
	len = SOLO_FRAGSZ / 2;
	len = -len;

	/* sample rate - 48 kHz */
	solo_write(dev, 0xa1, 0xf0);
	/* filter cutoff */
	solo_write(dev, 0xa2, solo_calcfilter(SOLO_RATE));


	/* mono/stereo - bit 0 set, bit 1 clear */
	solo_write(dev, 0xa8, (solo_read(dev, 0xa8) & ~0x03) | 1);

	(void) solo_cmd(dev, 0xd3);	/* turn off DAC1 output */

	/* setup fifo for signed 16-bit stereo */
	solo_write(dev, 0xb7, 0x71);
	solo_write(dev, 0xb7, 0xbc);

	v = solo_mixer_scale(dev, CTL_RECGAIN);
	v = v | (v << 4);
	solo_write(dev, 0xb4, v & 0xff);

	PORT_WR8(dev->vc, 0x8, 0xc4); /* command */
	PORT_WR8(dev->vc, 0xd, 0xff); /* clear DMA */
	PORT_WR8(dev->vc, 0xf, 0x01); /* stop DMA  */

	PORT_WR8(dev->vc, 0xd, 0xff); /* reset */
	PORT_WR8(dev->vc, 0xf, 0x01); /* mask */
	PORT_WR8(dev->vc, 0xb, 0x14); /* mode */

	PORT_WR32(dev->vc, 0x0, e->paddr);
	PORT_WR16(dev->vc, 0x4, SOLO_BUFSZ - 1);

	/* transfer length low, high */
	solo_write(dev, 0xa4, len & 0x00ff);
	solo_write(dev, 0xa5, (len & 0xff00) >> 8);

	/* autoinit, dma dir, go for it */
	solo_write(dev, 0xb8, 0x0f);
	PORT_WR8(dev->vc, 0xf, 0);	/* start DMA */

	dev->last_capture = e->paddr;
	e->trigger = true;
}

static void
solo_aud1_stop(solo_engine_t *e)
{
	solo_dev_t	*dev = e->dev;

	/* NB: We might be in quiesce, without a lock held */
	solo_write(dev, 0xb8, solo_read(dev, 0xb8) & ~0x01);
	e->trigger = false;
}

static void
solo_aud2_update(solo_engine_t *e)
{
	solo_dev_t	*dev = e->dev;
	uint16_t	offset = 0, n;

	ASSERT(mutex_owned(&dev->mutex));

	offset = SOLO_BUFSZ - PORT_RD16(dev->io, 0x4);
	offset /= (SOLO_NCHAN * SOLO_SAMPSZ);

	n = offset >= e->offset ?
	    offset - e->offset :
	    offset + SOLO_BUFFR - e->offset;

	e->offset = offset;
	e->count += n;
}

static void
solo_aud2_start(solo_engine_t *e)
{
	solo_dev_t	*dev = e->dev;
	int		len;
	uint32_t	v;

	ASSERT(mutex_owned(&dev->mutex));

	e->offset = 0;
	len = SOLO_FRAGSZ / 2;
	len = -len;

	/* program transfer type */
	solo_setmixer(dev, 0x78, 0x10);
	/* sample rate - 48 kHz */
	solo_setmixer(dev, 0x70, 0xf0);
	solo_setmixer(dev, 0x72, solo_calcfilter(SOLO_RATE));
	/* transfer length low & high */
	solo_setmixer(dev, 0x74, len & 0x00ff);
	solo_setmixer(dev, 0x76, (len & 0xff00) >> 8);
	/* enable irq, set signed 16-bit stereo format */
	solo_setmixer(dev, 0x7a, 0x47);

	PORT_WR8(dev->io, 0x6, 0);
	PORT_WR32(dev->io, 0x0, e->paddr);
	PORT_WR16(dev->io, 0x4, SOLO_BUFSZ);

	/* this crazy initialization appears to help with fifo weirdness */
	/* start the engine running */
	solo_setmixer(dev, 0x78, 0x92);
	drv_usecwait(10);
	solo_setmixer(dev, 0x78, 0x93);

	PORT_WR8(dev->io, 0x6, 0x0a); /* autoinit, enable */

	v = solo_mixer_scale(dev, CTL_VOLUME);
	v = v | (v << 4);
	solo_setmixer(dev, 0x7c, v & 0xff);

	e->trigger = true;
}

static void
solo_aud2_stop(solo_engine_t *e)
{
	solo_dev_t	*dev = e->dev;

	/* NB: We might be in quiesce, without a lock held */
	PORT_WR8(dev->io, 0x6, 0);
	solo_setmixer(dev, 0x78, solo_getmixer(dev, 0x78) & ~0x03);

	e->trigger = false;
}

/*
 * Audio entry points.
 */
static int
solo_format(void *arg)
{
	solo_engine_t	*e = arg;
	return (e->format);
}

static int
solo_channels(void *arg)
{
	_NOTE(ARGUNUSED(arg));
	return (SOLO_NCHAN);
}

static int
solo_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));
	return (SOLO_RATE);
}

static void
solo_chinfo(void *arg, int chan, unsigned *offset, unsigned *incr)
{
	solo_engine_t *e = arg;

	if (e->swapped) {
		*offset = !chan;
	} else {
		*offset = chan;
	}
	*incr = 2;
}

static void
solo_sync(void *arg, unsigned nframes)
{
	solo_engine_t *e = arg;

	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(e->dmah, 0, 0, e->syncdir);
}


static uint64_t
solo_count(void *arg)
{
	solo_engine_t	*e = arg;
	solo_dev_t	*dev = e->dev;
	uint64_t	count;

	mutex_enter(&dev->mutex);
	e->update(e);
	count = e->count;
	mutex_exit(&dev->mutex);

	return (count);
}

static int
solo_open(void *arg, int f, unsigned *nframes, caddr_t *buf)
{
	solo_engine_t	*e = arg;
	solo_dev_t	*dev = e->dev;

	_NOTE(ARGUNUSED(f));

	*nframes = SOLO_NFRAGS * SOLO_FRAGFR;
	*buf = e->kaddr;

	mutex_enter(&dev->mutex);
	e->started = false;
	e->count = 0;
	mutex_exit(&dev->mutex);

	return (0);
}

void
solo_close(void *arg)
{
	solo_engine_t	*e = arg;
	solo_dev_t	*dev = e->dev;

	mutex_enter(&dev->mutex);
	e->stop(e);
	e->started = false;
	mutex_exit(&dev->mutex);
}


static int
solo_start(void *arg)
{
	solo_engine_t	*e = arg;
	solo_dev_t	*dev = e->dev;

	mutex_enter(&dev->mutex);
	if (!e->started) {
		e->start(e);
		e->started = true;
	}
	mutex_exit(&dev->mutex);

	return (0);
}

static void
solo_stop(void *arg)
{
	solo_engine_t	*e = arg;
	solo_dev_t	*dev = e->dev;

	mutex_enter(&dev->mutex);
	if (e->started) {
		e->stop(e);
		e->started = false;
	}
	mutex_exit(&dev->mutex);

}

static audio_engine_ops_t solo_engine_ops = {
	AUDIO_ENGINE_VERSION,
	solo_open,
	solo_close,
	solo_start,
	solo_stop,
	solo_count,
	solo_format,
	solo_channels,
	solo_rate,
	solo_sync,
	NULL,
	solo_chinfo,
	NULL,
};

static void
solo_release_resources(solo_dev_t *dev)
{
	if (dev->ihandle != NULL) {
		(void) ddi_intr_disable(dev->ihandle);
		(void) ddi_intr_remove_handler(dev->ihandle);
		(void) ddi_intr_free(dev->ihandle);
		mutex_destroy(&dev->mutex);
	}

	if (dev->io.acch != NULL) {
		ddi_regs_map_free(&dev->io.acch);
	}

	if (dev->sb.acch != NULL) {
		ddi_regs_map_free(&dev->sb.acch);
	}

	if (dev->vc.acch != NULL) {
		ddi_regs_map_free(&dev->vc.acch);
	}

	if (dev->pcih != NULL) {
		pci_config_teardown(&dev->pcih);
	}

	/* release play resources */
	if (dev->play.paddr != 0)
		(void) ddi_dma_unbind_handle(dev->play.dmah);
	if (dev->play.acch != NULL)
		ddi_dma_mem_free(&dev->play.acch);
	if (dev->play.dmah != NULL)
		ddi_dma_free_handle(&dev->play.dmah);

	if (dev->play.engine != NULL) {
		audio_dev_remove_engine(dev->adev, dev->play.engine);
		audio_engine_free(dev->play.engine);
	}

	/* release record resources */
	if (dev->rec.paddr != 0)
		(void) ddi_dma_unbind_handle(dev->rec.dmah);
	if (dev->rec.acch != NULL)
		ddi_dma_mem_free(&dev->rec.acch);
	if (dev->rec.dmah != NULL)
		ddi_dma_free_handle(&dev->rec.dmah);

	if (dev->rec.engine != NULL) {
		audio_dev_remove_engine(dev->adev, dev->rec.engine);
		audio_engine_free(dev->rec.engine);
	}

	for (int i = 0; i < CTL_NUM; i++) {
		if (dev->ctrls[i].ctrl != NULL) {
			audio_dev_del_control(dev->ctrls[i].ctrl);
		}
	}

	if (dev->adev != NULL) {
		audio_dev_free(dev->adev);
	}

	kmem_free(dev, sizeof (*dev));
}

static bool
solo_setup_interrupts(solo_dev_t *dev)
{
	int actual;
	uint_t ipri;

	if ((ddi_intr_alloc(dev->dip, &dev->ihandle, DDI_INTR_TYPE_FIXED,
	    0, 1, &actual, DDI_INTR_ALLOC_NORMAL) != DDI_SUCCESS) ||
	    (actual != 1)) {
		audio_dev_warn(dev->adev, "can't alloc intr handle");
		return (false);
	}

	if (ddi_intr_get_pri(dev->ihandle, &ipri) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev,  "can't determine intr priority");
		(void) ddi_intr_free(dev->ihandle);
		dev->ihandle = NULL;
		return (false);
	}

	if (ddi_intr_add_handler(dev->ihandle, solo_intr, dev,
	    NULL) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "can't add intr handler");
		(void) ddi_intr_free(dev->ihandle);
		dev->ihandle = NULL;
		return (false);
	}

	mutex_init(&dev->mutex, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));

	return (true);
}

static bool
solo_map_registers(solo_dev_t *dev)
{
	dev_info_t	*dip = dev->dip;

	/* map registers */
	if (ddi_regs_map_setup(dip, 1, &dev->io.base, 0, 0, &acc_attr,
	    &dev->io.acch) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "can't map IO registers");
		return (false);
	}
	if (ddi_regs_map_setup(dip, 2, &dev->sb.base, 0, 0, &acc_attr,
	    &dev->sb.acch) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "can't map SB registers");
		return (false);
	}
	if (ddi_regs_map_setup(dip, 3, &dev->vc.base, 0, 0, &acc_attr,
	    &dev->vc.acch) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "can't map VC registers");
		return (false);
	}

	return (true);
}

#define	ESS_PCI_LEGACYCONTROL		0x40
#define	ESS_PCI_CONFIG			0x50
#define	ESS_PCI_DDMACONTROL		0x60

static bool
solo_init_hw(solo_dev_t *dev)
{
	uint32_t	data;

	/*
	 * Legacy audio register -- disable legacy audio.  We also
	 * arrange for 16-bit I/O address decoding.
	 */
	/* this version disables the MPU, FM synthesis (Adlib), and Game Port */
	pci_config_put16(dev->pcih, ESS_PCI_LEGACYCONTROL, 0x8041);

	/*
	 * Note that Solo-1 uses I/O space for all BARs, and hardwires
	 * the upper 32-bits to zero.
	 */
	data = pci_config_get32(dev->pcih, PCI_CONF_BASE2);
	data |= 1;
	pci_config_put16(dev->pcih, ESS_PCI_DDMACONTROL, data & 0xffff);

	/*
	 * Make sure that legacy IRQ and DRQ are disbled.  We disable most
	 * other legacy features too.
	 */
	pci_config_put16(dev->pcih, ESS_PCI_CONFIG, 0);

	if (!solo_reset_dsp(dev))
		return (false);

	/* enable extended mode */
	(void) solo_cmd(dev, 0xc6);


	PORT_WR8(dev->io, 0x7, 0x30); /* enable audio irqs */

	/* demand mode, 4 bytes/xfer */
	solo_write(dev, 0xb9, 0x01);

	/*
	 * This sets Audio 2 (playback) to use its own independent
	 * rate control, and gives us 48 kHz compatible divisors.  It
	 * also bypasses the switched capacitor filter.
	 */
	solo_setmixer(dev, 0x71, 0x2a);

	/* irq control */
	solo_write(dev, 0xb1, (solo_read(dev, 0xb1) & 0x0f) | 0x50);
	/* drq control */
	solo_write(dev, 0xb2, (solo_read(dev, 0xb2) & 0x0f) | 0x50);

	solo_setmixer(dev, 0, 0); /* reset mixer settings */

	solo_configure_mixer(dev);
	return (true);
}

static bool
solo_alloc_engine(solo_dev_t *dev, int engno)
{
	size_t			rlen;
	ddi_dma_attr_t		*dattr;
	ddi_dma_cookie_t	c;
	unsigned		ccnt;
	unsigned		caps;
	unsigned		dflags;
	const char		*desc;
	solo_engine_t		*e;

	ASSERT((engno == 1) || (engno = 2));

	switch (engno) {
	case 1:	/* record */
		e = &dev->rec;
		desc = "record";
		dattr = &dma_attr_audio1;
		caps = ENGINE_INPUT_CAP;
		dflags = DDI_DMA_READ | DDI_DMA_CONSISTENT;
		e->syncdir = DDI_DMA_SYNC_FORKERNEL;
		e->update = solo_aud1_update;
		e->start = solo_aud1_start;
		e->stop = solo_aud1_stop;
		e->format = AUDIO_FORMAT_S16_BE;
		e->swapped = true;
		break;

	case 2:	/* playback */
		e = &dev->play;
		desc = "playback";
		dattr = &dma_attr_audio2;
		caps = ENGINE_OUTPUT_CAP;
		dflags = DDI_DMA_WRITE | DDI_DMA_CONSISTENT;
		e->syncdir = DDI_DMA_SYNC_FORDEV;
		e->update = solo_aud2_update;
		e->start = solo_aud2_start;
		e->stop = solo_aud2_stop;
		e->format = AUDIO_FORMAT_S16_LE;
		e->swapped = false;
		break;

	default:
		audio_dev_warn(dev->adev, "bad engine number!");
		return (false);
	}

	e->dev = dev;

	if (ddi_dma_alloc_handle(dev->dip, dattr, DDI_DMA_SLEEP, NULL,
	    &e->dmah) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "%s dma handle alloc failed", desc);
		return (false);
	}
	if (ddi_dma_mem_alloc(e->dmah, SOLO_BUFSZ, &buf_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &e->kaddr,
	    &rlen, &e->acch) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "%s dma memory alloc failed", desc);
		return (false);
	}
	/* ensure that the buffer is zeroed out properly */
	bzero(e->kaddr, rlen);
	if (ddi_dma_addr_bind_handle(e->dmah, NULL, e->kaddr, SOLO_BUFSZ,
	    dflags, DDI_DMA_SLEEP, NULL, &c, &ccnt) != DDI_DMA_MAPPED) {
		audio_dev_warn(dev->adev, "%s dma binding failed", desc);
		return (false);
	}
	e->paddr = c.dmac_address;

	/*
	 * Allocate and configure audio engine.
	 */
	e->engine = audio_engine_alloc(&solo_engine_ops, caps);
	if (e->engine == NULL) {
		audio_dev_warn(dev->adev, "record audio_engine_alloc failed");
		return (false);
	}

	audio_engine_set_private(e->engine, e);
	audio_dev_add_engine(dev->adev, e->engine);

	return (true);
}


static int
solo_suspend(solo_dev_t *dev)
{
	audio_dev_suspend(dev->adev);

	mutex_enter(&dev->mutex);
	dev->suspended = true;
	mutex_exit(&dev->mutex);

	return (DDI_SUCCESS);
}

static int
solo_resume(solo_dev_t *dev)
{
	mutex_enter(&dev->mutex);
	if (!solo_init_hw(dev)) {
		/* yikes! */
		audio_dev_warn(dev->adev, "unable to resume audio!");
		audio_dev_warn(dev->adev, "reboot or reload driver to reset");
	}
	dev->suspended = false;
	mutex_exit(&dev->mutex);

	audio_dev_resume(dev->adev);

	return (DDI_SUCCESS);
}

static int
solo_attach(dev_info_t *dip)
{
	solo_dev_t	*dev;
	uint32_t	data;

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->dip = dip;
	ddi_set_driver_private(dip, dev);

	dev->adev = audio_dev_alloc(dip, 0);
	if (dev->adev == NULL)
		goto no;

	audio_dev_set_description(dev->adev, "ESS Solo-1 PCI AudioDrive");
	audio_dev_set_version(dev->adev, "ES1938");

	if (pci_config_setup(dip, &dev->pcih) != DDI_SUCCESS) {
		audio_dev_warn(NULL, "pci_config_setup failed");
		goto no;
	}

	data = pci_config_get16(dev->pcih, PCI_CONF_COMM);
	data |= PCI_COMM_ME | PCI_COMM_IO;
	pci_config_put16(dev->pcih, PCI_CONF_COMM, data);

	if ((!solo_map_registers(dev)) ||
	    (!solo_setup_interrupts(dev)) ||
	    (!solo_alloc_engine(dev, 1)) ||
	    (!solo_alloc_engine(dev, 2)) ||
	    (!solo_add_controls(dev)) ||
	    (!solo_init_hw(dev))) {
		goto no;
	}

	if (audio_dev_register(dev->adev) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev,
		    "unable to register with audio framework");
		goto no;
	}

	(void) ddi_intr_enable(dev->ihandle);
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

no:
	solo_release_resources(dev);
	return (DDI_FAILURE);
}

static int
solo_detach(solo_dev_t *dev)
{
	if (audio_dev_unregister(dev->adev) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	solo_release_resources(dev);
	return (DDI_SUCCESS);
}

static int
solo_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	solo_dev_t *dev;

	switch (cmd) {
	case DDI_ATTACH:
		return (solo_attach(dip));

	case DDI_RESUME:
		if ((dev = ddi_get_driver_private(dip)) == NULL) {
			return (DDI_FAILURE);
		}
		return (solo_resume(dev));

	default:
		return (DDI_FAILURE);
	}
}

static int
solo_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	solo_dev_t *dev;

	if ((dev = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		return (solo_detach(dev));

	case DDI_SUSPEND:
		return (solo_suspend(dev));
	default:
		return (DDI_FAILURE);
	}
}

static int
solo_quiesce(dev_info_t *dip)
{
	solo_dev_t *dev;

	dev = ddi_get_driver_private(dip);

	solo_aud1_stop(&dev->rec);
	solo_aud2_stop(&dev->play);

	solo_setmixer(dev, 0, 0);
	PORT_WR8(dev->io, 0x7, 0); /* disable all irqs */
	return (0);
}

struct dev_ops solo_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	solo_ddi_attach,	/* attach */
	solo_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	solo_quiesce,		/* quiesce */
};

static struct modldrv solo_modldrv = {
	&mod_driverops,			/* drv_modops */
	"ESS Solo-1 Audio",		/* linkinfo */
	&solo_dev_ops,			/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &solo_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&solo_dev_ops, DRVNAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&solo_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&solo_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
