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
 * Purpose: Driver for the Creative Audigy LS sound card
 */
/*
 * Copyright (C) 4Front Technologies 1996-2009.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>

#include "audiols.h"

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
	0x00000000,		/* low DMA address range */
	0xffffffff,		/* high DMA address range */
	0x000fffff,		/* DMA counter (16 bits only in Audigy LS) */
	4,			/* DMA address alignment */
	0x3c,			/* DMA burstsizes */
	4,			/* min effective DMA size */
	0xffffffff,		/* max DMA xfer size */
	0xffffffff,		/* segment boundary */
	1,			/* s/g length */
	4,			/* granularity of device */
	0			/* Bus specific DMA flags */
};

static int audigyls_attach(dev_info_t *);
static int audigyls_resume(dev_info_t *);
static int audigyls_detach(audigyls_dev_t *);
static int audigyls_suspend(audigyls_dev_t *);

static int audigyls_open(void *, int, unsigned *, caddr_t *);
static void audigyls_close(void *);
static int audigyls_start(void *);
static void audigyls_stop(void *);
static int audigyls_format(void *);
static int audigyls_channels(void *);
static int audigyls_rate(void *);
static uint64_t audigyls_count(void *);
static void audigyls_sync(void *, unsigned);
static void audigyls_chinfo(void *, int, unsigned *, unsigned *);


static uint16_t audigyls_read_ac97(void *, uint8_t);
static void audigyls_write_ac97(void *, uint8_t, uint16_t);
static int audigyls_alloc_port(audigyls_dev_t *, int);
static void audigyls_destroy(audigyls_dev_t *);
static void audigyls_hwinit(audigyls_dev_t *);
static void audigyls_configure_mixer(audigyls_dev_t *dev);

static audio_engine_ops_t audigyls_engine_ops = {
	AUDIO_ENGINE_VERSION,
	audigyls_open,
	audigyls_close,
	audigyls_start,
	audigyls_stop,
	audigyls_count,
	audigyls_format,
	audigyls_channels,
	audigyls_rate,
	audigyls_sync,
	NULL,
	audigyls_chinfo,
	NULL
};

/*
 * Audigy LS uses AC'97 strictly for the recording side of things.
 * While the chip can supposedly route output to AC'97 for playback,
 * the PCI devices use a separate I2S DAC instead.  As a result we
 * need to suppress controls that the AC'97 codec registers.
 *
 * Furthermore, even then the AC'97 codec offers inputs that we just
 * aren't interested in.
 */
const char *audigyls_remove_ac97[] = {
	AUDIO_CTRL_ID_VOLUME,
	AUDIO_CTRL_ID_LINEOUT,
	AUDIO_CTRL_ID_HEADPHONE,
	AUDIO_CTRL_ID_CD,
	AUDIO_CTRL_ID_VIDEO,
	AUDIO_CTRL_ID_3DDEPTH,
	AUDIO_CTRL_ID_3DENHANCE,
	AUDIO_CTRL_ID_BEEP,
	AUDIO_CTRL_ID_RECGAIN,
	AUDIO_CTRL_ID_RECSRC,
	AUDIO_CTRL_ID_LOOPBACK,
	NULL,
};

/*
 * AC'97 sources we don't want to expose.
 */
const char *audigyls_badsrcs[] = {
	AUDIO_PORT_VIDEO,
	AUDIO_PORT_CD,
	AUDIO_PORT_STEREOMIX,
	AUDIO_PORT_MONOMIX,
	NULL,
};

static unsigned int
read_chan(audigyls_dev_t *dev, int reg, int chn)
{
	uint32_t val;

	mutex_enter(&dev->low_mutex);
	/* Pointer */
	OUTL(dev, PR, (reg << 16) | (chn & 0xffff));
	/* Data */
	val = INL(dev, DR);
	mutex_exit(&dev->low_mutex);

	return (val);
}

static void
write_chan(audigyls_dev_t *dev, int reg, int chn, uint32_t value)
{
	mutex_enter(&dev->low_mutex);
	/* Pointer */
	OUTL(dev, PR, (reg << 16) | (chn & 0x7));
	/* Data */
	OUTL(dev, DR, value);
	mutex_exit(&dev->low_mutex);
}

static unsigned int
read_reg(audigyls_dev_t *dev, int reg)
{
	return (read_chan(dev, reg, 0));
}

static void
write_reg(audigyls_dev_t *dev, int reg, uint32_t value)
{
	write_chan(dev, reg, 0, value);
}


static uint16_t
audigyls_read_ac97(void *arg, uint8_t index)
{
	audigyls_dev_t *dev = arg;
	uint16_t dtemp = 0;
	int i;

	mutex_enter(&dev->low_mutex);
	OUTB(dev, AC97A, index);
	for (i = 0; i < 10000; i++) {
		if (INB(dev, AC97A) & 0x80)
			break;
	}
	if (i == 10000) {	/* Timeout */
		mutex_exit(&dev->low_mutex);
		return (0xffff);
	}
	dtemp = INW(dev, AC97D);
	mutex_exit(&dev->low_mutex);

	return (dtemp);
}

static void
audigyls_write_ac97(void *arg, uint8_t index, uint16_t data)
{
	audigyls_dev_t *dev = arg;
	int i;

	mutex_enter(&dev->low_mutex);
	OUTB(dev, AC97A, index);
	for (i = 0; i < 50000; i++) {
		if (INB(dev, AC97A) & 0x80)
			break;
	}
	if (i == 50000) {
		mutex_exit(&dev->low_mutex);
		return;
	}
	OUTW(dev, AC97D, data);
	mutex_exit(&dev->low_mutex);
}

static void
select_digital_enable(audigyls_dev_t *dev, int mode)
{
	/*
	 * Set the out3/spdif combo jack format.
	 * mode0=analog rear/center, 1=spdif
	 */

	if (mode == 0) {
		write_reg(dev, SPC, 0x00000f00);
	} else {
		write_reg(dev, SPC, 0x0000000f);
	}
}

/* only for SBLive 7.1 */
void
audigyls_i2c_write(audigyls_dev_t *dev, int reg, int data)
{
	int i, timeout, tmp;

	tmp = (reg << 9 | data) << 16;	/* set the upper 16 bits */
	/* first write the command to the data reg */
	write_reg(dev, I2C_1, tmp);
	for (i = 0; i < 20; i++) {
		tmp = read_reg(dev, I2C_A) & ~0x6fe;
		/* see audigyls.pdf for bits */
		tmp |= 0x400 | 0x100 | 0x34;
		write_reg(dev, I2C_A, tmp);
		/* now wait till controller sets valid bit (0x100) to 0 */
		timeout = 0;
		for (;;) {
			tmp = read_reg(dev, I2C_A);
			if ((tmp & 0x100) == 0)
				break;

			if (timeout > 100)
				break;

			timeout++;
		}

		/* transaction aborted */
		if (tmp & 0x200)
			break;
	}
}

int
audigyls_spi_write(audigyls_dev_t *dev, int data)
{
	unsigned int orig;
	unsigned int tmp;
	int i, valid;

	tmp = read_reg(dev, SPI);
	orig = (tmp & ~0x3ffff) | 0x30000;
	write_reg(dev, SPI, orig | data);
	valid = 0;
	/* Wait for status bit to return to 0 */
	for (i = 0; i < 1000; i++) {
		drv_usecwait(100);
		tmp = read_reg(dev, SPI);
		if (!(tmp & 0x10000)) {
			valid = 1;
			break;
		}
	}
	if (!valid)			/* Timed out */
		return (0);

	return (1);
}

/*
 * Audio routines
 */

int
audigyls_open(void *arg, int flag, unsigned *nframesp, caddr_t *bufp)
{
	audigyls_port_t	 *port = arg;
	audigyls_dev_t	 *dev = port->dev;

	_NOTE(ARGUNUSED(flag));

	mutex_enter(&dev->mutex);

	port->count = 0;
	*nframesp = port->buf_frames;
	*bufp = port->buf_kaddr;
	mutex_exit(&dev->mutex);

	return (0);
}

void
audigyls_close(void *arg)
{
	_NOTE(ARGUNUSED(arg));
}

int
audigyls_start(void *arg)
{
	audigyls_port_t *port = arg;
	audigyls_dev_t	*dev = port->dev;
	uint32_t	tmp;

	mutex_enter(&dev->mutex);

	port->offset = 0;

	switch (port->direction) {
	case AUDIGYLS_PLAY_PORT:
		write_chan(dev, PTCA, 0, 0);
		write_chan(dev, CPFA, 0, 0);
		write_chan(dev, CPCAV, 0, 0);
		write_chan(dev, PTCA, 1, 0);
		write_chan(dev, CPFA, 1, 0);
		write_chan(dev, CPCAV, 1, 0);
		write_chan(dev, PTCA, 3, 0);
		write_chan(dev, CPFA, 3, 0);
		write_chan(dev, CPCAV, 3, 0);

		tmp = read_reg(dev, SA);
		tmp |= SA_SPA(0);
		tmp |= SA_SPA(1);
		tmp |= SA_SPA(3);
		write_reg(dev, SA, tmp);
		break;

	case AUDIGYLS_REC_PORT:
		write_chan(dev, CRFA, 2, 0);
		write_chan(dev, CRCAV, 2, 0);

		tmp = read_reg(dev, SA);
		tmp |= SA_SRA(2);
		write_reg(dev, SA, tmp);
		break;
	}

	mutex_exit(&dev->mutex);
	return (0);
}

void
audigyls_stop(void *arg)
{
	audigyls_port_t	*port = arg;
	audigyls_dev_t	*dev = port->dev;
	uint32_t	tmp;

	mutex_enter(&dev->mutex);

	switch (port->direction) {
	case AUDIGYLS_PLAY_PORT:
		tmp = read_reg(dev, SA);
		tmp &= ~SA_SPA(0);
		tmp &= ~SA_SPA(1);
		tmp &= ~SA_SPA(3);
		write_reg(dev, SA, tmp);
		break;

	case AUDIGYLS_REC_PORT:
		tmp = read_reg(dev, SA);
		tmp &= ~SA_SRA(2);
		write_reg(dev, SA, tmp);
		break;
	}

	mutex_exit(&dev->mutex);
}

int
audigyls_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

int
audigyls_channels(void *arg)
{
	audigyls_port_t	*port = arg;

	return (port->nchan);
}

int
audigyls_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}

void
audigyls_sync(void *arg, unsigned nframes)
{
	audigyls_port_t *port = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(port->buf_dmah, 0, 0, port->syncdir);
}

uint64_t
audigyls_count(void *arg)
{
	audigyls_port_t	*port = arg;
	audigyls_dev_t	*dev = port->dev;
	uint64_t	count;
	uint32_t	offset, n;

	mutex_enter(&dev->mutex);

	if (port->direction == AUDIGYLS_PLAY_PORT) {
		offset = read_chan(dev, CPFA, 0);
	} else {
		offset = read_chan(dev, CRFA, 2);
	}

	/* get the offset, and switch to frames */
	offset /= (2 * sizeof (uint16_t));

	if (offset >= port->offset) {
		n = offset - port->offset;
	} else {
		n = offset + (port->buf_frames - port->offset);
	}
	port->offset = offset;
	port->count += n;

	count = port->count;
	mutex_exit(&dev->mutex);
	return (count);
}

static void
audigyls_chinfo(void *arg, int chan, unsigned *offset, unsigned *incr)
{
	audigyls_port_t *port = arg;

	if (port->direction == AUDIGYLS_PLAY_PORT) {
		*offset = (port->buf_frames * 2 * (chan / 2)) + (chan % 2);
		*incr = 2;
	} else {
		*offset = chan;
		*incr = 2;
	}
}

/* private implementation bits */

int
audigyls_alloc_port(audigyls_dev_t *dev, int num)
{
	audigyls_port_t		*port;
	size_t			len;
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			dir;
	unsigned		caps;
	audio_dev_t		*adev;

	adev = dev->adev;
	port = kmem_zalloc(sizeof (*port), KM_SLEEP);
	dev->port[num] = port;
	port->dev = dev;
	port->direction = num;

	switch (num) {
	case AUDIGYLS_REC_PORT:
		port->syncdir = DDI_DMA_SYNC_FORKERNEL;
		caps = ENGINE_INPUT_CAP;
		dir = DDI_DMA_READ;
		port->nchan = 2;
		break;
	case AUDIGYLS_PLAY_PORT:
		port->syncdir = DDI_DMA_SYNC_FORDEV;
		caps = ENGINE_OUTPUT_CAP;
		dir = DDI_DMA_WRITE;
		port->nchan = 6;
		break;
	default:
		return (DDI_FAILURE);
	}

	port->buf_frames = 2048;
	port->buf_size = port->buf_frames * port->nchan * sizeof (int16_t);

	/* Alloc buffers */
	if (ddi_dma_alloc_handle(dev->dip, &dma_attr_buf, DDI_DMA_SLEEP, NULL,
	    &port->buf_dmah) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate BUF handle");
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(port->buf_dmah, port->buf_size,
	    &buf_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &port->buf_kaddr, &len, &port->buf_acch) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate BUF memory");
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(port->buf_dmah, NULL, port->buf_kaddr,
	    len, DDI_DMA_CONSISTENT | dir, DDI_DMA_SLEEP, NULL, &cookie,
	    &count) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed binding BUF DMA handle");
		return (DDI_FAILURE);
	}
	port->buf_paddr = cookie.dmac_address;

	port->engine = audio_engine_alloc(&audigyls_engine_ops, caps);
	if (port->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(port->engine, port);
	audio_dev_add_engine(adev, port->engine);

	return (DDI_SUCCESS);
}

void
audigyls_del_controls(audigyls_dev_t *dev)
{
	for (int i = 0; i < CTL_NUM; i++) {
		if (dev->controls[i].ctrl) {
			audio_dev_del_control(dev->controls[i].ctrl);
			dev->controls[i].ctrl = NULL;
		}
	}
}

void
audigyls_destroy(audigyls_dev_t *dev)
{
	mutex_destroy(&dev->mutex);
	mutex_destroy(&dev->low_mutex);

	for (int i = 0; i < AUDIGYLS_NUM_PORT; i++) {
		audigyls_port_t *port = dev->port[i];
		if (!port)
			continue;
		if (port->engine) {
			audio_dev_remove_engine(dev->adev, port->engine);
			audio_engine_free(port->engine);
		}
		if (port->buf_paddr) {
			(void) ddi_dma_unbind_handle(port->buf_dmah);
		}
		if (port->buf_acch) {
			ddi_dma_mem_free(&port->buf_acch);
		}
		if (port->buf_dmah) {
			ddi_dma_free_handle(&port->buf_dmah);
		}
		kmem_free(port, sizeof (*port));
	}

	if (dev->ac97 != NULL) {
		ac97_free(dev->ac97);
	}

	audigyls_del_controls(dev);

	if (dev->adev != NULL) {
		audio_dev_free(dev->adev);
	}
	if (dev->regsh != NULL) {
		ddi_regs_map_free(&dev->regsh);
	}
	if (dev->pcih != NULL) {
		pci_config_teardown(&dev->pcih);
	}
	kmem_free(dev, sizeof (*dev));
}

void
audigyls_hwinit(audigyls_dev_t *dev)
{
	static unsigned int spi_dac[] = {
		0x00ff, 0x02ff, 0x0400, 0x520, 0x0620, 0x08ff, 0x0aff, 0x0cff,
		0x0eff, 0x10ff, 0x1200, 0x1400, 0x1800, 0x1aff, 0x1cff,
		0x1e00, 0x0530, 0x0602, 0x0622, 0x1400,
	};

	uint32_t	tmp;
	int		i, tries;
	uint32_t	paddr;
	uint32_t	chunksz;
	audigyls_port_t	*port;


	/* Set the orange jack to be analog out or S/PDIF */
	select_digital_enable(dev, dev->digital_enable);

	/*
	 * In P17, there's 8 GPIO pins.
	 * GPIO register: 0x00XXYYZZ
	 * XX: Configure GPIO to be either GPI (0) or GPO (1).
	 * YY: GPO values, applicable if the pin is configure to be GPO.
	 * ZZ: GPI values, applicable if the pin is configure to be GPI.
	 *
	 * in SB570, pin 0-4 and 6 is used as GPO and pin 5 and 7 is
	 * used as GPI.
	 *
	 * GPO0:
	 * 1 ==> Analog output
	 * 0 ==> Digital output
	 * GPO1:
	 * 1 ==> Enable output on card
	 * 0 ==> Disable output on card
	 * GPO2:
	 * 1 ==> Enable Mic Bias and Mic Path
	 * 0 ==> Disable Mic Bias and Mic Path
	 * GPO3:
	 * 1 ==> Disable SPDIF-IO output
	 * 0 ==> Enable SPDIF-IO output
	 * GPO4 and GPO6:
	 * DAC sampling rate selection:
	 * Not applicable to SB570 since DAC is controlled through SPI
	 * GPI5:
	 * 1 ==> Front Panel is not connected
	 * 0 ==> Front Panel is connected
	 * GPI7:
	 * 1 ==> Front Panel Headphone is not connected
	 * 0 ==> Front Panel Headphone is connected
	 */
	if (dev->ac97)
		OUTL(dev, GPIO, 0x005f03a3);
	else {
		/* for SBLive 7.1 */
		OUTL(dev, GPIO, 0x005f4301);

		audigyls_i2c_write(dev, 0x15, 0x2);
		tries = 0;
	again:
		for (i = 0; i < sizeof (spi_dac); i++) {
			if (!audigyls_spi_write(dev, spi_dac[i]) &&
			    tries < 100) {
				tries++;
				goto again;
			}
		}
	}

	OUTL(dev, IER, 0);
	OUTL(dev, HC, 0x00000009);	/* Enable audio, use 48 kHz */

	tmp = read_chan(dev, SRCTL, 0);
	if (dev->ac97)
		tmp |= 0xf0c81000;	/* Record src0/src1 from ac97 */
	else
		tmp |= 0x50c81000;	/* Record src0/src1 from I2SIN */
	tmp &= ~0x0303c00f;		/* Set sample rates to 48 kHz */
	write_chan(dev, SRCTL, 0, tmp);

	write_reg(dev, HMIXMAP_I2S, 0x76543210);	/* Default out route */
	write_reg(dev, AUDCTL, 0x0f0f003f);	/* Enable all outputs */

	/* All audio stopped! */
	write_reg(dev, SA, 0);

	for (i = 0; i < 4; i++) {
		/*
		 * Reset DMA pointers and counters.  Note that we do
		 * not use scatter/gather.
		 */
		write_chan(dev, PTBA, i, 0);
		write_chan(dev, PTBS, i, 0);
		write_chan(dev, PTCA, i, 0);

		write_chan(dev, CPFA, i, 0);
		write_chan(dev, PFEA, i, 0);
		write_chan(dev, CPCAV, i, 0);

		write_chan(dev, CRFA, i, 0);
		write_chan(dev, CRCAV, i, 0);
	}

	/*
	 * The 5.1 play port made up channels 0, 1, and 3.  The record
	 * port is channel 2.
	 */
	port = dev->port[AUDIGYLS_PLAY_PORT];
	paddr = port->buf_paddr;
	chunksz = port->buf_frames * 4;
	write_chan(dev, PFBA, 0, paddr);
	write_chan(dev, PFBS, 0, chunksz << 16);
	paddr += chunksz;
	write_chan(dev, PFBA, 1, paddr);
	write_chan(dev, PFBS, 1, chunksz << 16);
	paddr += chunksz;
	write_chan(dev, PFBA, 3, paddr);
	write_chan(dev, PFBS, 3, chunksz << 16);

	/* Record */
	port = dev->port[AUDIGYLS_REC_PORT];
	paddr = port->buf_paddr;
	chunksz = port->buf_frames * 4;
	write_chan(dev, RFBA, 2, paddr);
	write_chan(dev, RFBS, 2, chunksz << 16);

	/* Set sample rates to 48 kHz. */
	tmp = read_chan(dev, SRCTL, 0) & ~0x0303c00f;
	write_chan(dev, SRCTL, 0, tmp);

	write_reg(dev, SCS0, 0x02108004);	/* Audio */
	write_reg(dev, SCS1, 0x02108004);	/* Audio */
	write_reg(dev, SCS2, 0x02108004);	/* Audio */
	write_reg(dev, SCS3, 0x02108004);	/* Audio */
}

#define	PLAYCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_PLAY)
#define	RECCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_REC)
#define	MONCTL	(AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_MONITOR)
#define	PCMVOL	(PLAYCTL | AUDIO_CTRL_FLAG_PCMVOL)
#define	MAINVOL	(PLAYCTL | AUDIO_CTRL_FLAG_MAINVOL)
#define	RECVOL	(RECCTL | AUDIO_CTRL_FLAG_RECVOL)
#define	MONVOL	(MONCTL | AUDIO_CTRL_FLAG_MONVOL)

#define	MASK(nbits)	((1 << (nbits)) - 1)
#define	SCALE(val, nbits)	\
	((uint8_t)((((val) * MASK(nbits)) / 100)) << (8 - (nbits)))

static uint32_t
audigyls_stereo_scale(uint32_t value, uint8_t bits)
{
	uint8_t			left, right;
	uint32_t		val;

	left = (value >> 8) & 0xff;
	right = value & 0xff;

	val = (((left * ((1 << bits) - 1) / 100) << 8) |
	    (right * ((1 << bits) - 1) / 100));
	return (val);
}

static void
audigyls_configure_mixer(audigyls_dev_t *dev)
{
	unsigned int	r, v1, v2;

	/* output items */
	/* front */
	r = 0xffff - audigyls_stereo_scale(dev->controls[CTL_FRONT].val, 8);
	r = (r << 16) | r;
	write_chan(dev, MIXVOL_I2S, 0, r);

	/* surround */
	r = 0xffff - audigyls_stereo_scale(dev->controls[CTL_SURROUND].val, 8);
	r = (r << 16) | r;
	write_chan(dev, MIXVOL_I2S, 3, r);

	/* center/lfe */
	v1 = 255 - SCALE(dev->controls[CTL_CENTER].val, 8);
	v2 = 255 - SCALE(dev->controls[CTL_LFE].val, 8);
	r = (v1 << 8) | v2;
	r = (r << 16) | r;
	write_chan(dev, MIXVOL_I2S, 1, r);

	/* spread */
	r = dev->controls[CTL_SPREAD].val ? 0x10101010 : 0x76543210;
	write_reg(dev, HMIXMAP_I2S, r);

	/* input items */

	/* recgain */
	v1 = dev->controls[CTL_RECORDVOL].val;
	if (dev->ac97_recgain && !dev->controls[CTL_LOOP].val) {
		/*
		 * For AC'97, we use the AC'97 record gain, unless we are
		 * in loopback.
		 */
		(void) ac97_control_set(dev->ac97_recgain, v1);
		write_reg(dev, P17RECVOLL, 0x30303030);
		write_reg(dev, P17RECVOLH, 0x30303030);
	} else {
		/*
		 * Otherwise we set the P17 gain.
		 */
		r = 0xffff - audigyls_stereo_scale(v1, 8);
		r = r << 16 | r;
		write_reg(dev, P17RECVOLL, r);
		write_reg(dev, P17RECVOLH, r);
	}

	/* monitor gain */
	if (dev->ac97) {
		/* AC'97 monitor gain is done by the AC'97 codec */
		write_chan(dev, SRCTL, 1, 0x30303030);
		write_reg(dev, SMIXMAP_I2S, 0x10101076);
	} else {
		/* For non-AC'97 devices, just a single master monitor gain */
		r = 255 - SCALE(dev->controls[CTL_MONGAIN].val, 8);
		write_chan(dev, SRCTL, 1, 0xffff0000 | r << 8 | r);
		if (r != 0xff) {
			write_reg(dev, SMIXMAP_I2S, 0x10101076);
		} else {
			write_reg(dev, SMIXMAP_I2S, 0x10101010);
		}
	}

	/* record source */
	if (dev->ac97_recsrc != NULL) {
		(void) ac97_control_set(dev->ac97_recsrc,
		    dev->controls[CTL_RECSRC].val);
		v1 = RECSEL_AC97;	/* Audigy LS */
	} else {
		switch (dev->controls[CTL_RECSRC].val) {
		case 1:
			audigyls_i2c_write(dev, 0x15, 0x2);   /* Mic */
			OUTL(dev, GPIO, INL(dev, GPIO) | 0x400);
			break;

		case 2:
			audigyls_i2c_write(dev, 0x15, 0x4);   /* Line */
			OUTL(dev, GPIO, INL(dev, GPIO) & ~0x400);
			break;
		}
		v1 = RECSEL_I2SIN;	/* SB 7.1 value */
	}

	/* If loopback, record what you hear instead */

	if (dev->controls[CTL_LOOP].val) {
		r = 0;
		v1 = RECSEL_I2SOUT;
		r |= (v1 << 28) | (v1 << 24) | (v1 << 20) | (v1 << 16) | v1;
	} else {
		/*
		 * You'd think this would be the same as the logic
		 * above, but experience shows that what you need for
		 * loopback is different.  This whole thing looks
		 * particularly fishy to me.  I suspect someone has
		 * made a mistake somewhere.  But I can't seem to
		 * figure out where it lies.
		 */
		if (dev->ac97_recsrc != NULL) {
			r = 0xe4;
			for (int i = 0; i < 4; i++)
				r |= v1 << (16 + i * 3); /* Select input */
		} else {
			r = (v1 << 28) | (v1 << 24) | (v1 << 20) | (v1 << 16) |
			    v1;
		}
	}

	write_reg(dev, P17RECSEL, r);
}

static int
audigyls_set_control(void *arg, uint64_t val)
{
	audigyls_ctrl_t	*pc = arg;
	audigyls_dev_t	*dev = pc->dev;

	switch (pc->num) {

	case CTL_FRONT:
	case CTL_SURROUND:
	case CTL_RECORDVOL:
		if (((val & 0xff) > 100) ||
		    (((val & 0xff00) >> 8) > 100) ||
		    ((val & ~0xffff) != 0)) {
			return (EINVAL);
		}
		break;

	case CTL_CENTER:
	case CTL_LFE:
	case CTL_MONGAIN:
		if (val > 100) {
			return (EINVAL);
		}
		break;

	case CTL_RECSRC:
		if (((1U << val) & (dev->recmask)) == 0) {
			return (EINVAL);
		}
		break;

	case CTL_SPREAD:
	case CTL_LOOP:
		switch (val) {
		case 0:
		case 1:
			break;
		default:
			return (EINVAL);
		}
	}

	mutex_enter(&dev->mutex);
	pc->val = val;
	audigyls_configure_mixer(dev);

	mutex_exit(&dev->mutex);

	return (0);
}

static int
audigyls_get_control(void *arg, uint64_t *val)
{
	audigyls_ctrl_t	*pc = arg;
	audigyls_dev_t	*dev = pc->dev;

	mutex_enter(&dev->mutex);
	*val = pc->val;
	mutex_exit(&dev->mutex);
	return (0);
}

static void
audigyls_alloc_ctrl(audigyls_dev_t *dev, uint32_t num, uint64_t val)
{
	audio_ctrl_desc_t	desc;
	audigyls_ctrl_t		*pc;

	bzero(&desc, sizeof (desc));

	pc = &dev->controls[num];
	pc->num = num;
	pc->dev = dev;


	switch (num) {
	case CTL_FRONT:
		desc.acd_name = AUDIO_CTRL_ID_FRONT;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		break;

	case CTL_SURROUND:
		desc.acd_name = AUDIO_CTRL_ID_SURROUND;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		break;

	case CTL_CENTER:
		desc.acd_name = AUDIO_CTRL_ID_CENTER;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		break;

	case CTL_LFE:
		desc.acd_name = AUDIO_CTRL_ID_LFE;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		break;

	case CTL_RECORDVOL:
		desc.acd_name = AUDIO_CTRL_ID_RECGAIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		break;

	case CTL_RECSRC:
		desc.acd_name = AUDIO_CTRL_ID_RECSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_flags = RECCTL;

		/*
		 * For AC'97 devices, we want to expose the reasonable
		 * AC'97 input sources, but suppress the stereomix,
		 * because we use loopback instead.
		 */
		if (dev->ac97_recsrc) {
			int i, j;
			const char *n;
			const audio_ctrl_desc_t *adp;

			adp = ac97_control_desc(dev->ac97_recsrc);
			for (i = 0; i < 64; i++) {
				n = adp->acd_enum[i];

				if (((adp->acd_minvalue & (1 << i)) == 0) ||
				    (n == NULL)) {
					continue;
				}
				for (j = 0; audigyls_badsrcs[j]; j++) {
					if (strcmp(n, audigyls_badsrcs[j])
					    == 0) {
						n = NULL;
						break;
					}
				}
				if (n) {
					desc.acd_enum[i] = n;
					dev->recmask |= (1 << i);
				}
			}
			desc.acd_minvalue = desc.acd_maxvalue = dev->recmask;
		} else {
			dev->recmask = 3;
			desc.acd_minvalue = 3;
			desc.acd_maxvalue = 3;
			desc.acd_enum[0] = AUDIO_PORT_MIC;
			desc.acd_enum[1] = AUDIO_PORT_LINEIN;
		}
		break;

	case CTL_MONGAIN:
		ASSERT(!dev->ac97);
		desc.acd_name = AUDIO_CTRL_ID_MONGAIN;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MONVOL;
		break;

	case CTL_SPREAD:
		desc.acd_name = AUDIO_CTRL_ID_SPREAD;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = PLAYCTL;
		break;

	case CTL_LOOP:
		desc.acd_name = AUDIO_CTRL_ID_LOOPBACK;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 1;
		desc.acd_flags = RECCTL;
		break;
	}

	pc->val = val;
	pc->ctrl = audio_dev_add_control(dev->adev, &desc,
	    audigyls_get_control, audigyls_set_control, pc);
}

static void
audigyls_add_controls(audigyls_dev_t *dev)
{
	audio_dev_add_soft_volume(dev->adev);

	audigyls_alloc_ctrl(dev, CTL_FRONT, 75 | (75 << 8));
	audigyls_alloc_ctrl(dev, CTL_SURROUND, 75 | (75 << 8));
	audigyls_alloc_ctrl(dev, CTL_CENTER, 75);
	audigyls_alloc_ctrl(dev, CTL_LFE, 75);
	audigyls_alloc_ctrl(dev, CTL_RECORDVOL, 75 | (75 << 8));
	audigyls_alloc_ctrl(dev, CTL_RECSRC, 1);
	audigyls_alloc_ctrl(dev, CTL_SPREAD, 0);
	audigyls_alloc_ctrl(dev, CTL_LOOP, 0);
	if (!dev->ac97) {
		audigyls_alloc_ctrl(dev, CTL_MONGAIN, 0);
	}
}

int
audigyls_attach(dev_info_t *dip)
{
	uint16_t	pci_command, vendor, device;
	uint32_t	subdevice;
	audigyls_dev_t	*dev;
	ddi_acc_handle_t pcih;
	const char	*name, *version;
	boolean_t	ac97 = B_FALSE;

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->dip = dip;
	ddi_set_driver_private(dip, dev);
	mutex_init(&dev->mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dev->low_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((dev->adev = audio_dev_alloc(dip, 0)) == NULL) {
		cmn_err(CE_WARN, "audio_dev_alloc failed");
		goto error;
	}

	if (pci_config_setup(dip, &pcih) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "pci_config_setup failed");
		goto error;
	}
	dev->pcih = pcih;

	vendor = pci_config_get16(pcih, PCI_CONF_VENID);
	device = pci_config_get16(pcih, PCI_CONF_DEVID);
	subdevice = pci_config_get16(pcih, PCI_CONF_SUBVENID);
	subdevice <<= 16;
	subdevice |= pci_config_get16(pcih, PCI_CONF_SUBSYSID);
	if (vendor != PCI_VENDOR_ID_CREATIVE ||
	    device != PCI_DEVICE_ID_CREATIVE_AUDIGYLS) {
		audio_dev_warn(dev->adev, "Hardware not recognized "
		    "(vendor=%x, dev=%x)", vendor, device);
		goto error;
	}

	pci_command = pci_config_get16(pcih, PCI_CONF_COMM);
	pci_command |= PCI_COMM_ME | PCI_COMM_IO;
	pci_config_put16(pcih, PCI_CONF_COMM, pci_command);

	if ((ddi_regs_map_setup(dip, 1, &dev->base, 0, 0, &dev_attr,
	    &dev->regsh)) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "failed to map registers");
		goto error;
	}

	/* Function of the orange jack: 0=analog, 1=digital */
	dev->digital_enable = ddi_prop_get_int(DDI_DEV_T_ANY, dev->dip,
	    DDI_PROP_DONTPASS, "digital-enable", 0);

	switch (subdevice) {
	case 0x11021001:	/* SB0310 */
	case 0x11021002:	/* SB0310 */
	case 0x11021005:	/* SB0310b */
		name = "Creative Audigy LS";
		version = "SB0310";	/* could also be SB0312 */
		ac97 = B_TRUE;
		break;
	case 0x11021006:
		name = "Creative Sound Blaster Live! 24 bit";
		version = "SB0410";
		break;
	case 0x11021007:	/* Dell OEM version */
		name = "Creative Sound Blaster Live! 24 bit";
		version = "SB0413";
		break;
	case 0x1102100a:
		name = "Creative Audigy SE";
		version = "SB0570";
		break;
	case 0x11021011:
		name = "Creative Audigy SE OEM";
		version = "SB0570a";
		break;
	case 0x11021012:
		name = "Creative X-Fi Extreme Audio";
		version = "SB0790";
		break;
	case 0x14621009:
		name = "MSI K8N Diamond MB";
		version = "SB0438";
		break;
	case 0x12973038:
		name = "Shuttle XPC SD31P";
		version = "SD31P";
		break;
	case 0x12973041:
		name = "Shuttle XPC SD11G5";
		version = "SD11G5";
		break;
	default:
		name = "Creative Audigy LS";
		version = NULL;
		break;
	}

	audio_dev_set_description(dev->adev, name);
	if (version)
		audio_dev_set_version(dev->adev, version);

	if (ac97) {
		ac97_ctrl_t *ctrl;

		/* Original Audigy LS revision (AC97 based) */
		dev->ac97 = ac97_allocate(dev->adev, dip,
		    audigyls_read_ac97, audigyls_write_ac97, dev);
		if (dev->ac97 == NULL) {
			audio_dev_warn(dev->adev,
			    "failed to allocate ac97 handle");
			goto error;
		}

		ac97_probe_controls(dev->ac97);

		/* remove the AC'97 controls we don't want to expose */
		for (int i = 0; audigyls_remove_ac97[i]; i++) {
			ctrl = ac97_control_find(dev->ac97,
			    audigyls_remove_ac97[i]);
			if (ctrl != NULL) {
				ac97_control_unregister(ctrl);
			}
		}

		dev->ac97_recgain = ac97_control_find(dev->ac97,
		    AUDIO_CTRL_ID_RECGAIN);
		dev->ac97_recsrc = ac97_control_find(dev->ac97,
		    AUDIO_CTRL_ID_RECSRC);
	}

	audigyls_add_controls(dev);

	if (dev->ac97) {
		ac97_register_controls(dev->ac97);
	}

	if (audigyls_alloc_port(dev, AUDIGYLS_PLAY_PORT) != DDI_SUCCESS)
		goto error;
	if (audigyls_alloc_port(dev, AUDIGYLS_REC_PORT) != DDI_SUCCESS)
		goto error;

	audigyls_hwinit(dev);

	audigyls_configure_mixer(dev);

	if (audio_dev_register(dev->adev) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "unable to register with framework");
		goto error;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	audigyls_destroy(dev);
	return (DDI_FAILURE);
}

int
audigyls_resume(dev_info_t *dip)
{
	audigyls_dev_t *dev;

	dev = ddi_get_driver_private(dip);

	audigyls_hwinit(dev);

	/* allow ac97 operations again */
	if (dev->ac97)
		ac97_reset(dev->ac97);

	audio_dev_resume(dev->adev);

	return (DDI_SUCCESS);
}

int
audigyls_detach(audigyls_dev_t *dev)
{
	if (audio_dev_unregister(dev->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	audigyls_destroy(dev);
	return (DDI_SUCCESS);
}

int
audigyls_suspend(audigyls_dev_t *dev)
{
	audio_dev_suspend(dev->adev);

	return (DDI_SUCCESS);
}

static int audigyls_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int audigyls_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int audigyls_ddi_quiesce(dev_info_t *);

static struct dev_ops audigyls_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	audigyls_ddi_attach,	/* attach */
	audigyls_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	audigyls_ddi_quiesce,	/* quiesce */
};

static struct modldrv audigyls_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Creative Audigy LS Audio",		/* linkinfo */
	&audigyls_dev_ops,			/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &audigyls_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&audigyls_dev_ops, AUDIGYLS_NAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&audigyls_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&audigyls_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
audigyls_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (audigyls_attach(dip));

	case DDI_RESUME:
		return (audigyls_resume(dip));

	default:
		return (DDI_FAILURE);
	}
}

int
audigyls_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audigyls_dev_t *dev;

	dev = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		return (audigyls_detach(dev));

	case DDI_SUSPEND:
		return (audigyls_suspend(dev));

	default:
		return (DDI_FAILURE);
	}
}

int
audigyls_ddi_quiesce(dev_info_t *dip)
{
	audigyls_dev_t	*dev;
	uint32_t status;

	/*
	 * Turn off the hardware
	 */
	dev = ddi_get_driver_private(dip);

	write_reg(dev, SA, 0);
	OUTL(dev, IER, 0);	/* Interrupt disable */
	write_reg(dev, AIE, 0);	/* Disable audio interrupts */
	status = INL(dev, IPR);
	OUTL(dev, IPR, status);	/* Acknowledge */
	return (DDI_SUCCESS);
}
