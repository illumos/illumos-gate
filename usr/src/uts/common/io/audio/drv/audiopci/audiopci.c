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
 * Purpose: Creative/Ensoniq AudioPCI  driver (ES1370)
 *
 * This driver is used with the original Ensoniq AudioPCI.
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

#include <sys/audio/audio_driver.h>
#include <sys/note.h>
#include <sys/pci.h>
#include "audiopci.h"

/*
 * The original OSS driver used a single duplex engine and a separate
 * playback only engine.  Instead, we expose three engines, one for input
 * and two for output.
 */

#define	ENSONIQ_VENDOR_ID	0x1274
#define	CREATIVE_VENDOR_ID	0x1102
#define	ENSONIQ_ES1370		0x5000

#define	DRVNAME			"audiopci"

#define	INPUT_MIC	0
#define	INPUT_LINEIN	1
#define	INPUT_CD	2
#define	INPUT_VIDEO	3
#define	INPUT_PHONE	4
#define	INSRCS		0x1f		/* bits 0-4 */

static const char *audiopci_insrcs[] = {
	AUDIO_PORT_MIC,
	AUDIO_PORT_LINEIN,
	AUDIO_PORT_CD,
	AUDIO_PORT_VIDEO,
	AUDIO_PORT_PHONE,
	NULL
};

typedef struct audiopci_port
{
	/* Audio parameters */
	int			speed;
	int			fmt;

	int			num;
#define	PORT_DAC		0
#define	PORT_SYN		1
#define	PORT_ADC		2
#define	PORT_MAX		PORT_ADC

	caddr_t			kaddr;
	uint32_t		paddr;
	ddi_acc_handle_t	acch;
	ddi_dma_handle_t	dmah;
	unsigned		nframes;
	unsigned		frameno;
	uint64_t		count;

	struct audiopci_dev	*dev;
	audio_engine_t		*engine;
} audiopci_port_t;

typedef enum {
	CTL_VOLUME = 0,
	CTL_FRONT,
	CTL_MONO,
	CTL_MIC,
	CTL_LINE,
	CTL_CD,
	CTL_VID,
	CTL_PHONE,
	CTL_MICBOOST,
	CTL_RECSRC,
	CTL_MONSRC,
	CTL_NUM		/* must be last */
} audiopci_ctrl_num_t;

typedef struct audiopci_ctrl
{
	struct audiopci_dev	*dev;
	audio_ctrl_t		*ctrl;
	audiopci_ctrl_num_t	num;
	uint64_t		val;
} audiopci_ctrl_t;


typedef struct audiopci_dev
{
	audio_dev_t		*adev;
	kmutex_t		mutex;
	uint16_t		devid;
	dev_info_t		*dip;

	uint8_t			ak_regs[0x20];
	int			micbias;

	/*
	 * Controls
	 */
	audiopci_ctrl_t		controls[CTL_NUM];
#if 0
	audiopci_ctrl_t		*micbias;
#endif

	audiopci_port_t		port[PORT_MAX + 1];


	caddr_t			regs;
	ddi_acc_handle_t	acch;
} audiopci_dev_t;

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
 * The hardware appears to be able to address up to 16-bits worth of longwords,
 * giving a total address space of 256K.  But we need substantially less.
 */
#define	AUDIOPCI_BUF_LEN	(16384)

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

static void audiopci_init_hw(audiopci_dev_t *);
static void audiopci_init_port(audiopci_port_t *);
static uint16_t audiopci_dac_rate(int);
static int audiopci_add_controls(audiopci_dev_t *);
static void audiopci_del_controls(audiopci_dev_t *);
static void audiopci_ak_write(audiopci_dev_t *, uint16_t, uint8_t);

static int
audiopci_ak_wait(audiopci_dev_t *dev, uint8_t wstat)
{
	for (int i = 4000; i; i--) {
		if (!(GET8(dev, CONC_bCODECSTAT_OFF) & wstat))
			return (DDI_SUCCESS);
		drv_usecwait(10);
	}
	return (DDI_FAILURE);
}

static void
audiopci_ak_idle(audiopci_dev_t *dev)
{
	for (int i = 0; i < 5; i++) {
		if (audiopci_ak_wait(dev, CONC_CSTAT_CSTAT) == DDI_SUCCESS)
			return;
	}
	audio_dev_warn(dev->adev, "timed out waiting for codec to idle");
}

static void
audiopci_ak_write(audiopci_dev_t *dev, uint16_t addr, uint8_t data)
{
	uint8_t	wstat;

	/* shadow the value */
	dev->ak_regs[addr] = data;

	wstat = addr == CODEC_RESET_PWRD ? CONC_CSTAT_CWRIP : CONC_CSTAT_CSTAT;

	/* wait for codec to be available */
	if (audiopci_ak_wait(dev, wstat) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "timeout waiting for codec");
	}

	PUT16(dev, CONC_wCODECCTL_OFF, (addr << 8) | data);
}

static void
audiopci_writemem(audiopci_dev_t *dev, uint32_t page, uint32_t offs,
    uint32_t data)
{
	/* Select memory page */
	PUT32(dev, CONC_bMEMPAGE_OFF, page);
	PUT32(dev, offs, data);
}

static uint32_t
audiopci_readmem(audiopci_dev_t *dev, uint32_t page, uint32_t offs)
{
	PUT32(dev, CONC_bMEMPAGE_OFF, page);	/* Select memory page */
	return (GET32(dev, offs));
}

/*
 * Audio routines
 */

static int
audiopci_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));
	return (AUDIO_FORMAT_S16_LE);
}

static int
audiopci_channels(void *arg)
{
	_NOTE(ARGUNUSED(arg));
	return (2);
}

static int
audiopci_rate(void *arg)
{
	audiopci_port_t	*port = arg;

	return (port->speed);
}

static void
audiopci_init_port(audiopci_port_t *port)
{
	audiopci_dev_t	*dev = port->dev;
	unsigned tmp;

	switch (port->num) {
	case PORT_DAC:

		/* Set physical address of the DMA buffer */
		audiopci_writemem(dev, CONC_DACCTL_PAGE, CONC_dDACPADDR_OFF,
		    port->paddr);

		/* Set DAC rate */
		PUT16(dev, CONC_wDACRATE_OFF, audiopci_dac_rate(48000));

		/* Set format */
		tmp = GET8(dev, CONC_bSERFMT_OFF);
		tmp |= CONC_PCM_DAC_16BIT;
		tmp |= CONC_PCM_DAC_STEREO;

		PUT8(dev, CONC_bSKIPC_OFF, 0x10);
		PUT8(dev, CONC_bSERFMT_OFF, tmp);

		/* Set the frame count */
		audiopci_writemem(dev, CONC_DACCTL_PAGE, CONC_wDACFC_OFF,
		    port->nframes - 1);

		/* Set # of frames between interrupts */
		PUT16(dev, CONC_wDACIC_OFF, port->nframes - 1);

		break;

	case PORT_SYN:

		/* Set physical address of the DMA buffer */
		audiopci_writemem(dev, CONC_SYNCTL_PAGE, CONC_dSYNPADDR_OFF,
		    port->paddr);

		/* Set rate - we force to 44.1 kHz */
		SET8(dev, CONC_bMISCCTL_OFF, CONC_MISCCTL_SYN_44KHZ);

		/* Set format */
		tmp = GET8(dev, CONC_bSERFMT_OFF);
		tmp |= CONC_PCM_SYN_16BIT;
		tmp |= CONC_PCM_SYN_STEREO;

		PUT8(dev, CONC_bSERFMT_OFF, tmp);

		/* Set the frame count */
		audiopci_writemem(dev, CONC_SYNCTL_PAGE, CONC_wSYNFC_OFF,
		    port->nframes - 1);

		/* Set # of frames between interrupts */
		PUT16(dev, CONC_wSYNIC_OFF, port->nframes - 1);

		break;

	case PORT_ADC:
		/* Set physical address of the DMA buffer */
		audiopci_writemem(dev, CONC_ADCCTL_PAGE, CONC_dADCPADDR_OFF,
		    port->paddr);

		/* Set ADC rate */
		PUT16(dev, CONC_wDACRATE_OFF, audiopci_dac_rate(48000));

		/* Set format - for input we only support 16 bit input */
		tmp = GET8(dev, CONC_bSERFMT_OFF);
		tmp |= CONC_PCM_ADC_16BIT;
		tmp |= CONC_PCM_ADC_STEREO;

		PUT8(dev, CONC_bSKIPC_OFF, 0x10);

		PUT8(dev, CONC_bSERFMT_OFF, tmp);

		/* Set the frame count */
		audiopci_writemem(dev, CONC_ADCCTL_PAGE, CONC_wADCFC_OFF,
		    port->nframes - 1);

		/* Set # of frames between interrupts */
		PUT16(dev, CONC_wADCIC_OFF, port->nframes - 1);

		break;
	}

	port->frameno = 0;
}

static int
audiopci_open(void *arg, int flag, unsigned *nframes, caddr_t *bufp)
{
	audiopci_port_t	*port = arg;

	_NOTE(ARGUNUSED(flag));

	/* NB: frame size = 4 (16-bit stereo) */
	port->nframes = AUDIOPCI_BUF_LEN / 4;
	port->count = 0;

	*nframes = port->nframes;
	*bufp = port->kaddr;

	return (0);
}

static int
audiopci_start(void *arg)
{
	audiopci_port_t *port = arg;
	audiopci_dev_t *dev = port->dev;

	mutex_enter(&dev->mutex);

	audiopci_init_port(port);

	switch (port->num) {
	case PORT_DAC:
		SET8(dev, CONC_bDEVCTL_OFF, CONC_DEVCTL_DAC_EN);
		break;
	case PORT_SYN:
		SET8(dev, CONC_bDEVCTL_OFF, CONC_DEVCTL_SYN_EN);
		break;
	case PORT_ADC:
		SET8(dev, CONC_bDEVCTL_OFF, CONC_DEVCTL_ADC_EN);
		break;
	}
	mutex_exit(&dev->mutex);

	return (0);
}

static void
audiopci_stop(void *arg)
{
	audiopci_port_t *port = arg;
	audiopci_dev_t *dev = port->dev;

	mutex_enter(&dev->mutex);
	switch (port->num) {
	case PORT_DAC:
		CLR8(dev, CONC_bDEVCTL_OFF, CONC_DEVCTL_DAC_EN);
		break;
	case PORT_SYN:
		CLR8(dev, CONC_bDEVCTL_OFF, CONC_DEVCTL_SYN_EN);
		break;
	case PORT_ADC:
		CLR8(dev, CONC_bDEVCTL_OFF, CONC_DEVCTL_ADC_EN);
		break;
	}
	mutex_exit(&dev->mutex);
}

static uint64_t
audiopci_count(void *arg)
{
	audiopci_port_t *port = arg;
	audiopci_dev_t *dev = port->dev;
	uint64_t val;
	uint32_t page, offs;
	int frameno, n;

	switch (port->num) {
	case PORT_DAC:
		page = CONC_DACCTL_PAGE;
		offs = CONC_wDACFC_OFF;
		break;

	case PORT_SYN:
		page = CONC_SYNCTL_PAGE;
		offs = CONC_wSYNFC_OFF;
		break;

	case PORT_ADC:
		page = CONC_ADCCTL_PAGE;
		offs = CONC_wADCFC_OFF;
		break;
	}

	/*
	 * Note that the current frame counter is in the high nybble.
	 */
	mutex_enter(&dev->mutex);
	frameno = audiopci_readmem(port->dev, page, offs) >> 16;
	mutex_exit(&dev->mutex);

	n = frameno >= port->frameno ?
	    frameno - port->frameno :
	    frameno + port->nframes - port->frameno;
	port->frameno = frameno;
	port->count += n;

	val = port->count;
	return (val);
}

static void
audiopci_close(void *arg)
{
	_NOTE(ARGUNUSED(arg));
}

static void
audiopci_sync(void *arg, unsigned nframes)
{
	audiopci_port_t *port = arg;

	_NOTE(ARGUNUSED(nframes));

	if (port->num == PORT_ADC) {
		(void) ddi_dma_sync(port->dmah, 0, 0, DDI_DMA_SYNC_FORCPU);
	} else {
		(void) ddi_dma_sync(port->dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	}
}

audio_engine_ops_t audiopci_engine_ops = {
	AUDIO_ENGINE_VERSION,		/* version number */
	audiopci_open,
	audiopci_close,
	audiopci_start,
	audiopci_stop,
	audiopci_count,
	audiopci_format,
	audiopci_channels,
	audiopci_rate,
	audiopci_sync,
	NULL,
	NULL,
	NULL,
};

static uint16_t
audiopci_dac_rate(int samPerSec)
{
	unsigned short usTemp;

	/* samPerSec /= 2; */

	usTemp = (unsigned short) ((DAC_CLOCK_DIVIDE / 8) / samPerSec);

	if (usTemp & 0x00000001) {
		usTemp >>= 1;
		usTemp -= 1;
	} else {
		usTemp >>= 1;
		usTemp -= 2;
	}
	return (usTemp);
}

void
audiopci_init_hw(audiopci_dev_t *dev)
{
	int tmp;

	/* setup DAC frequency */
	PUT16(dev, CONC_wDACRATE_OFF, audiopci_dac_rate(48000));

	CLR8(dev, CONC_bMISCCTL_OFF, CONC_MISCCTL_CCB_INTRM);
	SET8(dev, CONC_bMISCCTL_OFF, CONC_MISCCTL_SYN_44KHZ);

	/* Turn on CODEC (UART and joystick left disabled) */
	tmp = GET8(dev, CONC_bDEVCTL_OFF);
	tmp |= CONC_DEVCTL_SERR_DIS;
	tmp |= CONC_DEVCTL_CODEC_EN;
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);

	/* Reset the UART */
	PUT8(dev, CONC_bUARTCSTAT_OFF, 0x00);

	/* Disable NMI */
	PUT8(dev, CONC_bNMIENA_OFF, 0);
	PUT16(dev, CONC_wNMISTAT_OFF, 0);

	/* Initialize serial interface */
	PUT8(dev, CONC_bSERCTL_OFF, 0);
	PUT8(dev, CONC_bSERFMT_OFF,
	    CONC_PCM_SYN_STEREO | CONC_PCM_SYN_16BIT);

	/* Unmute codec */
	CLR8(dev, CONC_bMISCCTL_OFF, CONC_MISCCTL_MUTE);

	/* mixer initialization */
	audiopci_ak_idle(dev);

	/* power/reset down the codec */
	audiopci_ak_write(dev, CODEC_RESET_PWRD, 0);
	drv_usecwait(10);

	/* now powerup and bring out of reset */
	audiopci_ak_write(dev, CODEC_RESET_PWRD, 0x3);
	audiopci_ak_idle(dev);

	/* enable PLL for DAC2 */
	audiopci_ak_write(dev, CODEC_CLKSELECT, 0);

	/* select input mixer */
	audiopci_ak_write(dev, CODEC_ADSELECT, 0);

	/* mark FM for output mixer */
	audiopci_ak_write(dev, CODEC_OUT_SW1, CODEC_OUT_ENABLE_SYNTH);
	audiopci_ak_write(dev, CODEC_OUT_SW2, CODEC_OUT_ENABLE_WAVE);

	/* initialize some reasonable values for the WAVE and SYNTH inputs */
	audiopci_ak_write(dev, CODEC_VOL_WAVE_L, 6);
	audiopci_ak_write(dev, CODEC_VOL_WAVE_R, 6);
	audiopci_ak_write(dev, CODEC_VOL_SYNTH_L, 6);
	audiopci_ak_write(dev, CODEC_VOL_SYNTH_R, 6);

	/* enable microphone phantom power */
	if (dev->micbias) {
		SET16(dev, 2, CONC_DEVCTL_MICBIAS);
	}
}

static int
audiopci_init(audiopci_dev_t *dev)
{
	dev->micbias = 1;

	audiopci_init_hw(dev);

	for (int i = 0; i <= PORT_MAX; i++) {
		audiopci_port_t *port;
		unsigned caps;
		unsigned dmaflags;
		size_t rlen;
		ddi_dma_cookie_t c;
		unsigned ccnt;

		port = &dev->port[i];
		port->dev = dev;

		switch (i) {
		case PORT_SYN:
			caps = ENGINE_OUTPUT_CAP;
			dmaflags = DDI_DMA_WRITE | DDI_DMA_CONSISTENT;
			port->speed = 44100;
			break;

		case PORT_DAC:
			caps = ENGINE_OUTPUT_CAP;
			dmaflags = DDI_DMA_WRITE | DDI_DMA_CONSISTENT;
			port->speed = 48000;
			break;

		case PORT_ADC:
			caps = ENGINE_INPUT_CAP;
			dmaflags = DDI_DMA_READ | DDI_DMA_CONSISTENT;
			port->speed = 48000;
			break;
		}

		port->num = i;

		/*
		 * Allocate DMA resources.
		 */

		if (ddi_dma_alloc_handle(dev->dip, &dma_attr, DDI_DMA_SLEEP,
		    NULL, &port->dmah) != DDI_SUCCESS) {
			audio_dev_warn(dev->adev,
			    "port %d: dma handle allocation failed", i);
			return (DDI_FAILURE);
		}
		if (ddi_dma_mem_alloc(port->dmah, AUDIOPCI_BUF_LEN, &buf_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &port->kaddr,
		    &rlen, &port->acch) != DDI_SUCCESS) {
			audio_dev_warn(dev->adev,
			    "port %d: dma memory allocation failed", i);
			return (DDI_FAILURE);
		}
		/* ensure that the buffer is zeroed out properly */
		bzero(port->kaddr, rlen);
		if (ddi_dma_addr_bind_handle(port->dmah, NULL, port->kaddr,
		    AUDIOPCI_BUF_LEN, dmaflags, DDI_DMA_SLEEP, NULL,
		    &c, &ccnt) != DDI_DMA_MAPPED) {
			audio_dev_warn(dev->adev,
			    "port %d: dma binding failed", i);
			return (DDI_FAILURE);
		}
		port->paddr = c.dmac_address;

		/*
		 * Allocate and configure audio engine.
		 */
		port->engine = audio_engine_alloc(&audiopci_engine_ops, caps);
		if (port->engine == NULL) {
			audio_dev_warn(dev->adev,
			    "port %d: audio_engine_alloc failed", i);
			return (DDI_FAILURE);
		}

		audio_engine_set_private(port->engine, port);
		audio_dev_add_engine(dev->adev, port->engine);
	}

	/*
	 * Register audio controls.
	 */
	if (audiopci_add_controls(dev) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}


	if (audio_dev_register(dev->adev) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev,
		    "unable to register with audio framework");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
audiopci_destroy(audiopci_dev_t *dev)
{
	int	i;

	mutex_destroy(&dev->mutex);

	/* free up ports, including DMA resources for ports */
	for (i = 0; i <= PORT_MAX; i++) {
		audiopci_port_t	*port = &dev->port[i];

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

	audiopci_del_controls(dev);

	if (dev->adev != NULL) {
		audio_dev_free(dev->adev);
	}

	kmem_free(dev, sizeof (*dev));
}

static void
audiopci_stereo(audiopci_dev_t *dev, audiopci_ctrl_num_t num, uint8_t lreg)
{
	uint8_t		lval, rval;
	uint8_t		lmute, rmute;
	uint64_t	val;
	uint8_t		rreg;

	rreg = lreg + 1;
	val = dev->controls[num].val;
	lval = (val & 0xff00) >> 8;
	rval = val & 0xff;

	lmute = lval ? 0 : CODEC_ATT_MUTE;
	rmute = rval ? 0 : CODEC_ATT_MUTE;

	/* convert to attenuation & apply mute if appropriate */
	lval = ((((100U - lval) * CODEC_ATT_MAX) / 100) & 0xff) | lmute;
	rval = ((((100U - rval) * CODEC_ATT_MAX) / 100) & 0xff) | rmute;

	audiopci_ak_write(dev, lreg, lval);
	audiopci_ak_write(dev, rreg, rval);
}

static void
audiopci_mono(audiopci_dev_t *dev, audiopci_ctrl_num_t num, uint8_t reg)
{
	uint64_t val = (dev->controls[num].val & 0xff);
	uint8_t mute;

	mute = val ? 0 : CODEC_ATT_MUTE;
	val = ((((100U - val) * CODEC_ATT_MAX) / 100) & 0xff) | mute;

	audiopci_ak_write(dev, reg, val);
}

static void
audiopci_mono8(audiopci_dev_t *dev, audiopci_ctrl_num_t num, uint8_t reg)
{
	uint64_t val = (dev->controls[num].val & 0xff);
	uint8_t mute;

	mute = val ? 0 : CODEC_ATT_MUTE;
	val = ((((100U - val) * CODEC_ATT_MONO) / 100) & 0xff) | mute;

	audiopci_ak_write(dev, reg, val);
}

static int
audiopci_get_value(void *arg, uint64_t *val)
{
	audiopci_ctrl_t	*pc = arg;

	*val = pc->val;

	return (0);
}

static void
audiopci_configure_output(audiopci_dev_t *dev)
{
	uint64_t val;
	uint8_t	tmp;

	/* PCM/Wave level */
	audiopci_mono(dev, CTL_VOLUME, CODEC_VOL_WAVE_L);
	audiopci_mono(dev, CTL_VOLUME, CODEC_VOL_WAVE_R);
	audiopci_mono(dev, CTL_VOLUME, CODEC_VOL_SYNTH_L);
	audiopci_mono(dev, CTL_VOLUME, CODEC_VOL_SYNTH_R);

	/* front & mono outputs */
	audiopci_stereo(dev, CTL_FRONT, CODEC_VOL_MASTER_L);
	audiopci_mono8(dev, CTL_MONO, CODEC_VOL_MONO);

	val = dev->controls[CTL_MONSRC].val;

	/* setup output monitoring as well */
	tmp = CODEC_OUT_ENABLE_SYNTH;
	if (val & (1U << INPUT_MIC))
		tmp |= CODEC_OUT_ENABLE_MIC;
	if (val & (1U << INPUT_CD))
		tmp |= CODEC_OUT_ENABLE_CD;
	if (val & (1U << INPUT_LINEIN))
		tmp |= CODEC_OUT_ENABLE_AUX;
	audiopci_ak_write(dev, CODEC_OUT_SW1, tmp);

	tmp = CODEC_OUT_ENABLE_WAVE;
	if (val & (1U << INPUT_VIDEO))
		tmp |= CODEC_OUT_ENABLE_TV;
	if (val & (1U << INPUT_PHONE))
		tmp |= CODEC_OUT_ENABLE_TAD;
	audiopci_ak_write(dev, CODEC_OUT_SW2, tmp);
}

static void
audiopci_configure_input(audiopci_dev_t *dev)
{
	uint64_t	val = dev->controls[CTL_RECSRC].val;
	uint8_t		tmp;

	tmp = 0;
	if (val & (1U << INPUT_LINEIN))
		tmp |= CODEC_IN_ENABLE_AUX_L;
	if (val & (1U << INPUT_CD))
		tmp |= CODEC_IN_ENABLE_CD_L;
	if (val & (1U << INPUT_MIC))
		tmp |= CODEC_IN_ENABLE_MIC;
	if (val & (1U << INPUT_PHONE))
		tmp |= CODEC_IN_ENABLE_TAD;
	audiopci_ak_write(dev, CODEC_LIN_SW1, tmp);

	tmp = 0;
	if (val & (1U << INPUT_LINEIN))
		tmp |= CODEC_IN_ENABLE_AUX_R;
	if (val & (1U << INPUT_CD))
		tmp |= CODEC_IN_ENABLE_CD_R;
	if (val & (1U << INPUT_PHONE))
		tmp |= CODEC_IN_ENABLE_TAD;
	if (val & (1U << INPUT_MIC))
		tmp |= CODEC_IN_ENABLE_MIC;
	audiopci_ak_write(dev, CODEC_RIN_SW1, tmp);

	tmp = 0;
	if (val & (1U << INPUT_VIDEO))
		tmp |= CODEC_IN_ENABLE_TV_L;
	if (val & (1U << INPUT_MIC))
		tmp |= CODEC_IN_ENABLE_TMIC;
	audiopci_ak_write(dev, CODEC_LIN_SW2, tmp);

	tmp = 0;
	if (val & (1U << INPUT_VIDEO))
		tmp |= CODEC_IN_ENABLE_TV_R;
	if (val & (1U << INPUT_MIC))
		tmp |= CODEC_IN_ENABLE_TMIC;
	audiopci_ak_write(dev, CODEC_RIN_SW2, tmp);

	/* configure volumes */
	audiopci_mono(dev, CTL_MIC, CODEC_VOL_MIC);
	audiopci_mono(dev, CTL_PHONE, CODEC_VOL_TAD);
	audiopci_stereo(dev, CTL_LINE, CODEC_VOL_AUX_L);
	audiopci_stereo(dev, CTL_CD, CODEC_VOL_CD_L);
	audiopci_stereo(dev, CTL_VID, CODEC_VOL_TV_L);

	/* activate 30dB mic boost */
	audiopci_ak_write(dev, CODEC_MICBOOST,
	    dev->controls[CTL_MICBOOST].val ? 1 : 0);
}

static int
audiopci_set_reclevel(void *arg, uint64_t val)
{
	audiopci_ctrl_t	*pc = arg;
	audiopci_dev_t	*dev = pc->dev;
	uint8_t		l;
	uint8_t		r;

	l = (val & 0xff00) >> 8;
	r = val & 0xff;

	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&dev->mutex);
	pc->val = val;
	audiopci_configure_input(dev);

	mutex_exit(&dev->mutex);
	return (0);
}

static int
audiopci_set_micboost(void *arg, uint64_t val)
{
	audiopci_ctrl_t	*pc = arg;
	audiopci_dev_t	*dev = pc->dev;

	mutex_enter(&dev->mutex);
	pc->val = val;
	audiopci_configure_input(dev);
	mutex_exit(&dev->mutex);
	return (0);
}

static int
audiopci_set_monsrc(void *arg, uint64_t val)
{
	audiopci_ctrl_t	*pc = arg;
	audiopci_dev_t	*dev = pc->dev;

	if ((val & ~INSRCS) != 0)
		return (EINVAL);

	mutex_enter(&dev->mutex);
	pc->val = val;
	audiopci_configure_output(dev);
	mutex_exit(&dev->mutex);
	return (0);
}

static int
audiopci_set_recsrc(void *arg, uint64_t val)
{
	audiopci_ctrl_t	*pc = arg;
	audiopci_dev_t	*dev = pc->dev;

	if ((val & ~INSRCS) != 0)
		return (EINVAL);

	mutex_enter(&dev->mutex);
	pc->val = val;
	audiopci_configure_input(dev);
	mutex_exit(&dev->mutex);
	return (0);
}

static int
audiopci_set_volume(void *arg, uint64_t val)
{
	audiopci_ctrl_t	*pc = arg;
	audiopci_dev_t	*dev = pc->dev;

	val &= 0xff;
	if (val > 100)
		return (EINVAL);

	val = (val & 0xff) | ((val & 0xff) << 8);

	mutex_enter(&dev->mutex);
	pc->val = val;
	audiopci_configure_output(dev);
	mutex_exit(&dev->mutex);

	return (0);
}

static int
audiopci_set_front(void *arg, uint64_t val)
{
	audiopci_ctrl_t	*pc = arg;
	audiopci_dev_t	*dev = pc->dev;
	uint8_t		l;
	uint8_t		r;

	l = (val & 0xff00) >> 8;
	r = val & 0xff;

	if ((l > 100) || (r > 100))
		return (EINVAL);

	mutex_enter(&dev->mutex);
	pc->val = val;
	audiopci_configure_output(dev);

	mutex_exit(&dev->mutex);
	return (0);
}

static int
audiopci_set_speaker(void *arg, uint64_t val)
{
	audiopci_ctrl_t	*pc = arg;
	audiopci_dev_t	*dev = pc->dev;

	val &= 0xff;

	if (val > 100)
		return (EINVAL);

	mutex_enter(&dev->mutex);
	pc->val = val;
	audiopci_configure_output(dev);

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
audiopci_alloc_ctrl(audiopci_dev_t *dev, uint32_t num, uint64_t val)
{
	audio_ctrl_desc_t	desc;
	audio_ctrl_wr_t		fn;
	audiopci_ctrl_t		*pc;

	bzero(&desc, sizeof (desc));

	pc = &dev->controls[num];
	pc->num = num;
	pc->dev = dev;

	switch (num) {
	case CTL_VOLUME:
		desc.acd_name = AUDIO_CTRL_ID_VOLUME;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = PCMVOL;
		fn = audiopci_set_volume;
		break;

	case CTL_FRONT:
		desc.acd_name = AUDIO_CTRL_ID_LINEOUT;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiopci_set_front;
		break;

	case CTL_MONO:
		desc.acd_name = AUDIO_CTRL_ID_SPEAKER;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = MAINVOL;
		fn = audiopci_set_speaker;
		break;

	case CTL_MIC:
		desc.acd_name = AUDIO_CTRL_ID_MIC;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiopci_set_reclevel;
		break;

	case CTL_LINE:
		desc.acd_name = AUDIO_CTRL_ID_LINEIN;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiopci_set_reclevel;
		break;

	case CTL_CD:
		desc.acd_name = AUDIO_CTRL_ID_CD;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiopci_set_reclevel;
		break;

	case CTL_VID:
		desc.acd_name = AUDIO_CTRL_ID_VIDEO;
		desc.acd_type = AUDIO_CTRL_TYPE_STEREO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiopci_set_reclevel;
		break;

	case CTL_PHONE:
		desc.acd_name = AUDIO_CTRL_ID_PHONE;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECVOL;
		fn = audiopci_set_reclevel;
		break;

	case CTL_RECSRC:
		desc.acd_name = AUDIO_CTRL_ID_RECSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_minvalue = INSRCS;
		desc.acd_maxvalue = INSRCS;
		desc.acd_flags = RECCTL | AUDIO_CTRL_FLAG_MULTI;
		for (int i = 0; audiopci_insrcs[i]; i++) {
			desc.acd_enum[i] = audiopci_insrcs[i];
		}
		fn = audiopci_set_recsrc;
		break;

	case CTL_MONSRC:
		desc.acd_name = AUDIO_CTRL_ID_MONSRC;
		desc.acd_type = AUDIO_CTRL_TYPE_ENUM;
		desc.acd_minvalue = INSRCS;
		desc.acd_maxvalue = INSRCS;
		desc.acd_flags = MONCTL | AUDIO_CTRL_FLAG_MULTI;
		for (int i = 0; audiopci_insrcs[i]; i++) {
			desc.acd_enum[i] = audiopci_insrcs[i];
		}
		fn = audiopci_set_monsrc;
		break;

	case CTL_MICBOOST:
		desc.acd_name = AUDIO_CTRL_ID_MICBOOST;
		desc.acd_type = AUDIO_CTRL_TYPE_BOOLEAN;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = RECCTL;
		fn = audiopci_set_micboost;
		break;
	}

	pc->val = val;
	pc->ctrl = audio_dev_add_control(dev->adev, &desc,
	    audiopci_get_value, fn, pc);
}

static int
audiopci_add_controls(audiopci_dev_t *dev)
{
	audiopci_alloc_ctrl(dev, CTL_VOLUME, 75);
	audiopci_alloc_ctrl(dev, CTL_FRONT, ((75) | (75 << 8)));
	audiopci_alloc_ctrl(dev, CTL_MONO, 75);
	audiopci_alloc_ctrl(dev, CTL_MIC, 50);
	audiopci_alloc_ctrl(dev, CTL_LINE, 0);
	audiopci_alloc_ctrl(dev, CTL_CD, 0);
	audiopci_alloc_ctrl(dev, CTL_VID, 0);
	audiopci_alloc_ctrl(dev, CTL_PHONE, 0);
	audiopci_alloc_ctrl(dev, CTL_RECSRC, (1U << INPUT_MIC));
	audiopci_alloc_ctrl(dev, CTL_MONSRC, 0);
	audiopci_alloc_ctrl(dev, CTL_MICBOOST, 1);

	audiopci_configure_output(dev);
	audiopci_configure_input(dev);

	return (DDI_SUCCESS);
}

static void
audiopci_del_controls(audiopci_dev_t *dev)
{
	for (int i = 0; i < CTL_NUM; i++) {
		if (dev->controls[i].ctrl) {
			audio_dev_del_control(dev->controls[i].ctrl);
		}
	}
}

static int
audiopci_attach(dev_info_t *dip)
{
	uint16_t pci_command, vendor, device;
	audiopci_dev_t *dev;
	ddi_acc_handle_t pcih;

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->dip = dip;
	ddi_set_driver_private(dip, dev);

	mutex_init(&dev->mutex, NULL, MUTEX_DRIVER, NULL);

	if (pci_config_setup(dip, &pcih) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "pci_config_setup failed");
		mutex_destroy(&dev->mutex);
		kmem_free(dev, sizeof (*dev));
		return (DDI_FAILURE);
	}

	vendor = pci_config_get16(pcih, PCI_CONF_VENID);
	device = pci_config_get16(pcih, PCI_CONF_DEVID);

	if ((vendor != ENSONIQ_VENDOR_ID && vendor != CREATIVE_VENDOR_ID) ||
	    (device != ENSONIQ_ES1370))
		goto err_exit;

	dev->devid = device;

	dev->adev = audio_dev_alloc(dip, 0);
	if (dev->adev == NULL) {
		goto err_exit;
	}

	audio_dev_set_description(dev->adev, "AudioPCI");
	audio_dev_set_version(dev->adev, "ES1370");
	audio_dev_add_info(dev->adev, "Legacy codec: Asahi Kasei AK4531");

	/* activate the device */
	pci_command = pci_config_get16(pcih, PCI_CONF_COMM);
	pci_command |= PCI_COMM_ME | PCI_COMM_IO;
	pci_config_put16(pcih, PCI_CONF_COMM, pci_command);

	/* map registers */
	if (ddi_regs_map_setup(dip, 1, &dev->regs, 0, 0, &acc_attr,
	    &dev->acch) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "can't map registers");
		goto err_exit;
	}


	/* This allocates and configures the engines */
	if (audiopci_init(dev) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "can't init device");
		goto err_exit;
	}

	pci_config_teardown(&pcih);

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

err_exit:
	mutex_destroy(&dev->mutex);
	pci_config_teardown(&pcih);

	audiopci_destroy(dev);

	return (DDI_FAILURE);
}

static int
audiopci_detach(audiopci_dev_t *dev)
{
	int tmp;

	/* first unregister us from the DDI framework, might be busy */
	if (audio_dev_unregister(dev->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	mutex_enter(&dev->mutex);

	tmp = GET8(dev, CONC_bSERCTL_OFF) &
	    ~(CONC_SERCTL_DACIE | CONC_SERCTL_SYNIE | CONC_SERCTL_ADCIE);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);

	tmp = GET8(dev, CONC_bDEVCTL_OFF) &
	    ~(CONC_DEVCTL_DAC_EN | CONC_DEVCTL_ADC_EN | CONC_DEVCTL_SYN_EN);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);

	mutex_exit(&dev->mutex);

	audiopci_destroy(dev);

	return (DDI_SUCCESS);
}

static int
audiopci_resume(audiopci_dev_t *dev)
{
	/* reinitialize hardware */
	audiopci_init_hw(dev);

	audio_dev_resume(dev->adev);
	return (DDI_SUCCESS);
}

static int
audiopci_suspend(audiopci_dev_t *dev)
{
	audio_dev_suspend(dev->adev);

	return (DDI_SUCCESS);
}

static int
audiopci_quiesce(dev_info_t *dip)
{
	audiopci_dev_t	*dev;
	uint8_t		tmp;

	if ((dev = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	/* This disables all DMA engines and interrupts */
	tmp = GET8(dev, CONC_bSERCTL_OFF) &
	    ~(CONC_SERCTL_DACIE | CONC_SERCTL_SYNIE | CONC_SERCTL_ADCIE);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);

	tmp = GET8(dev, CONC_bDEVCTL_OFF) &
	    ~(CONC_DEVCTL_DAC_EN | CONC_DEVCTL_ADC_EN | CONC_DEVCTL_SYN_EN);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);

	return (DDI_SUCCESS);
}


static int
audiopci_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	audiopci_dev_t *dev;

	switch (cmd) {
	case DDI_ATTACH:
		return (audiopci_attach(dip));

	case DDI_RESUME:
		if ((dev = ddi_get_driver_private(dip)) == NULL) {
			return (DDI_FAILURE);
		}
		return (audiopci_resume(dev));

	default:
		return (DDI_FAILURE);
	}
}

static int
audiopci_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audiopci_dev_t *dev;

	if ((dev = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		return (audiopci_detach(dev));

	case DDI_SUSPEND:
		return (audiopci_suspend(dev));
	default:
		return (DDI_FAILURE);
	}
}

static struct dev_ops audiopci_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	audiopci_ddi_attach,	/* attach */
	audiopci_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	audiopci_quiesce,	/* quiesce */
};

static struct modldrv audiopci_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Ensoniq 1370 Audio",		/* linkinfo */
	&audiopci_dev_ops,		/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &audiopci_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&audiopci_dev_ops, DRVNAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&audiopci_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&audiopci_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
