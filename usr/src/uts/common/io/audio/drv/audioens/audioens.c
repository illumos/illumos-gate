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
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 */
/*
 * Purpose: Creative/Ensoniq AudioPCI97  driver (ES1371/ES1373)
 *
 * This driver is used with the original Ensoniq AudioPCI97 card and many
 * PCI based Sound Blaster cards by Creative Technologies. For example
 * Sound Blaster PCI128 and Creative/Ectiva EV1938.
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
#include <sys/audio/ac97.h>
#include <sys/note.h>
#include <sys/pci.h>

/*
 * For VMWare platforms, we have to utilize the (emulated) hardware interrupts
 * of the device.  This is necessary for audio playback to function, as
 * the toggling of the interrupt bits apparently triggers logic inside the
 * emulated device.  So we need to detect this platform, and conditionally
 * wire up the interrupt handler.
 */
#ifdef __x86
#include <sys/x86_archext.h>
#endif

#include "audioens.h"

/*
 * Set the latency to 32, 64, 96, 128 clocks - some APCI97 devices exhibit
 * garbled audio in some cases and setting the latency to higer values fixes it
 * Values: 32, 64, 96, 128 - Default: 64 (or defined by bios)
 */
int audioens_latency = 0;

/*
 * Enable SPDIF port on SoundBlaster 128D or Sound Blaster Digital-4.1 models
 * Values: 1=Enable 0=Disable Default: 0
 */
int audioens_spdif = 0;

/*
 * Note: Latest devices can support SPDIF with AC3 pass thru.
 * However, in order to do this, one of the two DMA engines must be
 * dedicated to this, which would prevent the card from supporting 4
 * channel audio.  For now we don't bother with the AC3 pass through
 * mode, and instead just focus on 4 channel support.  In the future,
 * this could be selectable via a property.
 */

#define	ENSONIQ_VENDOR_ID	0x1274
#define	CREATIVE_VENDOR_ID	0x1102
#define	ECTIVA_VENDOR_ID	0x1102
#define	ENSONIQ_ES1371		0x1371
#define	ENSONIQ_ES5880		0x8001
#define	ENSONIQ_ES5880A		0x8002
#define	ENSONIQ_ES5880B		0x5880
#define	ECTIVA_ES1938		0x8938

#define	DEFRATE			48000
#define	DRVNAME			"audioens"

typedef struct audioens_port
{
	/* Audio parameters */
	int			speed;

	int			num;
#define	PORT_DAC		0
#define	PORT_ADC		1
#define	PORT_MAX		PORT_ADC

	caddr_t			kaddr;
	uint32_t		paddr;
	ddi_acc_handle_t	acch;
	ddi_dma_handle_t	dmah;
	int			nchan;
	unsigned		nframes;
	unsigned		iframes;
	unsigned		frameno;
	uint64_t		count;

	struct audioens_dev	*dev;
	audio_engine_t		*engine;
} audioens_port_t;

typedef struct audioens_dev
{
	audio_dev_t		*osdev;
	kmutex_t		mutex;
	uint16_t		devid;
	uint8_t			revision;
	dev_info_t		*dip;

	audioens_port_t		port[PORT_MAX + 1];

	ac97_t			*ac97;

	caddr_t			regs;
	ddi_acc_handle_t	acch;

	boolean_t		suspended;

#ifdef __x86
	boolean_t		useintr;
	ddi_intr_handle_t	intrh;
	uint_t			intrpri;
#endif
} audioens_dev_t;

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
#define	CLR32(dev, offset, v)	PUT32(dev, offset, GET32(dev, offset) & ~(v))
#define	SET32(dev, offset, v)	PUT32(dev, offset, GET32(dev, offset) | (v))

static void audioens_init_hw(audioens_dev_t *);

static uint16_t
audioens_rd97(void *dev_, uint8_t wAddr)
{
	audioens_dev_t *dev = dev_;
	int i, dtemp;

	mutex_enter(&dev->mutex);
	dtemp = GET32(dev, CONC_dCODECCTL_OFF);
	/* wait for WIP to go away saving the current state for later */
	for (i = 0; i < 0x100UL; ++i) {
		dtemp = GET32(dev, CONC_dCODECCTL_OFF);
		if ((dtemp & (1UL << 30)) == 0)
			break;
	}

	/* write addr w/data=0 and assert read request ... */
	PUT32(dev, CONC_dCODECCTL_OFF, ((int)wAddr << 16) | (1UL << 23));

	/* now wait for the data (RDY) */
	for (i = 0; i < 0x100UL; ++i) {
		dtemp = GET32(dev, CONC_dCODECCTL_OFF);
		if (dtemp & (1UL << 31))
			break;
	}
	dtemp = GET32(dev, CONC_dCODECCTL_OFF);
	mutex_exit(&dev->mutex);

	return (dtemp & 0xffff);
}

static void
audioens_wr97(void *dev_, uint8_t wAddr, uint16_t wData)
{
	audioens_dev_t *dev = dev_;
	int i, dtemp;

	mutex_enter(&dev->mutex);
	/* wait for WIP to go away */
	for (i = 0; i < 0x100UL; ++i) {
		dtemp = GET32(dev, CONC_dCODECCTL_OFF);
		if ((dtemp & (1UL << 30)) == 0)
			break;
	}

	PUT32(dev, CONC_dCODECCTL_OFF, ((int)wAddr << 16) | wData);

	mutex_exit(&dev->mutex);
}

static unsigned short
SRCRegRead(audioens_dev_t *dev, unsigned short reg)
{
	int i, dtemp;

	dtemp = GET32(dev, CONC_dSRCIO_OFF);
	/* wait for ready */
	for (i = 0; i < SRC_IOPOLL_COUNT; ++i) {
		dtemp = GET32(dev, CONC_dSRCIO_OFF);
		if ((dtemp & SRC_BUSY) == 0)
			break;
	}

	/* assert a read request */
	PUT32(dev, CONC_dSRCIO_OFF, (dtemp & SRC_CTLMASK) | ((int)reg << 25));

	/* now wait for the data */
	for (i = 0; i < SRC_IOPOLL_COUNT; ++i) {
		dtemp = GET32(dev, CONC_dSRCIO_OFF);
		if ((dtemp & SRC_BUSY) == 0)
			break;
	}

	return ((unsigned short) dtemp);
}

static void
SRCRegWrite(audioens_dev_t *dev, unsigned short reg, unsigned short val)
{
	int i, dtemp;
	int writeval;

	dtemp = GET32(dev, CONC_dSRCIO_OFF);
	/* wait for ready */
	for (i = 0; i < SRC_IOPOLL_COUNT; ++i) {
		dtemp = GET32(dev, CONC_dSRCIO_OFF);
		if ((dtemp & SRC_BUSY) == 0)
			break;
	}

	/* assert the write request */
	writeval = (dtemp & SRC_CTLMASK) | SRC_WENABLE |
	    ((int)reg << 25) | val;
	PUT32(dev, CONC_dSRCIO_OFF, writeval);
}

static void
SRCSetRate(audioens_dev_t *dev, unsigned char base, unsigned short rate)
{
	int i, freq, dtemp;
	unsigned short N, truncM, truncStart;

	if (base != SRC_ADC_BASE) {
		/* freeze the channel */
		dtemp = (base == SRC_DAC1_BASE) ?
		    SRC_DAC1FREEZE : SRC_DAC2FREEZE;
		for (i = 0; i < SRC_IOPOLL_COUNT; ++i) {
			if (!(GET32(dev, CONC_dSRCIO_OFF) & SRC_BUSY))
				break;
		}
		PUT32(dev, CONC_dSRCIO_OFF,
		    (GET32(dev, CONC_dSRCIO_OFF) & SRC_CTLMASK) | dtemp);

		/* calculate new frequency and write it - preserve accum */
		freq = ((int)rate << 16) / 3000U;
		SRCRegWrite(dev, (unsigned short) base + SRC_INT_REGS_OFF,
		    (SRCRegRead(dev, (unsigned short) base + SRC_INT_REGS_OFF)
		    & 0x00ffU) | ((unsigned short) (freq >> 6) & 0xfc00));
		SRCRegWrite(dev, (unsigned short) base + SRC_VFREQ_FRAC_OFF,
		    (unsigned short) freq >> 1);

		/* un-freeze the channel */
		for (i = 0; i < SRC_IOPOLL_COUNT; ++i)
			if (!(GET32(dev, CONC_dSRCIO_OFF) & SRC_BUSY))
				break;
		PUT32(dev, CONC_dSRCIO_OFF,
		    (GET32(dev, CONC_dSRCIO_OFF) & SRC_CTLMASK) & ~dtemp);
	} else {
		/* derive oversample ratio */
		N = rate / 3000U;
		if (N == 15 || N == 13 || N == 11 || N == 9)
			--N;

		/* truncate the filter and write n/trunc_start */
		truncM = (21 * N - 1) | 1;
		if (rate >= 24000U) {
			if (truncM > 239)
				truncM = 239;
			truncStart = (239 - truncM) >> 1;

			SRCRegWrite(dev, base + SRC_TRUNC_N_OFF,
			    (truncStart << 9) | (N << 4));
		} else {
			if (truncM > 119)
				truncM = 119;
			truncStart = (119 - truncM) >> 1;

			SRCRegWrite(dev, base + SRC_TRUNC_N_OFF,
			    0x8000U | (truncStart << 9) | (N << 4));
		}

		/* calculate new frequency and write it - preserve accum */
		freq = ((48000UL << 16) / rate) * N;
		SRCRegWrite(dev, base + SRC_INT_REGS_OFF,
		    (SRCRegRead(dev, (unsigned short) base + SRC_INT_REGS_OFF)
		    & 0x00ff) | ((unsigned short) (freq >> 6) & 0xfc00));
		SRCRegWrite(dev, base + SRC_VFREQ_FRAC_OFF,
		    (unsigned short) freq >> 1);

		SRCRegWrite(dev, SRC_ADC_VOL_L, N << 8);
		SRCRegWrite(dev, SRC_ADC_VOL_R, N << 8);
	}
}

static void
SRCInit(audioens_dev_t *dev)
{
	int i;

	/* Clear all SRC RAM then init - keep SRC disabled until done */
	for (i = 0; i < SRC_IOPOLL_COUNT; ++i) {
		if (!(GET32(dev, CONC_dSRCIO_OFF) & SRC_BUSY))
			break;
	}
	PUT32(dev, CONC_dSRCIO_OFF, SRC_DISABLE);

	for (i = 0; i < 0x80; ++i)
		SRCRegWrite(dev, (unsigned short) i, 0U);

	SRCRegWrite(dev, SRC_DAC1_BASE + SRC_TRUNC_N_OFF, 16 << 4);
	SRCRegWrite(dev, SRC_DAC1_BASE + SRC_INT_REGS_OFF, 16 << 10);
	SRCRegWrite(dev, SRC_DAC2_BASE + SRC_TRUNC_N_OFF, 16 << 4);
	SRCRegWrite(dev, SRC_DAC2_BASE + SRC_INT_REGS_OFF, 16 << 10);
	SRCRegWrite(dev, SRC_DAC1_VOL_L, 1 << 12);
	SRCRegWrite(dev, SRC_DAC1_VOL_R, 1 << 12);
	SRCRegWrite(dev, SRC_DAC2_VOL_L, 1 << 12);
	SRCRegWrite(dev, SRC_DAC2_VOL_R, 1 << 12);
	SRCRegWrite(dev, SRC_ADC_VOL_L, 1 << 12);
	SRCRegWrite(dev, SRC_ADC_VOL_R, 1 << 12);

	/* default some rates */
	SRCSetRate(dev, SRC_DAC1_BASE, 48000);
	SRCSetRate(dev, SRC_DAC2_BASE, 48000);
	SRCSetRate(dev, SRC_ADC_BASE, 48000);

	/* now enable the whole deal */
	for (i = 0; i < SRC_IOPOLL_COUNT; ++i) {
		if (!(GET32(dev, CONC_dSRCIO_OFF) & SRC_BUSY))
			break;
	}
	PUT32(dev, CONC_dSRCIO_OFF, 0);
}

static void
audioens_writemem(audioens_dev_t *dev, uint32_t page, uint32_t offs,
    uint32_t data)
{
	/* Select memory page */
	PUT32(dev, CONC_bMEMPAGE_OFF, page);
	PUT32(dev, offs, data);
}

static uint32_t
audioens_readmem(audioens_dev_t *dev, uint32_t page, uint32_t offs)
{
	PUT32(dev, CONC_bMEMPAGE_OFF, page);	/* Select memory page */
	return (GET32(dev, offs));
}

#ifdef __x86
static unsigned
audioens_intr(caddr_t arg1, caddr_t arg2)
{
	audioens_dev_t *dev = (void *)arg1;
	uint32_t status;
	uint32_t frameno;
	uint32_t n;
	audioens_port_t *port;

	_NOTE(ARGUNUSED(arg2));

	mutex_enter(&dev->mutex);
	if (dev->suspended || !dev->useintr) {
		mutex_exit(&dev->mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	status = GET32(dev, CONC_dSTATUS_OFF);
	if ((status & CONC_STATUS_PENDING) == 0) {
		mutex_exit(&dev->mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* Three interrupts, DAC1, DAC2, and ADC.  The UART we just toss. */

	if (status & CONC_STATUS_DAC1INT) {
		port = &dev->port[PORT_DAC];

		/* current frame counter is in high nybble */
		frameno = audioens_readmem(dev,
		    CONC_DAC1CTL_PAGE, CONC_wDAC1FC_OFF) >> 16;
		n = frameno >= port->frameno ?
		    frameno - port->frameno :
		    frameno + port->nframes - port->frameno;
		port->frameno = frameno;
		port->count += n;
		CLR8(dev, CONC_bSERCTL_OFF, CONC_SERCTL_DAC1IE);
		SET8(dev, CONC_bSERCTL_OFF, CONC_SERCTL_DAC1IE);
	}
	if (status & CONC_STATUS_ADCINT) {
		port = &dev->port[PORT_ADC];

		/* current frame counter is in high nybble */
		frameno = audioens_readmem(dev,
		    CONC_ADCCTL_PAGE, CONC_wADCFC_OFF) >> 16;
		n = frameno >= port->frameno ?
		    frameno - port->frameno :
		    frameno + port->nframes - port->frameno;
		port->frameno = frameno;
		port->count += n;
		CLR8(dev, CONC_bSERCTL_OFF, CONC_SERCTL_ADCIE);
		SET8(dev, CONC_bSERCTL_OFF, CONC_SERCTL_ADCIE);
	}
	if (status & CONC_STATUS_DAC2INT) {
		CLR8(dev, CONC_bSERCTL_OFF, CONC_SERCTL_DAC2IE);
		SET8(dev, CONC_bSERCTL_OFF, CONC_SERCTL_DAC2IE);
	}
	if (status & CONC_STATUS_UARTINT) {
		/*
		 * Consume data in the UART RX FIFO.  We don't support
		 * the UART for now, so just eat it.
		 */
		while (GET8(dev, CONC_bUARTCSTAT_OFF) & CONC_UART_RXRDY)
			continue;
	}
	mutex_exit(&dev->mutex);

	return (DDI_INTR_CLAIMED);
}

static int
audioens_setup_intr(audioens_dev_t *dev)
{
	int	act;
	uint_t	ipri;

	if ((ddi_intr_alloc(dev->dip, &dev->intrh, DDI_INTR_TYPE_FIXED, 0, 1,
	    &act, DDI_INTR_ALLOC_NORMAL) != DDI_SUCCESS) || (act != 1)) {
		audio_dev_warn(dev->osdev, "can't alloc intr handle");
		goto fail;
	}

	if (ddi_intr_get_pri(dev->intrh, &ipri) != DDI_SUCCESS) {
		audio_dev_warn(dev->osdev, "can't get interrupt priority");
		goto fail;
	}
	if (ddi_intr_add_handler(dev->intrh, audioens_intr, dev, NULL) !=
	    DDI_SUCCESS) {
		audio_dev_warn(dev->osdev, "cannot add interrupt handler");
		goto fail;
	}
	dev->intrpri = ipri;
	return (DDI_SUCCESS);

fail:
	if (dev->intrh != NULL) {
		(void) ddi_intr_free(dev->intrh);
		dev->intrh = NULL;
	}
	return (DDI_FAILURE);
}

#endif	/* __x86 */

/*
 * Audio routines
 */
static int
audioens_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	/* hardware can also do AUDIO_FORMAT_U8, but no need for it */
	return (AUDIO_FORMAT_S16_LE);
}

static int
audioens_channels(void *arg)
{
	audioens_port_t *port = arg;

	return (port->nchan);
}

static int
audioens_rate(void *arg)
{
	audioens_port_t *port = arg;

	return (port->speed);
}

static int
audioens_open(void *arg, int flag, unsigned *nframes, caddr_t *bufp)
{
	audioens_port_t	*port = arg;
	audioens_dev_t	*dev = port->dev;

	_NOTE(ARGUNUSED(flag));

	mutex_enter(&dev->mutex);

	port->count = 0;

	*nframes = port->nframes;
	*bufp = port->kaddr;
	mutex_exit(&dev->mutex);

	return (0);
}

static int
audioens_start(void *arg)
{
	audioens_port_t *port = arg;
	audioens_dev_t *dev = port->dev;
	uint32_t tmp;

	mutex_enter(&dev->mutex);

	switch (port->num) {
	case PORT_DAC:
		/* Set physical address of the DMA buffer */
		audioens_writemem(dev, CONC_DAC1CTL_PAGE, CONC_dDAC1PADDR_OFF,
		    port->paddr);
		audioens_writemem(dev, CONC_DAC2CTL_PAGE, CONC_dDAC2PADDR_OFF,
		    port->paddr + (port->nframes * sizeof (int16_t) * 2));

		/* Set DAC rate */
		SRCSetRate(dev, SRC_DAC1_BASE, port->speed);
		SRCSetRate(dev, SRC_DAC2_BASE, port->speed);

		/* Configure the channel setup - SPDIF only uses front */
		tmp = GET32(dev, CONC_dSTATUS_OFF);
		tmp &= ~(CONC_STATUS_SPKR_MASK | CONC_STATUS_SPDIF_MASK);
		tmp |= CONC_STATUS_SPKR_4CH | CONC_STATUS_SPDIF_P1;
		PUT32(dev, CONC_dSTATUS_OFF, tmp);

		/* Set format */
		PUT8(dev, CONC_bSKIPC_OFF, 0x10);
		SET8(dev, CONC_bSERFMT_OFF,
		    CONC_PCM_DAC1_16BIT | CONC_PCM_DAC2_16BIT |
		    CONC_PCM_DAC1_STEREO | CONC_PCM_DAC2_STEREO);

		/* Set the frame count */
		audioens_writemem(dev, CONC_DAC1CTL_PAGE, CONC_wDAC1FC_OFF,
		    port->nframes - 1);
		audioens_writemem(dev, CONC_DAC2CTL_PAGE, CONC_wDAC2FC_OFF,
		    port->nframes - 1);

		PUT16(dev, CONC_wDAC1IC_OFF, port->iframes - 1);
		PUT16(dev, CONC_wDAC2IC_OFF, port->iframes - 1);
		SET8(dev, CONC_bDEVCTL_OFF,
		    CONC_DEVCTL_DAC2_EN | CONC_DEVCTL_DAC1_EN);
#ifdef __x86
		if (dev->useintr) {
			SET8(dev, CONC_bSERCTL_OFF, CONC_SERCTL_DAC1IE);
		}
#endif

		break;

	case PORT_ADC:
		/* Set physical address of the DMA buffer */
		audioens_writemem(dev, CONC_ADCCTL_PAGE, CONC_dADCPADDR_OFF,
		    port->paddr);

		/* Set ADC rate */
		SRCSetRate(dev, SRC_ADC_BASE, port->speed);

		/* Set format - for input we only support 16 bit input */
		tmp = GET8(dev, CONC_bSERFMT_OFF);
		tmp |= CONC_PCM_ADC_16BIT;
		tmp |= CONC_PCM_ADC_STEREO;

		PUT8(dev, CONC_bSKIPC_OFF, 0x10);

		PUT8(dev, CONC_bSERFMT_OFF, tmp);

		/* Set the frame count */
		audioens_writemem(dev, CONC_ADCCTL_PAGE, CONC_wADCFC_OFF,
		    port->nframes - 1);

		/* Set # of frames between interrupts */
		PUT16(dev, CONC_wADCIC_OFF, port->iframes - 1);

		SET8(dev, CONC_bDEVCTL_OFF, CONC_DEVCTL_ADC_EN);
#ifdef __x86
		if (dev->useintr) {
			SET8(dev, CONC_bSERCTL_OFF, CONC_SERCTL_ADCIE);
		}
#endif
		break;
	}

	port->frameno = 0;
	mutex_exit(&dev->mutex);

	return (0);
}

static void
audioens_stop(void *arg)
{
	audioens_port_t *port = arg;
	audioens_dev_t *dev = port->dev;

	mutex_enter(&dev->mutex);
	switch (port->num) {
	case PORT_DAC:
		CLR8(dev, CONC_bDEVCTL_OFF,
		    CONC_DEVCTL_DAC2_EN | CONC_DEVCTL_DAC1_EN);
		break;
	case PORT_ADC:
		CLR8(dev, CONC_bDEVCTL_OFF, CONC_DEVCTL_ADC_EN);
		break;
	}
	mutex_exit(&dev->mutex);
}

static uint64_t
audioens_count(void *arg)
{
	audioens_port_t *port = arg;
	audioens_dev_t *dev = port->dev;
	uint64_t val;
	uint32_t page, offs;
	int frameno, n;

	switch (port->num) {
	case PORT_DAC:
		page = CONC_DAC1CTL_PAGE;
		offs = CONC_wDAC1FC_OFF;
		break;

	case PORT_ADC:
		page = CONC_ADCCTL_PAGE;
		offs = CONC_wADCFC_OFF;
		break;
	}

	mutex_enter(&dev->mutex);
#ifdef __x86
	if (!dev->useintr) {
#endif

	/*
	 * Note that the current frame counter is in the high nybble.
	 */
	frameno = audioens_readmem(port->dev, page, offs) >> 16;
	n = frameno >= port->frameno ?
	    frameno - port->frameno :
	    frameno + port->nframes - port->frameno;
	port->frameno = frameno;
	port->count += n;

#ifdef __x86
	}
#endif

	val = port->count;
	mutex_exit(&dev->mutex);

	return (val);
}

static void
audioens_close(void *arg)
{
	_NOTE(ARGUNUSED(arg));
}

static void
audioens_sync(void *arg, unsigned nframes)
{
	audioens_port_t *port = arg;

	_NOTE(ARGUNUSED(nframes));

	if (port->num == PORT_ADC) {
		(void) ddi_dma_sync(port->dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL);
	} else {
		(void) ddi_dma_sync(port->dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	}
}

static void
audioens_chinfo(void *arg, int chan, unsigned *offset, unsigned *incr)
{
	audioens_port_t *port = arg;

	if ((port->num == PORT_DAC) && (chan >= 2)) {
		*offset = (port->nframes * 2) + (chan % 2);
		*incr = 2;
	} else {
		*offset = chan;
		*incr = 2;
	}
}

audio_engine_ops_t audioens_engine_ops = {
	AUDIO_ENGINE_VERSION,		/* version number */
	audioens_open,
	audioens_close,
	audioens_start,
	audioens_stop,
	audioens_count,
	audioens_format,
	audioens_channels,
	audioens_rate,
	audioens_sync,
	NULL,
	audioens_chinfo,
	NULL,
};

void
audioens_init_hw(audioens_dev_t *dev)
{
	int tmp;

	if ((dev->devid == ENSONIQ_ES5880) ||
	    (dev->devid == ENSONIQ_ES5880A) ||
	    (dev->devid == ENSONIQ_ES5880B) ||
	    (dev->devid == 0x1371 && dev->revision == 7) ||
	    (dev->devid == 0x1371 && dev->revision >= 9)) {

		/* Have a ES5880 so enable the codec manually */
		tmp = GET8(dev, CONC_bINTSUMM_OFF) & 0xff;
		tmp |= 0x20;
		PUT8(dev, CONC_bINTSUMM_OFF, tmp);
		for (int i = 0; i < 2000; i++)
			drv_usecwait(10);
	}

	SRCInit(dev);

	/*
	 * Turn on CODEC (UART and joystick left disabled)
	 */
	tmp = GET32(dev, CONC_bDEVCTL_OFF) & 0xff;
	tmp &= ~(CONC_DEVCTL_PCICLK_DS | CONC_DEVCTL_XTALCLK_DS);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bUARTCSTAT_OFF, 0x00);

	/* Perform AC97 codec warm reset */
	tmp = GET8(dev, CONC_bMISCCTL_OFF) & 0xff;
	PUT8(dev, CONC_bMISCCTL_OFF, tmp | CONC_MISCCTL_SYNC_RES);
	drv_usecwait(200);
	PUT8(dev, CONC_bMISCCTL_OFF, tmp);
	drv_usecwait(200);

	if (dev->revision >= 4) {
		/* XXX: enable SPDIF - PCM only for now */
		if (audioens_spdif) {
			/* enable SPDIF */
			PUT32(dev, 0x04, GET32(dev, 0x04) | (1 << 18));
			/* SPDIF out = data from DAC */
			PUT32(dev, 0x00, GET32(dev, 0x00) | (1 << 26));
			CLR32(dev, CONC_dSPDIF_OFF, CONC_SPDIF_AC3);

		} else {
			/* disable spdif out */
			PUT32(dev, 0x04, GET32(dev, 0x04) & ~(1 << 18));
			PUT32(dev, 0x00, GET32(dev, 0x00) & ~(1 << 26));
		}

		/* we want to run each channel independently */
		CLR32(dev, CONC_dSTATUS_OFF, CONC_STATUS_ECHO);
	}
}

static int
audioens_init(audioens_dev_t *dev)
{

	audioens_init_hw(dev);

	/*
	 * On this hardware, we want to disable the internal speaker by
	 * default, if it exists.  (We don't have a speakerphone on any
	 * of these cards, and no SPARC hardware uses it either!)
	 */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dev->dip, AC97_PROP_SPEAKER,
	    0);

	/*
	 * Init mixer
	 */

	dev->ac97 = ac97_alloc(dev->dip, audioens_rd97, audioens_wr97, dev);
	if (dev->ac97 == NULL)
		return (DDI_FAILURE);

	if (ac97_init(dev->ac97, dev->osdev) != 0) {
		return (DDI_FAILURE);
	}

	for (int i = 0; i <= PORT_MAX; i++) {
		audioens_port_t *port;
		unsigned caps;
		unsigned dmaflags;
		size_t rlen;
		ddi_dma_cookie_t c;
		unsigned ccnt;
		size_t bufsz;

		port = &dev->port[i];
		port->dev = dev;

		/*
		 * We have 48000Hz.  At that rate, 128 frames will give
		 * us an interrupt rate of 375Hz.  2048 frames buys about
		 * 42ms of buffer.  Note that interrupts are only enabled
		 * for platforms which need them (i.e. VMWare).
		 */

		switch (i) {
		case PORT_DAC:
			port->nchan = 4;
			port->speed = 48000;
			port->iframes = 128;
			port->nframes = 2048;
			caps = ENGINE_OUTPUT_CAP;
			dmaflags = DDI_DMA_WRITE | DDI_DMA_CONSISTENT;
			break;

		case PORT_ADC:
			port->nchan = 2;
			port->speed = 48000;
			port->iframes = 128;
			port->nframes = 2048;
			caps = ENGINE_INPUT_CAP;
			dmaflags = DDI_DMA_READ | DDI_DMA_CONSISTENT;
			break;
		}

		port->num = i;
		bufsz = port->nframes * port->nchan * sizeof (uint16_t);

		/*
		 * Allocate DMA resources.
		 */

		if (ddi_dma_alloc_handle(dev->dip, &dma_attr, DDI_DMA_SLEEP,
		    NULL, &port->dmah) != DDI_SUCCESS) {
			audio_dev_warn(dev->osdev,
			    "port %d: dma handle allocation failed", i);
			return (DDI_FAILURE);
		}
		if (ddi_dma_mem_alloc(port->dmah, bufsz, &buf_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &port->kaddr,
		    &rlen, &port->acch) != DDI_SUCCESS) {
			audio_dev_warn(dev->osdev,
			    "port %d: dma memory allocation failed", i);
			return (DDI_FAILURE);
		}
		/* ensure that the buffer is zeroed out properly */
		bzero(port->kaddr, rlen);
		if (ddi_dma_addr_bind_handle(port->dmah, NULL, port->kaddr,
		    bufsz, dmaflags, DDI_DMA_SLEEP, NULL,
		    &c, &ccnt) != DDI_DMA_MAPPED) {
			audio_dev_warn(dev->osdev,
			    "port %d: dma binding failed", i);
			return (DDI_FAILURE);
		}
		port->paddr = c.dmac_address;

		/*
		 * Allocate and configure audio engine.
		 */
		port->engine = audio_engine_alloc(&audioens_engine_ops, caps);
		if (port->engine == NULL) {
			audio_dev_warn(dev->osdev,
			    "port %d: audio_engine_alloc failed", i);
			return (DDI_FAILURE);
		}

		audio_engine_set_private(port->engine, port);
		audio_dev_add_engine(dev->osdev, port->engine);
	}

	if (audio_dev_register(dev->osdev) != DDI_SUCCESS) {
		audio_dev_warn(dev->osdev,
		    "unable to register with audio framework");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
audioens_destroy(audioens_dev_t *dev)
{
	int	i;

#ifdef __x86
	if (dev->useintr && dev->intrh != NULL) {
		(void) ddi_intr_disable(dev->intrh);
		(void) ddi_intr_remove_handler(dev->intrh);
		(void) ddi_intr_free(dev->intrh);
		dev->intrh = NULL;
	}
#endif

	mutex_destroy(&dev->mutex);

	/* free up ports, including DMA resources for ports */
	for (i = 0; i <= PORT_MAX; i++) {
		audioens_port_t	*port = &dev->port[i];

		if (port->paddr != 0)
			(void) ddi_dma_unbind_handle(port->dmah);
		if (port->acch != NULL)
			ddi_dma_mem_free(&port->acch);
		if (port->dmah != NULL)
			ddi_dma_free_handle(&port->dmah);

		if (port->engine != NULL) {
			audio_dev_remove_engine(dev->osdev, port->engine);
			audio_engine_free(port->engine);
		}
	}

	if (dev->acch != NULL) {
		ddi_regs_map_free(&dev->acch);
	}

	if (dev->ac97) {
		ac97_free(dev->ac97);
	}

	if (dev->osdev != NULL) {
		audio_dev_free(dev->osdev);
	}

	kmem_free(dev, sizeof (*dev));
}

int
audioens_attach(dev_info_t *dip)
{
	uint16_t pci_command, vendor, device;
	uint8_t revision;
	audioens_dev_t *dev;
	ddi_acc_handle_t pcih;
	const char *chip_name;
	const char *chip_vers;

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->dip = dip;
	ddi_set_driver_private(dip, dev);
	mutex_init(&dev->mutex, NULL, MUTEX_DRIVER, NULL);

	if (pci_config_setup(dip, &pcih) != DDI_SUCCESS) {
		audio_dev_warn(dev->osdev, "pci_config_setup failed");
		goto err_exit;
	}

	vendor = pci_config_get16(pcih, PCI_CONF_VENID);
	device = pci_config_get16(pcih, PCI_CONF_DEVID);
	revision = pci_config_get8(pcih, PCI_CONF_REVID);

	if ((vendor != ENSONIQ_VENDOR_ID && vendor != CREATIVE_VENDOR_ID) ||
	    (device != ENSONIQ_ES1371 && device != ENSONIQ_ES5880 &&
	    device != ENSONIQ_ES5880A && device != ECTIVA_ES1938 &&
	    device != ENSONIQ_ES5880B)) {
		audio_dev_warn(dev->osdev, "unrecognized device");
		goto err_exit;
	}

	chip_name = "AudioPCI97";
	chip_vers = "unknown";

	switch (device) {
	case ENSONIQ_ES1371:
		chip_name = "AudioPCI97";
		switch (revision) {
		case 0x02:
		case 0x09:
		default:
			chip_vers = "ES1371";
			break;
		case 0x04:
		case 0x06:
		case 0x08:
			chip_vers = "ES1373";
			break;
		case 0x07:
			chip_vers = "ES5880";
			break;
		}
		break;

	case ENSONIQ_ES5880:
		chip_name = "SB PCI128";
		chip_vers = "ES5880";
		break;
	case ENSONIQ_ES5880A:
		chip_name = "SB PCI128";
		chip_vers = "ES5880A";
		break;
	case ENSONIQ_ES5880B:
		chip_name = "SB PCI128";
		chip_vers = "ES5880B";
		break;

	case ECTIVA_ES1938:
		chip_name = "AudioPCI";
		chip_vers = "ES1938";
		break;
	}

	dev->revision = revision;
	dev->devid = device;

	dev->osdev = audio_dev_alloc(dip, 0);
	if (dev->osdev == NULL) {
		goto err_exit;
	}

	audio_dev_set_description(dev->osdev, chip_name);
	audio_dev_set_version(dev->osdev, chip_vers);

	/* set the PCI latency */
	if ((audioens_latency == 32) || (audioens_latency == 64) ||
	    (audioens_latency == 96))
		pci_config_put8(pcih, PCI_CONF_LATENCY_TIMER,
		    audioens_latency);

	/* activate the device */
	pci_command = pci_config_get16(pcih, PCI_CONF_COMM);
	pci_command |= PCI_COMM_ME | PCI_COMM_IO;
	pci_config_put16(pcih, PCI_CONF_COMM, pci_command);

	/* map registers */
	if (ddi_regs_map_setup(dip, 1, &dev->regs, 0, 0, &acc_attr,
	    &dev->acch) != DDI_SUCCESS) {
		audio_dev_warn(dev->osdev, "can't map registers");
		goto err_exit;
	}

#ifdef __x86
	/*
	 * Virtual platforms (mostly VMWare!) seem to need us to pulse
	 * the interrupt enables to make progress.  So enable (emulated)
	 * hardware interrupts.
	 */
	dev->useintr = B_FALSE;
	if (get_hwenv() & HW_VIRTUAL) {
		dev->useintr = B_TRUE;
		if (audioens_setup_intr(dev) != DDI_SUCCESS) {
			goto err_exit;
		}
		/* Reinitialize the mutex with interrupt priority. */
		mutex_destroy(&dev->mutex);
		mutex_init(&dev->mutex, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(dev->intrpri));
	}
#endif

	/* This allocates and configures the engines */
	if (audioens_init(dev) != DDI_SUCCESS) {
		audio_dev_warn(dev->osdev, "can't init device");
		goto err_exit;
	}

#ifdef __x86
	if (dev->useintr) {
		(void) ddi_intr_enable(dev->intrh);
	}
#endif
	pci_config_teardown(&pcih);

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

err_exit:
	pci_config_teardown(&pcih);

	audioens_destroy(dev);

	return (DDI_FAILURE);
}

int
audioens_detach(audioens_dev_t *dev)
{
	int tmp;

	/* first unregister us from the DDI framework, might be busy */
	if (audio_dev_unregister(dev->osdev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	mutex_enter(&dev->mutex);

	tmp = GET8(dev, CONC_bSERCTL_OFF) &
	    ~(CONC_SERCTL_DAC2IE | CONC_SERCTL_DAC1IE | CONC_SERCTL_ADCIE);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);

	tmp = GET8(dev, CONC_bDEVCTL_OFF) &
	    ~(CONC_DEVCTL_DAC2_EN | CONC_DEVCTL_ADC_EN | CONC_DEVCTL_DAC1_EN);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);

	mutex_exit(&dev->mutex);

	audioens_destroy(dev);

	return (DDI_SUCCESS);
}

static int
audioens_resume(audioens_dev_t *dev)
{
	mutex_enter(&dev->mutex);
	dev->suspended = B_FALSE;
	mutex_exit(&dev->mutex);

	/* reinitialize hardware */
	audioens_init_hw(dev);

	/* restore AC97 state */
	ac97_reset(dev->ac97);

	audio_dev_resume(dev->osdev);

	return (DDI_SUCCESS);
}

static int
audioens_suspend(audioens_dev_t *dev)
{
	audio_dev_suspend(dev->osdev);

	mutex_enter(&dev->mutex);
	CLR8(dev, CONC_bDEVCTL_OFF,
	    CONC_DEVCTL_DAC2_EN | CONC_DEVCTL_DAC1_EN | CONC_DEVCTL_ADC_EN);
	dev->suspended = B_TRUE;
	mutex_exit(&dev->mutex);

	return (DDI_SUCCESS);
}

static int
audioens_quiesce(dev_info_t *dip)
{
	audioens_dev_t	*dev;
	uint8_t		tmp;

	if ((dev = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	/* This disables all DMA engines and interrupts */
	tmp = GET8(dev, CONC_bSERCTL_OFF) &
	    ~(CONC_SERCTL_DAC2IE | CONC_SERCTL_DAC1IE | CONC_SERCTL_ADCIE);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);
	PUT8(dev, CONC_bSERCTL_OFF, tmp);

	tmp = GET8(dev, CONC_bDEVCTL_OFF) &
	    ~(CONC_DEVCTL_DAC2_EN | CONC_DEVCTL_ADC_EN | CONC_DEVCTL_DAC1_EN);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);
	PUT8(dev, CONC_bDEVCTL_OFF, tmp);

	return (DDI_SUCCESS);
}


static int
audioens_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	audioens_dev_t *dev;

	switch (cmd) {
	case DDI_ATTACH:
		return (audioens_attach(dip));

	case DDI_RESUME:
		if ((dev = ddi_get_driver_private(dip)) == NULL) {
			return (DDI_FAILURE);
		}
		return (audioens_resume(dev));

	default:
		return (DDI_FAILURE);
	}
}

static int
audioens_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audioens_dev_t *dev;

	if ((dev = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		return (audioens_detach(dev));

	case DDI_SUSPEND:
		return (audioens_suspend(dev));
	default:
		return (DDI_FAILURE);
	}
}

static int audioens_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int audioens_ddi_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops audioens_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	audioens_ddi_attach,	/* attach */
	audioens_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	audioens_quiesce,	/* quiesce */
};

static struct modldrv audioens_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Ensoniq 1371/1373 Audio",	/* linkinfo */
	&audioens_dev_ops,		/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &audioens_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&audioens_dev_ops, DRVNAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&audioens_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&audioens_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
