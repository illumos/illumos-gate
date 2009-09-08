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
 * Purpose: Driver for the Creative P16X AC97 audio controller
 */
/*
 *
 * Copyright (C) 4Front Technologies 1996-2009.
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
#include <sys/note.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>

#include "audiop16x.h"

/*
 * These boards use an AC'97 codec, but don't have all of the
 * various outputs that the AC'97 codec can offer.  We just
 * suppress them for now.
 */
static char *p16x_remove_ac97[] = {
	AUDIO_CTRL_ID_BEEP,
	AUDIO_CTRL_ID_VIDEO,
	AUDIO_CTRL_ID_MICSRC,
	AUDIO_CTRL_ID_SPEAKER,
	AUDIO_CTRL_ID_SPKSRC,
	NULL
};

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
	0xfffffffe,		/* DMA counter register */
	4,			/* DMA address alignment */
	0x3c,			/* DMA burstsizes */
	4,			/* min effective DMA size */
	0xffffffff,		/* max DMA xfer size */
	0xffffffff,		/* segment boundary */
	1,			/* s/g length */
	4,			/* granularity of device */
	0			/* Bus specific DMA flags */
};

static int p16x_attach(dev_info_t *);
static int p16x_resume(dev_info_t *);
static int p16x_detach(p16x_dev_t *);
static int p16x_suspend(p16x_dev_t *);

static int p16x_open(void *, int, unsigned *, unsigned *, caddr_t *);
static void p16x_close(void *);
static int p16x_start(void *);
static void p16x_stop(void *);
static int p16x_format(void *);
static int p16x_channels(void *);
static int p16x_rate(void *);
static uint64_t p16x_count(void *);
static void p16x_sync(void *, unsigned);
static size_t p16x_qlen(void *);
static void p16x_chinfo(void *, int, unsigned *, unsigned *);

static uint16_t p16x_read_ac97(void *, uint8_t);
static void p16x_write_ac97(void *, uint8_t, uint16_t);
static int p16x_alloc_port(p16x_dev_t *, int);
static void p16x_update_port(p16x_port_t *);
static void p16x_start_port(p16x_port_t *);
static void p16x_stop_port(p16x_port_t *);
static void p16x_destroy(p16x_dev_t *);
static int p16x_setup_intrs(p16x_dev_t *);
static void p16x_hwinit(p16x_dev_t *);
static uint_t p16x_intr(caddr_t, caddr_t);

static audio_engine_ops_t p16x_engine_ops = {
	AUDIO_ENGINE_VERSION,
	p16x_open,
	p16x_close,
	p16x_start,
	p16x_stop,
	p16x_count,
	p16x_format,
	p16x_channels,
	p16x_rate,
	p16x_sync,
	p16x_qlen,
	p16x_chinfo,
};

static unsigned int
read_reg(p16x_dev_t *dev, int reg, int chn)
{
	unsigned int val;

	mutex_enter(&dev->low_mutex);
	OUTL(dev, (reg << 16) | (chn & 0xffff), PTR);	/* Pointer */
	val = INL(dev, DR);	/* Data */
	mutex_exit(&dev->low_mutex);

	return (val);
}

static void
write_reg(p16x_dev_t *dev, int reg, int chn, unsigned int value)
{

	mutex_enter(&dev->low_mutex);
	OUTL(dev, (reg << 16) | (chn & 0xffff), PTR);	/* Pointer */
	OUTL(dev, value, DR);	/* Data */
	mutex_exit(&dev->low_mutex);
}

static uint16_t
p16x_read_ac97(void *arg, uint8_t index)
{
	p16x_dev_t *dev = arg;
	uint16_t value;
	int i;

	mutex_enter(&dev->low_mutex);
	OUTB(dev, index, AC97A);
	for (i = 0; i < 10000; i++)
		if (INB(dev, AC97A) & 0x80)
			break;
	value = INW(dev, AC97D);
	mutex_exit(&dev->low_mutex);
	return (value);
}

static void
p16x_write_ac97(void *arg, uint8_t index, uint16_t data)
{
	p16x_dev_t *dev = arg;
	unsigned int i;

	mutex_enter(&dev->low_mutex);
	OUTB(dev, index, AC97A);
	for (i = 0; i < 10000; i++)
		if (INB(dev, AC97A) & 0x80)
			break;
	OUTW(dev, data, AC97D);
	mutex_exit(&dev->low_mutex);
}

static uint_t
p16x_intr(caddr_t argp, caddr_t nocare)
{
	p16x_dev_t	*dev = (void *)argp;
	unsigned int	status;
	audio_engine_t	*consume = NULL;
	audio_engine_t	*produce = NULL;

	_NOTE(ARGUNUSED(nocare));

	mutex_enter(&dev->mutex);
	if (dev->suspended) {
		mutex_exit(&dev->mutex);
		return (DDI_INTR_UNCLAIMED);
	}
	/* Read the interrupt status */
	status = INL(dev, IP);
	OUTL(dev, status, IP);	/* Acknowledge */

	if (!(status & INTR_ALL)) {
		mutex_exit(&dev->mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	if (status & INTR_PCI) {
		audio_dev_warn(dev->adev, "PCI error triggered, PCI status %x",
		    pci_config_get16(dev->pcih, PCI_CONF_STAT));
	}

	if ((status & (INTR_PFF | INTR_PFH)) &&
	    (dev->port[P16X_PLAY]->started)) {
		consume = dev->port[P16X_PLAY]->engine;
	}

	if ((status & (INTR_RFF | INTR_RFH)) &&
	    (dev->port[P16X_REC]->started)) {
		produce = dev->port[P16X_REC]->engine;
	}

	mutex_exit(&dev->mutex);

	if (consume) {
		audio_engine_consume(consume);
	}

	if (produce) {
		audio_engine_produce(produce);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Audio routines
 */

static void
p16x_init_port(p16x_port_t *port)
{
	p16x_dev_t	*dev = port->dev;

	if (port->suspended)
		return;

	if (port->port_num == P16X_REC) {
		write_reg(dev, CRFA, 0, 0);
		write_reg(dev, CRCAV, 0, 0);

	} else {
		for (int i = 0; i < 3; i++) {
			write_reg(dev, PTBA, i, 0);
			write_reg(dev, PTBS, i, 0);
			write_reg(dev, PTCA, i, 0);
			write_reg(dev, PFEA, i, 0);
			write_reg(dev, CPFA, i, 0);
			write_reg(dev, CPCAV, i, 0);
		}

	}
}


static int
p16x_open(void *arg, int flag, uint_t *fragfrp, uint_t *nfp, caddr_t *bufp)
{
	p16x_port_t	*port = arg;
	p16x_dev_t	*dev = port->dev;

	_NOTE(ARGUNUSED(flag));

	mutex_enter(&dev->mutex);

	port->started = B_FALSE;
	port->count = 0;
	port->offset = 0;

	p16x_init_port(port);

	*fragfrp = port->fragfr;
	*nfp = port->nfrags;
	*bufp = port->buf_kaddr;
	mutex_exit(&dev->mutex);

	return (0);
}

void
p16x_close(void *arg)
{
	p16x_port_t	 *port = arg;
	p16x_dev_t	 *dev = port->dev;

	mutex_enter(&dev->mutex);
	p16x_stop_port(port);
	port->started = B_FALSE;
	mutex_exit(&dev->mutex);
}

int
p16x_start(void *arg)
{
	p16x_port_t	*port = arg;
	p16x_dev_t	*dev = port->dev;

	mutex_enter(&dev->mutex);
	if (!port->started) {
		p16x_start_port(port);
		port->started = B_TRUE;
	}
	mutex_exit(&dev->mutex);
	return (0);
}

void
p16x_stop(void *arg)
{
	p16x_port_t	*port = arg;
	p16x_dev_t	*dev = port->dev;

	mutex_enter(&dev->mutex);
	if (port->started) {
		p16x_stop_port(port);
		port->started = B_FALSE;
	}
	mutex_exit(&dev->mutex);
}

int
p16x_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

int
p16x_channels(void *arg)
{
	p16x_port_t *port = arg;

	return (port->nchan);
}

int
p16x_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}

void
p16x_sync(void *arg, unsigned nframes)
{
	p16x_port_t *port = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(port->buf_dmah, 0, 0, port->syncdir);
}

size_t
p16x_qlen(void *arg)
{
	_NOTE(ARGUNUSED(arg));
	return (0);
}

uint64_t
p16x_count(void *arg)
{
	p16x_port_t	*port = arg;
	p16x_dev_t	*dev = port->dev;
	uint64_t	val;

	mutex_enter(&dev->mutex);
	if (port->started && !dev->suspended)
		p16x_update_port(port);
	val = port->count;
	mutex_exit(&dev->mutex);

	return (val);
}

static void
p16x_chinfo(void *arg, int chan, unsigned *offset, unsigned *incr)
{
	p16x_port_t *port = arg;
	unsigned mult;

	if (port->port_num == P16X_PLAY) {
		switch (chan) {
		case 0:	/* left front */
		case 1:	/* right front */
			mult = 0;
			break;
		case 2:	/* center */
		case 3:	/* lfe */
			mult = 2;
			break;
		case 4:	/* left surround */
		case 5:	/* right surround */
			mult = 1;
			break;
		}
		*offset = (port->buf_frames * 2 * mult) + (chan % 2);
		*incr = 2;
	} else {
		*offset = chan;
		*incr = 2;
	}
}

/* private implementation bits */

void
p16x_update_port(p16x_port_t *port)
{
	p16x_dev_t	*dev = port->dev;
	uint32_t	offset, n;

	if (dev->suspended)
		return;

	if (port->port_num == P16X_PLAY) {
		offset = read_reg(dev, CPFA, 0);
	} else {
		offset = read_reg(dev, CRFA, 0);
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
}

void
p16x_start_port(p16x_port_t *port)
{
	p16x_dev_t	*dev = port->dev;
	unsigned int	tmp;

	ASSERT(mutex_owned(&dev->mutex));

	if (dev->suspended)
		return;

	if (port->port_num == P16X_REC) {
		/* Enable Rec Channel */
		tmp = read_reg(dev, SA, 0);
		tmp |= 0x100;
		write_reg(dev, SA, 0, tmp);
		tmp = INL(dev, IE);
		tmp |= INTR_REC;
		OUTL(dev, tmp, IE);
	} else {
		/* Enable play channel and go */
		tmp = read_reg(dev, SA, 0);
		tmp |= 7;
		write_reg(dev, SA, 0, tmp);
		tmp = INL(dev, IE);
		tmp |= INTR_PLAY;
		OUTL(dev, tmp, IE);
	}
}

void
p16x_stop_port(p16x_port_t *port)
{
	p16x_dev_t	*dev = port->dev;
	unsigned int tmp;


	if (dev->suspended)
		return;

	if (port->port_num == P16X_REC) {
		/* Disable rec channel */
		tmp = read_reg(dev, SA, 0);
		tmp &= ~0x100;
		write_reg(dev, SA, 0, tmp);
		tmp = INL(dev, IE);
		tmp &= ~INTR_REC;
		OUTL(dev, tmp, IE);

	} else {
		/* Disable Play channel */
		tmp = read_reg(dev, SA, 0);
		tmp &= ~7;
		write_reg(dev, SA, 0, tmp);
		tmp = INL(dev, IE);
		tmp &= ~INTR_PLAY;
		OUTL(dev, tmp, IE);
	}
}

int
p16x_alloc_port(p16x_dev_t *dev, int num)
{
	p16x_port_t		*port;
	size_t			len;
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			dir;
	char			*prop;
	unsigned		caps;
	audio_dev_t		*adev;

	adev = dev->adev;
	port = kmem_zalloc(sizeof (*port), KM_SLEEP);
	dev->port[num] = port;
	port->dev = dev;
	port->started = B_FALSE;

	switch (num) {
	case P16X_REC:
		prop = "record-interrupts";
		port->syncdir = DDI_DMA_SYNC_FORKERNEL;
		caps = ENGINE_INPUT_CAP;
		dir = DDI_DMA_READ;
		port->port_num = P16X_REC;
		port->nchan = 2;
		break;
	case P16X_PLAY:
		prop = "play-interrupts";
		port->syncdir = DDI_DMA_SYNC_FORDEV;
		caps = ENGINE_OUTPUT_CAP;
		dir = DDI_DMA_WRITE;
		port->port_num = P16X_PLAY;
		port->nchan = 6;
		break;
	default:
		return (DDI_FAILURE);
	}

	/* figure out fragment configuration */
	port->intrs = ddi_prop_get_int(DDI_DEV_T_ANY, dev->dip,
	    DDI_PROP_DONTPASS, prop, P16X_DEF_INTRS);

	/* make sure the values are good */
	if (port->intrs < P16X_MIN_INTRS) {
		audio_dev_warn(adev, "%s too low, %d, reset to %d",
		    prop, port->intrs, P16X_MIN_INTRS);
		port->intrs = P16X_MIN_INTRS;
	} else if (port->intrs > P16X_MAX_INTRS) {
		audio_dev_warn(adev, "%s too high, %d, reset to %d",
		    prop, port->intrs, P16X_DEF_INTRS);
		port->intrs = P16X_DEF_INTRS;
	}

	/*
	 * We choose 6 fragments for a specific reason.	 Since the
	 * device only has full and half interrupts, and since the
	 * framework will try to queue up 4 frags automatically, this
	 * ensures that we will be able to queue all 4 fragments, and
	 * it avoids a potential underrun that you would get with 8
	 * fragments.  (More than 8 fragments is guaranteed to cause
	 * underruns in Boomer.)
	 *
	 * Boomer needs to get smarter about dealing with devices with
	 * fewer fragment counts.  This device, for instance, should
	 * really be represented with just two fragments.  That wll
	 * cause an infinite loop in Boomer, when Boomer tries to
	 * queue up 4 fragments.
	 */
	port->nfrags = 6;
	port->fragfr = 48000 / port->intrs;
	/*
	 * The device operates in pairs of dwords at a time, for
	 * performance reasons.	 So make sure that our buffer is
	 * arranged as a whole number of these.	 We could probably
	 * fine tune by just ensuring that the overall buffer was 128
	 * (64 for half and 64 for full), but this is simpler.
	 */
	port->fragfr = (port->fragfr + 63) & ~(63);
	port->fragsz = port->fragfr * port->nchan * 2; /* 16 bit frames */
	port->buf_size = port->nfrags * port->fragsz;
	port->buf_frames = port->fragfr * port->nfrags;

	/* now allocate buffers */
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

	port->engine = audio_engine_alloc(&p16x_engine_ops, caps);
	if (port->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(port->engine, port);
	audio_dev_add_engine(adev, port->engine);

	return (DDI_SUCCESS);
}

void
p16x_destroy(p16x_dev_t *dev)
{
	if (dev->ih != NULL) {
		(void) ddi_intr_disable(dev->ih);
		(void) ddi_intr_remove_handler(dev->ih);
		(void) ddi_intr_free(dev->ih);
		mutex_destroy(&dev->mutex);
		mutex_destroy(&dev->low_mutex);
	}

	if (dev->ksp) {
		kstat_delete(dev->ksp);
	}

	for (int i = 0; i < P16X_NUM_PORT; i++) {
		p16x_port_t *port = dev->port[i];
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
p16x_hwinit(p16x_dev_t *dev)
{
	p16x_port_t		*port;
	uint32_t		paddr;
	uint32_t		chunksz;
	int i;

	for (i = 0; i < 3; i++) {
		write_reg(dev, PTBA, i, 0);
		write_reg(dev, PTBS, i, 0);
		write_reg(dev, PTCA, i, 0);
		write_reg(dev, PFEA, i, 0);
		write_reg(dev, CPFA, i, 0);
		write_reg(dev, CPCAV, i, 0);
		write_reg(dev, CRFA, i, 0);
		write_reg(dev, CRCAV, i, 0);
	}
	write_reg(dev, SCS0, 0, 0x02108504);
	write_reg(dev, SCS1, 0, 0x02108504);
	write_reg(dev, SCS2, 0, 0x02108504);

	/* set the spdif/analog combo jack to analog out */
	write_reg(dev, SPC, 0, 0x00000700);
	write_reg(dev, EA_aux, 0, 0x0001003f);

	port = dev->port[P16X_REC];
	/* Set physical address of the DMA buffer */
	write_reg(dev, RFBA, 0, port->buf_paddr);
	write_reg(dev, RFBS, 0, (port->buf_size) << 16);

	/* Set physical address of the DMA buffer */
	port = dev->port[P16X_PLAY];
	paddr = port->buf_paddr;
	chunksz = port->buf_frames * 4;
	write_reg(dev, PFBA, 0, paddr);
	write_reg(dev, PFBS, 0, chunksz << 16);
	paddr += chunksz;
	write_reg(dev, PFBA, 1, paddr);
	write_reg(dev, PFBS, 1, chunksz << 16);
	paddr += chunksz;
	write_reg(dev, PFBA, 2, paddr);
	write_reg(dev, PFBS, 2, chunksz << 16);

	OUTL(dev, 0x1080, GPIO);	/* GPIO */
	/* Clear any pending interrupts */
	OUTL(dev, INTR_ALL, IP);
	OUTL(dev, 0, IE);
	OUTL(dev, 0x9, HC);	/* Enable audio */
}

int
p16x_setup_intrs(p16x_dev_t *dev)
{
	uint_t			ipri;
	int			actual;
	int			rv;
	ddi_intr_handle_t	ih[1];

	rv = ddi_intr_alloc(dev->dip, ih, DDI_INTR_TYPE_FIXED,
	    0, 1, &actual, DDI_INTR_ALLOC_STRICT);
	if ((rv != DDI_SUCCESS) || (actual != 1)) {
		audio_dev_warn(dev->adev,
		    "Can't alloc interrupt handle (rv %d actual %d)",
		    rv, actual);
		return (DDI_FAILURE);
	}

	if (ddi_intr_get_pri(ih[0], &ipri) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "Can't get interrupt priority");
		(void) ddi_intr_free(ih[0]);
		return (DDI_FAILURE);
	}

	if (ddi_intr_add_handler(ih[0], p16x_intr, dev, NULL) !=
	    DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "Can't add interrupt handler");
		(void) ddi_intr_free(ih[0]);
		return (DDI_FAILURE);
	}

	dev->ih = ih[0];
	mutex_init(&dev->mutex, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));
	mutex_init(&dev->low_mutex, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));
	return (DDI_SUCCESS);
}

int
p16x_attach(dev_info_t *dip)
{
	uint16_t	vendor, device;
	p16x_dev_t	*dev;
	ddi_acc_handle_t pcih;

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->dip = dip;
	ddi_set_driver_private(dip, dev);

	/* we don't support high level interrupts in the driver */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		cmn_err(CE_WARN,
		    "!%s%d: unsupported high level interrupt",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	if (ddi_get_iblock_cookie(dip, 0, &dev->iblock) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s%d: cannot get iblock cookie",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		kmem_free(dev, sizeof (*dev));
		return (DDI_FAILURE);
	}
	mutex_init(&dev->mutex, NULL, MUTEX_DRIVER, dev->iblock);
	mutex_init(&dev->low_mutex, NULL, MUTEX_DRIVER, dev->iblock);

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
	if (vendor != CREATIVE_VENDOR_ID ||
	    device != SB_P16X_ID) {
		audio_dev_warn(dev->adev, "Hardware not recognized "
		    "(vendor=%x, dev=%x)", vendor, device);
		goto error;
	}

	/* set PCI command register */
	pci_config_put16(pcih, PCI_CONF_COMM,
	    pci_config_get16(pcih, PCI_CONF_COMM) |
	    PCI_COMM_MAE | PCI_COMM_IO);


	if ((ddi_regs_map_setup(dip, 1, &dev->base, 0, 0, &dev_attr,
	    &dev->regsh)) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "failed to map registers");
		goto error;
	}

	audio_dev_set_description(dev->adev, "Creative Sound Blaster Live!");
	audio_dev_set_version(dev->adev, "SBO200");

	if ((p16x_alloc_port(dev, P16X_PLAY) != DDI_SUCCESS) ||
	    (p16x_alloc_port(dev, P16X_REC) != DDI_SUCCESS)) {
		goto error;
	}

	p16x_hwinit(dev);

	/* set up the interrupt handler */
	if (p16x_setup_intrs(dev) != DDI_SUCCESS) {
		goto error;
	}

	/* Enable PCI interrupts */
	OUTL(dev, INTR_PCI, IE);

	dev->ac97 = ac97_allocate(dev->adev, dip,
	    p16x_read_ac97, p16x_write_ac97, dev);
	if (dev->ac97 == NULL) {
		audio_dev_warn(dev->adev, "failed to allocate ac97 handle");
		goto error;
	}

	ac97_probe_controls(dev->ac97);

	/* remove the AC'97 controls we don't want to expose */
	for (int i = 0; p16x_remove_ac97[i]; i++) {
		ac97_ctrl_t *ctrl;
		ctrl = ac97_control_find(dev->ac97, p16x_remove_ac97[i]);
		if (ctrl != NULL) {
			ac97_control_unregister(ctrl);
		}
	}

	ac97_register_controls(dev->ac97);

	/* set up kernel statistics */
	if ((dev->ksp = kstat_create(P16X_NAME, ddi_get_instance(dip),
	    P16X_NAME, "controller", KSTAT_TYPE_INTR, 1,
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(dev->ksp);
	}

	if (audio_dev_register(dev->adev) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "unable to register with framework");
		goto error;
	}

	(void) ddi_intr_enable(dev->ih);
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	p16x_destroy(dev);
	return (DDI_FAILURE);
}

int
p16x_resume(dev_info_t *dip)
{
	p16x_dev_t *dev;

	dev = ddi_get_driver_private(dip);

	p16x_hwinit(dev);

	/* allow ac97 operations again */
	ac97_resume(dev->ac97);

	mutex_enter(&dev->mutex);
	dev->suspended = B_FALSE;

	for (int i = 0; i < P16X_NUM_PORT; i++) {

		p16x_port_t *port = dev->port[i];

		if (port->engine != NULL)
			audio_engine_reset(port->engine);

		/* reset the port */
		p16x_init_port(port);

		if (port->started) {
			p16x_start_port(port);
		} else {
			p16x_stop_port(port);
		}
	}
	mutex_exit(&dev->mutex);
	return (DDI_SUCCESS);
}

int
p16x_detach(p16x_dev_t *dev)
{
	if (audio_dev_unregister(dev->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	p16x_destroy(dev);
	return (DDI_SUCCESS);
}

int
p16x_suspend(p16x_dev_t *dev)
{
	ac97_suspend(dev->ac97);

	mutex_enter(&dev->mutex);
	for (int i = 0; i < P16X_NUM_PORT; i++) {

		p16x_port_t *port = dev->port[i];
		p16x_stop_port(port);
	}

	write_reg(dev, SA, 0, 0);
	OUTL(dev, 0x00, IE);	/* Interrupt disable */
	OUTL(dev, 0x01, HC);

	dev->suspended = B_TRUE;
	mutex_exit(&dev->mutex);
	return (DDI_SUCCESS);
}

static int p16x_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int p16x_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int p16x_ddi_quiesce(dev_info_t *);

static struct dev_ops p16x_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	p16x_ddi_attach,	/* attach */
	p16x_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	p16x_ddi_quiesce,	/* quiesce */
};

static struct modldrv p16x_modldrv = {
	&mod_driverops,		/* drv_modops */
	"Creative P16X Audio",	/* linkinfo */
	&p16x_dev_ops,		/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &p16x_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&p16x_dev_ops, P16X_NAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&p16x_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&p16x_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
p16x_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (p16x_attach(dip));

	case DDI_RESUME:
		return (p16x_resume(dip));

	default:
		return (DDI_FAILURE);
	}
}

int
p16x_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	p16x_dev_t *dev;

	dev = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		return (p16x_detach(dev));

	case DDI_SUSPEND:
		return (p16x_suspend(dev));

	default:
		return (DDI_FAILURE);
	}
}

int
p16x_ddi_quiesce(dev_info_t *dip)
{
	p16x_dev_t	*dev;

	dev = ddi_get_driver_private(dip);

	for (int i = 0; i < P16X_NUM_PORT; i++) {

		p16x_port_t *port = dev->port[i];
		p16x_stop_port(port);
	}

	write_reg(dev, SA, 0, 0);
	OUTL(dev, 0x00, IE);	    /* Interrupt disable */
	OUTL(dev, 0x01, HC);

	return (DDI_SUCCESS);
}
