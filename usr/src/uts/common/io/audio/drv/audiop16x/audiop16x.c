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

static int p16x_open(void *, int, unsigned *, caddr_t *);
static void p16x_close(void *);
static int p16x_start(void *);
static void p16x_stop(void *);
static int p16x_format(void *);
static int p16x_channels(void *);
static int p16x_rate(void *);
static uint64_t p16x_count(void *);
static void p16x_sync(void *, unsigned);
static void p16x_chinfo(void *, int, unsigned *, unsigned *);

static uint16_t p16x_read_ac97(void *, uint8_t);
static void p16x_write_ac97(void *, uint8_t, uint16_t);
static int p16x_alloc_port(p16x_dev_t *, int);
static void p16x_destroy(p16x_dev_t *);
static void p16x_hwinit(p16x_dev_t *);

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
	NULL,
	p16x_chinfo,
	NULL
};

static unsigned int
read_reg(p16x_dev_t *dev, int reg, int chn)
{
	unsigned int val;

	mutex_enter(&dev->mutex);
	OUTL(dev, (reg << 16) | (chn & 0xffff), PTR);	/* Pointer */
	val = INL(dev, DR);	/* Data */
	mutex_exit(&dev->mutex);

	return (val);
}

static void
write_reg(p16x_dev_t *dev, int reg, int chn, unsigned int value)
{

	mutex_enter(&dev->mutex);
	OUTL(dev, (reg << 16) | (chn & 0xffff), PTR);	/* Pointer */
	OUTL(dev, value, DR);	/* Data */
	mutex_exit(&dev->mutex);
}

static void
set_reg_bits(p16x_dev_t *dev, int reg, int chn, unsigned int mask)
{
	unsigned int	val;
	mutex_enter(&dev->mutex);
	OUTL(dev, (reg << 16) | (chn & 0xffff), PTR);	/* Pointer */
	val = INL(dev, DR);	/* Data */
	val |= mask;
	OUTL(dev, val, DR);	/* Data */
	mutex_exit(&dev->mutex);
}

static void
clear_reg_bits(p16x_dev_t *dev, int reg, int chn, unsigned int mask)
{
	unsigned int	val;
	mutex_enter(&dev->mutex);
	OUTL(dev, (reg << 16) | (chn & 0xffff), PTR);	/* Pointer */
	val = INL(dev, DR);	/* Data */
	val &= ~(mask);
	OUTL(dev, val, DR);	/* Data */
	mutex_exit(&dev->mutex);
}

static uint16_t
p16x_read_ac97(void *arg, uint8_t index)
{
	p16x_dev_t *dev = arg;
	uint16_t value;
	int i;

	OUTB(dev, index, AC97A);
	for (i = 0; i < 10000; i++)
		if (INB(dev, AC97A) & 0x80)
			break;
	value = INW(dev, AC97D);
	return (value);
}

static void
p16x_write_ac97(void *arg, uint8_t index, uint16_t data)
{
	p16x_dev_t *dev = arg;
	unsigned int i;

	OUTB(dev, index, AC97A);
	for (i = 0; i < 10000; i++)
		if (INB(dev, AC97A) & 0x80)
			break;
	OUTW(dev, data, AC97D);
}

/*
 * Audio routines
 */

int
p16x_open(void *arg, int flag, uint_t *nframes, caddr_t *bufp)
{
	p16x_port_t	*port = arg;

	_NOTE(ARGUNUSED(flag));

	port->count = 0;
	*nframes = port->buf_frames;
	*bufp = port->buf_kaddr;

	return (0);
}

void
p16x_close(void *arg)
{
	_NOTE(ARGUNUSED(arg));
}

int
p16x_start(void *arg)
{
	p16x_port_t	*port = arg;
	p16x_dev_t	*dev = port->dev;

	port->offset = 0;

	if (port->port_num == P16X_REC) {
		write_reg(dev, CRFA, 0, 0);
		write_reg(dev, CRCAV, 0, 0);

		/* Enable rec channel */
		set_reg_bits(dev, SA, 0, 0x100);
	} else {
		for (int i = 0; i < 3; i++) {
			write_reg(dev, PTBA, i, 0);
			write_reg(dev, PTBS, i, 0);
			write_reg(dev, PTCA, i, 0);
			write_reg(dev, PFEA, i, 0);
			write_reg(dev, CPFA, i, 0);
			write_reg(dev, CPCAV, i, 0);
		}

		/* Enable play channel */
		set_reg_bits(dev, SA, 0, 0x7);
	}

	return (0);
}

void
p16x_stop(void *arg)
{
	p16x_port_t	*port = arg;
	p16x_dev_t	*dev = port->dev;

	if (port->port_num == P16X_REC) {
		/* Disable rec channel */
		clear_reg_bits(dev, SA, 0, 0x100);

	} else {
		/* Disable Play channel */
		clear_reg_bits(dev, SA, 0, 0x7);
	}
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

uint64_t
p16x_count(void *arg)
{
	p16x_port_t	*port = arg;
	p16x_dev_t	*dev = port->dev;
	uint64_t	val;
	uint32_t	offset, n;

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
	val = port->count;

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

int
p16x_alloc_port(p16x_dev_t *dev, int num)
{
	p16x_port_t		*port;
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

	switch (num) {
	case P16X_REC:
		port->syncdir = DDI_DMA_SYNC_FORKERNEL;
		caps = ENGINE_INPUT_CAP;
		dir = DDI_DMA_READ;
		port->port_num = P16X_REC;
		port->nchan = 2;
		break;
	case P16X_PLAY:
		port->syncdir = DDI_DMA_SYNC_FORDEV;
		caps = ENGINE_OUTPUT_CAP;
		dir = DDI_DMA_WRITE;
		port->port_num = P16X_PLAY;
		port->nchan = 6;
		break;
	default:
		return (DDI_FAILURE);
	}

	/*
	 * NB: The device operates in pairs of dwords at a time, for
	 * performance reasons.  So make sure that our buffer is
	 * arranged as a whole number of these.  The value below gives
	 * a reasonably large buffer so we can support a deep
	 * playahead if we need to (and we should avoid input
	 * overruns.)
	 */
	port->buf_frames = 4096;
	port->buf_size = port->buf_frames * port->nchan * sizeof (uint16_t);

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
	mutex_destroy(&dev->mutex);

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
p16x_attach(dev_info_t *dip)
{
	uint16_t	vendor, device;
	p16x_dev_t	*dev;
	ddi_acc_handle_t pcih;

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->dip = dip;
	ddi_set_driver_private(dip, dev);

	mutex_init(&dev->mutex, NULL, MUTEX_DRIVER, NULL);

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

	if (audio_dev_register(dev->adev) != DDI_SUCCESS) {
		audio_dev_warn(dev->adev, "unable to register with framework");
		goto error;
	}

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

	ac97_reset(dev->ac97);

	audio_dev_resume(dev->adev);

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
	audio_dev_suspend(dev->adev);

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

	write_reg(dev, SA, 0, 0);
	OUTL(dev, 0x01, HC);

	return (DDI_SUCCESS);
}
