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
 * Purpose: Driver for the VIA VT82C686A AC97 audio controller
 */
/*
 *
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

#include "audiovia97.h"

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

static ddi_dma_attr_t dma_attr_sgd = {
	DMA_ATTR_V0,		/* version number */
	0x00000000,		/* low DMA address range */
	0xffffffff,		/* high DMA address range */
	0x0000ffff,		/* DMA counter register */
	8,			/* DMA address alignment */
	0x3c,			/* DMA burstsizes */
	8,			/* min effective DMA size */
	0xffffffff,		/* max DMA xfer size */
	0x00000fff,		/* segment boundary */
	1,			/* s/g length */
	8,			/* granularity of device */
	0			/* Bus specific DMA flags */
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

static int via97_attach(dev_info_t *);
static int via97_resume(dev_info_t *);
static int via97_detach(via97_devc_t *);
static int via97_suspend(via97_devc_t *);

static int via97_open(void *, int, unsigned *, caddr_t *);
static void via97_close(void *);
static int via97_start(void *);
static void via97_stop(void *);
static int via97_format(void *);
static int via97_channels(void *);
static int via97_rate(void *);
static uint64_t via97_count(void *);
static void via97_sync(void *, unsigned);
static uint_t via97_playahead(void *);

static uint16_t via97_read_ac97(void *, uint8_t);
static void via97_write_ac97(void *, uint8_t, uint16_t);
static int via97_alloc_port(via97_devc_t *, int);
static void via97_destroy(via97_devc_t *);
static void via97_hwinit(via97_devc_t *);

static audio_engine_ops_t via97_engine_ops = {
	AUDIO_ENGINE_VERSION,
	via97_open,
	via97_close,
	via97_start,
	via97_stop,
	via97_count,
	via97_format,
	via97_channels,
	via97_rate,
	via97_sync,
	NULL,
	NULL,
	via97_playahead
};

static uint16_t
via97_read_ac97(void *arg, uint8_t index)
{
	via97_devc_t *devc = arg;
	int tmp, addr, i;

	/* Index has only 7 bits */
	if (index > 0x7F)
		return (0xffff);

	addr = (index << 16) + CODEC_RD;
	OUTL(devc, devc->base + AC97CODEC, addr);
	drv_usecwait(100);

	/* Check AC CODEC access time out */
	for (i = 0; i < CODEC_TIMEOUT_COUNT; i++) {
		/* if send command over, break */
		if (INL(devc, devc->base + AC97CODEC) & STA_VALID)
			break;
		drv_usecwait(50);
	}
	if (i == CODEC_TIMEOUT_COUNT) {
		return (0xffff);
	}

	/* Check if Index still ours? If yes, return data, else return FAIL */
	tmp = INL(devc, devc->base + AC97CODEC);
	OUTB(devc, devc->base + AC97CODEC + 3, 0x02);
	if (((tmp & CODEC_INDEX) >> 16) == index) {
		return ((int)tmp & CODEC_DATA);
	}
	return (0xffff);
}

static void
via97_write_ac97(void *arg, uint8_t index, uint16_t data)
{
	via97_devc_t *devc = arg;
	int value = 0;
	unsigned int i = 0;

	value = (index << 16) + data;
	OUTL(devc, devc->base + AC97CODEC, value);
	drv_usecwait(100);

	/* Check AC CODEC access time out */
	for (i = 0; i < CODEC_TIMEOUT_COUNT; i++) {
		/* if send command over, break */
		if (!(INL(devc, devc->base + AC97CODEC) & IN_CMD))
			break;
		drv_usecwait(50);
	}
}

/*
 * Audio routines
 */

int
via97_open(void *arg, int flag, unsigned *nframesp, caddr_t *bufp)
{
	via97_portc_t	 *portc = arg;

	_NOTE(ARGUNUSED(flag));

	portc->count = 0;
	*nframesp = portc->nframes;
	*bufp = portc->buf_kaddr;

	return (0);
}

void
via97_close(void *arg)
{
	_NOTE(ARGUNUSED(arg));
}

int
via97_start(void *arg)
{
	via97_portc_t	*portc = arg;
	via97_devc_t	*devc = portc->devc;

	portc->pos = 0;

	OUTB(devc, portc->base + 0x01, 0x40); /* Stop */
	OUTL(devc, portc->base + 4, portc->sgd_paddr);
	/* Set autostart at EOL, stereo, 16 bits */
	OUTB(devc, portc->base + 0x02,
	    0x80 |	/* Set autostart at EOL */
	    0x20 |	/* 16 bits */
	    0x10);	/* Stereo */

	OUTB(devc, portc->base + 0x01, 0x80); /* Start */

	return (0);
}

void
via97_stop(void *arg)
{
	via97_portc_t	*portc = arg;
	via97_devc_t	*devc = portc->devc;

	OUTB(devc, portc->base + 0x01, 0x40); /* Stop */
}

int
via97_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

int
via97_channels(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (2);
}

int
via97_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}

void
via97_sync(void *arg, unsigned nframes)
{
	via97_portc_t *portc = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(portc->buf_dmah, 0, 0, portc->syncdir);
}

uint_t
via97_playahead(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	/*
	 * We see some situations where the default 1.5 fragments from
	 * the framework is not enough.  800-900 frame jitter is not
	 * uncommon.  Especially at startup.
	 */
	return (1024);
}

uint64_t
via97_count(void *arg)
{
	via97_portc_t	*portc = arg;
	via97_devc_t	*devc = portc->devc;
	uint32_t	pos;
	uint32_t	n;

	pos = INL(devc, portc->base + 0x0c) & 0xffffff;
	/* convert from bytes to 16-bit stereo frames */
	pos /= (sizeof (int16_t) * 2);

	if (pos >= portc->pos) {
		n = portc->nframes - (pos - portc->pos);
	} else {
		n = portc->pos - pos;
	}
	portc->pos = pos;
	portc->count += n;

	return (portc->count);
}


/* private implementation bits */

int
via97_alloc_port(via97_devc_t *devc, int num)
{
	via97_portc_t		*portc;
	size_t			len;
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			dir;
	unsigned		caps;
	audio_dev_t		*adev;
	uint32_t		*desc;

	adev = devc->adev;
	portc = kmem_zalloc(sizeof (*portc), KM_SLEEP);
	devc->portc[num] = portc;
	portc->devc = devc;
	portc->base = devc->base + num * 0x10;

	switch (num) {
	case VIA97_REC_SGD_NUM:
		portc->syncdir = DDI_DMA_SYNC_FORKERNEL;
		caps = ENGINE_INPUT_CAP;
		dir = DDI_DMA_READ;
		break;
	case VIA97_PLAY_SGD_NUM:
		portc->syncdir = DDI_DMA_SYNC_FORDEV;
		caps = ENGINE_OUTPUT_CAP;
		dir = DDI_DMA_WRITE;
		break;
	default:
		return (DDI_FAILURE);
	}

	/* Simplicity -- a single contiguous looping buffer */
	portc->nframes = 2048;
	portc->buf_size = portc->nframes * sizeof (int16_t) * 2;

	/* first allocate up space for SGD list */
	if (ddi_dma_alloc_handle(devc->dip, &dma_attr_sgd,
	    DDI_DMA_SLEEP, NULL, &portc->sgd_dmah) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate SGD handle");
		return (DDI_FAILURE);
	}

	/* a single SGD entry is only 8 bytes long */
	if (ddi_dma_mem_alloc(portc->sgd_dmah, 8, &dev_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &portc->sgd_kaddr,
	    &len, &portc->sgd_acch) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate SGD memory");
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(portc->sgd_dmah, NULL,
	    portc->sgd_kaddr, len, DDI_DMA_CONSISTENT | DDI_DMA_WRITE,
	    DDI_DMA_SLEEP, NULL, &cookie, &count) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed binding SGD DMA handle");
		return (DDI_FAILURE);
	}
	portc->sgd_paddr = cookie.dmac_address;

	/* now buffers */
	if (ddi_dma_alloc_handle(devc->dip, &dma_attr_buf, DDI_DMA_SLEEP, NULL,
	    &portc->buf_dmah) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate BUF handle");
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(portc->buf_dmah, portc->buf_size,
	    &buf_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &portc->buf_kaddr, &len, &portc->buf_acch) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate BUF memory");
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(portc->buf_dmah, NULL, portc->buf_kaddr,
	    len, DDI_DMA_CONSISTENT | dir, DDI_DMA_SLEEP, NULL, &cookie,
	    &count) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed binding BUF DMA handle");
		return (DDI_FAILURE);
	}
	portc->buf_paddr = cookie.dmac_address;

	/* now wire descriptor up -- we only use one (which has EOL set)! */
	desc = (void *)portc->sgd_kaddr;
	ddi_put32(portc->sgd_acch, desc++, portc->buf_paddr);
	ddi_put32(portc->sgd_acch, desc++, 0x80000000U | portc->buf_size);

	OUTL(devc, portc->base + 4, portc->sgd_paddr);
	(void) ddi_dma_sync(portc->sgd_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	portc->engine = audio_engine_alloc(&via97_engine_ops, caps);
	if (portc->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(portc->engine, portc);
	audio_dev_add_engine(adev, portc->engine);

	return (DDI_SUCCESS);
}

void
via97_destroy(via97_devc_t *devc)
{
	for (int i = 0; i < VIA97_NUM_PORTC; i++) {
		via97_portc_t *portc = devc->portc[i];
		if (!portc)
			continue;
		if (portc->engine) {
			audio_dev_remove_engine(devc->adev, portc->engine);
			audio_engine_free(portc->engine);
		}
		if (portc->sgd_paddr) {
			(void) ddi_dma_unbind_handle(portc->sgd_dmah);
		}
		if (portc->sgd_acch) {
			ddi_dma_mem_free(&portc->sgd_acch);
		}
		if (portc->sgd_dmah) {
			ddi_dma_free_handle(&portc->sgd_dmah);
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

void
via97_hwinit(via97_devc_t *devc)
{
	ddi_acc_handle_t	pcih = devc->pcih;
	uint32_t		tmp;

	/* Enable codec, etc */

	pci_config_put8(pcih, 0x41, 0xc0);
	drv_usecwait(10);
	tmp = pci_config_get8(pcih, 0x41);
	pci_config_put8(pcih, 0x41, tmp | 0x0c);
	drv_usecwait(10);

	/* disable game port/MIDI */
	pci_config_put8(pcih, 0x42, 0x00);
	/* disable FM io */
	pci_config_put8(pcih, 0x48, 0x00);

	/* Enable interrupt on FLAG and on EOL */
	tmp = INB(devc, devc->base + 0x22);
	OUTB(devc, devc->base + 0x22, tmp | 0x83);
}

int
via97_attach(dev_info_t *dip)
{
	uint16_t	pci_command, vendor, device;
	via97_devc_t	*devc;
	ddi_acc_handle_t pcih;

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

	vendor = pci_config_get16(pcih, PCI_CONF_VENID);
	device = pci_config_get16(pcih, PCI_CONF_DEVID);
	if (vendor != VIA_VENDOR_ID ||
	    device != VIA_82C686) {
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

	audio_dev_set_description(devc->adev, "VIA 82C686 Audio");

	via97_hwinit(devc);

	if ((via97_alloc_port(devc, VIA97_PLAY_SGD_NUM) != DDI_SUCCESS) ||
	    (via97_alloc_port(devc, VIA97_REC_SGD_NUM) != DDI_SUCCESS)) {
		goto error;
	}

	devc->ac97 = ac97_alloc(dip, via97_read_ac97, via97_write_ac97, devc);
	if (devc->ac97 == NULL) {
		audio_dev_warn(devc->adev, "failed to allocate ac97 handle");
		goto error;
	}

	if (ac97_init(devc->ac97, devc->adev) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "failed to init ac97");
		goto error;
	}

	if (audio_dev_register(devc->adev) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "unable to register with framework");
		goto error;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	via97_destroy(devc);
	return (DDI_FAILURE);
}

int
via97_resume(dev_info_t *dip)
{
	via97_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	via97_hwinit(devc);

	ac97_reset(devc->ac97);

	audio_dev_resume(devc->adev);
	return (DDI_SUCCESS);
}

int
via97_detach(via97_devc_t *devc)
{
	if (audio_dev_unregister(devc->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	via97_destroy(devc);
	return (DDI_SUCCESS);
}

int
via97_suspend(via97_devc_t *devc)
{
	audio_dev_suspend(devc->adev);
	return (DDI_SUCCESS);
}

static int via97_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int via97_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int via97_ddi_quiesce(dev_info_t *);

static struct dev_ops via97_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	via97_ddi_attach,	/* attach */
	via97_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	via97_ddi_quiesce,	/* quiesce */
};

static struct modldrv via97_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Via 82C686 Audio",		/* linkinfo */
	&via97_dev_ops,			/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &via97_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&via97_dev_ops, VIA97_NAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&via97_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&via97_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
via97_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (via97_attach(dip));

	case DDI_RESUME:
		return (via97_resume(dip));

	default:
		return (DDI_FAILURE);
	}
}

int
via97_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	via97_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		return (via97_detach(devc));

	case DDI_SUSPEND:
		return (via97_suspend(devc));

	default:
		return (DDI_FAILURE);
	}
}

int
via97_ddi_quiesce(dev_info_t *dip)
{
	via97_devc_t	*devc;

	devc = ddi_get_driver_private(dip);

	/*
	 * Turn off the hardware
	 */
	OUTB(devc, devc->base + 0x01, 0x40);
	OUTB(devc, devc->base + 0x11, 0x40);
	OUTB(devc, devc->base + 0x02, 0);
	OUTB(devc, devc->base + 0x12, 0);
	OUTL(devc, devc->base + 0x04, 0);
	OUTL(devc, devc->base + 0x14, 0);
	OUTL(devc, devc->base + 0x22, 0);
	return (DDI_SUCCESS);
}
