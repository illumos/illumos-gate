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

static int via97_open(void *, int, unsigned *, unsigned *, caddr_t *);
static void via97_close(void *);
static int via97_start(void *);
static void via97_stop(void *);
static int via97_format(void *);
static int via97_channels(void *);
static int via97_rate(void *);
static uint64_t via97_count(void *);
static void via97_sync(void *, unsigned);
static size_t via97_qlen(void *);

static uint16_t via97_read_ac97(void *, uint8_t);
static void via97_write_ac97(void *, uint8_t, uint16_t);
static int via97_alloc_port(via97_devc_t *, int);
static void via97_start_port(via97_portc_t *);
static void via97_stop_port(via97_portc_t *);
static void via97_update_port(via97_portc_t *);
static void via97_reset_port(via97_portc_t *);
static void via97_destroy(via97_devc_t *);
static int via97_setup_intrs(via97_devc_t *);
static void via97_hwinit(via97_devc_t *);
static uint_t via97_intr(caddr_t, caddr_t);

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
	via97_qlen
};

static uint16_t
via97_read_ac97(void *arg, uint8_t index)
{
	via97_devc_t *devc = arg;
	int tmp, addr, i;

	/* Index has only 7 bits */
	if (index > 0x7F)
		return (0xffff);

	mutex_enter(&devc->low_mutex);
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
		mutex_exit(&devc->low_mutex);
		return (0xffff);
	}

	/* Check if Index still ours? If yes, return data, else return FAIL */
	tmp = INL(devc, devc->base + AC97CODEC);
	OUTB(devc, devc->base + AC97CODEC + 3, 0x02);
	if (((tmp & CODEC_INDEX) >> 16) == index) {
		mutex_exit(&devc->low_mutex);
		return ((int)tmp & CODEC_DATA);
	}
	mutex_exit(&devc->low_mutex);
	return (0xffff);
}

static void
via97_write_ac97(void *arg, uint8_t index, uint16_t data)
{
	via97_devc_t *devc = arg;
	int value = 0;
	unsigned int i = 0;

	mutex_enter(&devc->low_mutex);
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
	mutex_exit(&devc->low_mutex);
}

static uint_t
via97_recintr(via97_devc_t *devc)
{
	int status;

	status = INB(devc, devc->base + 0x10);

	if (!(status & 0x01)) /* No interrupt */
		return (B_FALSE);

	audio_engine_produce(devc->portc[VIA97_REC_SGD_NUM]->engine);

	OUTB(devc, devc->base + 0x10, status | 0x01); /* Ack */
	return (B_TRUE);
}

static uint_t
via97_playintr(via97_devc_t *devc)
{
	int status;

	status = INB(devc, devc->base + 0x00);

	if (!(status & 0x01)) /* No interrupt */
		return (B_FALSE);

	audio_engine_consume(devc->portc[VIA97_PLAY_SGD_NUM]->engine);

	OUTB(devc, devc->base + 0x00, status | 0x01); /* Ack */
	return (B_TRUE);
}

static uint_t
via97_intr(caddr_t argp, caddr_t nocare)
{
	via97_devc_t	*devc = (void *)argp;

	_NOTE(ARGUNUSED(nocare));

	if (devc->suspended) {
		return (DDI_INTR_UNCLAIMED);
	}

	if (!via97_recintr(devc) && !via97_playintr(devc)) {
		return (DDI_INTR_UNCLAIMED);
	}

	if (devc->ksp) {
		VIA97_KIOP(devc)->intrs[KSTAT_INTR_HARD]++;
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Audio routines
 */

int
via97_open(void *arg, int flag,
    unsigned *fragfrp, unsigned *nfragsp, caddr_t *bufp)
{
	via97_portc_t	 *portc = arg;
	via97_devc_t	 *devc = portc->devc;

	_NOTE(ARGUNUSED(flag));

	portc->started = B_FALSE;
	portc->count = 0;
	*fragfrp = portc->fragfr;
	*nfragsp = VIA97_NUM_SGD;
	*bufp = portc->buf_kaddr;

	mutex_enter(&devc->mutex);
	via97_reset_port(portc);
	mutex_exit(&devc->mutex);

	return (0);
}

void
via97_close(void *arg)
{
	via97_portc_t	 *portc = arg;
	via97_devc_t	 *devc = portc->devc;

	mutex_enter(&devc->mutex);
	via97_stop_port(portc);
	portc->started = B_FALSE;
	mutex_exit(&devc->mutex);
}

int
via97_start(void *arg)
{
	via97_portc_t	*portc = arg;
	via97_devc_t	*devc = portc->devc;

	mutex_enter(&devc->mutex);
	if (!portc->started) {
		via97_start_port(portc);
		portc->started = B_TRUE;
	}
	mutex_exit(&devc->mutex);
	return (0);
}

void
via97_stop(void *arg)
{
	via97_portc_t	*portc = arg;
	via97_devc_t	*devc = portc->devc;

	mutex_enter(&devc->mutex);
	if (portc->started) {
		via97_stop_port(portc);
		portc->started = B_FALSE;
	}
	mutex_exit(&devc->mutex);
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

size_t
via97_qlen(void *arg)
{
	_NOTE(ARGUNUSED(arg));
	return (0);
}

uint64_t
via97_count(void *arg)
{
	via97_portc_t	*portc = arg;
	via97_devc_t	*devc = portc->devc;
	uint64_t	val;

	mutex_enter(&devc->mutex);
	via97_update_port(portc);
	/*
	 * The residual is in bytes.  We have to convert to frames,
	 * and then subtract it from the fragment size to get the
	 * number of frames processed.  Note that we have 16 bit
	 * stereo frames.
	 */
	val = portc->count +
	    (portc->fragfr - (portc->resid / (2 * 2)));
	mutex_exit(&devc->mutex);

	return (val);
}


/* private implementation bits */

void
via97_start_port(via97_portc_t *portc)
{
	via97_devc_t	*devc = portc->devc;

	ASSERT(mutex_owned(&devc->mutex));

	if (devc->suspended)
		return;
	OUTB(devc, portc->base + 0x01, 0x80); /* Start */
}

void
via97_stop_port(via97_portc_t *portc)
{
	via97_devc_t	*devc = portc->devc;

	if (devc->suspended)
		return;

	OUTB(devc, portc->base + 0x01, 0x40); /* Stop */
}

void
via97_update_port(via97_portc_t *portc)
{
/*
 * Unfortunately the controller seems to raise interrupt about 32 bytes before
 * the DMA pointer moves to a new fragment. This means that the bytes value
 * returned will be bogus during few samples before
 * the pointer wraps back to the beginning of buffer.
 */
	via97_devc_t	*devc = portc->devc;
	uint32_t	frag, resid;
	uint32_t	n;

	ASSERT(mutex_owned(&devc->mutex));
	if (devc->suspended) {
		portc->cur_frag = 0;
		portc->resid = portc->fragsz;
		n = 0;
	} else {
		resid = INL(devc, portc->base + 0x0c) & 0xffffff;
		resid = portc->fragsz - resid;

		frag =
		    ((INL(devc, portc->base + 0x04) - portc->sgd_paddr) / 8) -
		    1;

		portc->resid = resid;

		if (frag >= portc->cur_frag) {
			n = frag - portc->cur_frag;
		} else {
			n = frag + VIA97_NUM_SGD - portc->cur_frag;
		}
		portc->count += (n * portc->fragfr);
		portc->cur_frag = frag;
	}
}

void
via97_reset_port(via97_portc_t *portc)
{
	via97_devc_t	*devc = portc->devc;

	portc->cur_frag = 0;
	portc->resid = portc->fragsz;

	if (devc->suspended)
		return;

	OUTB(devc, portc->base + 0x01, 0x40); /* Stop */
	OUTL(devc, portc->base + 4, portc->sgd_paddr);
	/* Set autostart at EOL, interrupt on FLAG, stereo, 16 bits */
	OUTB(devc, portc->base + 0x02,
	    0x81 |	/* Set autostart at EOL, interrupt on FLAG */
	    0x20 |	/* 16 bits */
	    0x10);	/* Stereo */
}

int
via97_alloc_port(via97_devc_t *devc, int num)
{
	via97_portc_t		*portc;
	size_t			len;
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			dir;
	char			*prop;
	unsigned		caps;
	audio_dev_t		*adev;
	uint32_t		*desc;
	uint32_t		paddr;

	adev = devc->adev;
	portc = kmem_zalloc(sizeof (*portc), KM_SLEEP);
	devc->portc[num] = portc;
	portc->devc = devc;
	portc->started = B_FALSE;
	portc->base = devc->base + num * 0x10;

	switch (num) {
	case VIA97_REC_SGD_NUM:
		prop = "record-interrupts";
		portc->syncdir = DDI_DMA_SYNC_FORKERNEL;
		caps = ENGINE_INPUT_CAP;
		dir = DDI_DMA_READ;
		break;
	case VIA97_PLAY_SGD_NUM:
		prop = "play-interrupts";
		portc->syncdir = DDI_DMA_SYNC_FORDEV;
		caps = ENGINE_OUTPUT_CAP;
		dir = DDI_DMA_WRITE;
		break;
	default:
		return (DDI_FAILURE);
	}

	/* figure out fragment configuration */
	portc->intrs = ddi_prop_get_int(DDI_DEV_T_ANY, devc->dip,
	    DDI_PROP_DONTPASS, prop, VIA97_INTRS);

	/* make sure the values are good */
	if (portc->intrs < VIA97_MIN_INTRS) {
		audio_dev_warn(adev, "%s too low, %d, reset to %d",
		    prop, portc->intrs, VIA97_INTRS);
		portc->intrs = VIA97_INTRS;
	} else if (portc->intrs > VIA97_MAX_INTRS) {
		audio_dev_warn(adev, "%s too high, %d, reset to %d",
		    prop, portc->intrs, VIA97_INTRS);
		portc->intrs = VIA97_INTRS;
	}

	portc->fragfr = 48000 / portc->intrs;
	portc->fragsz = portc->fragfr * 2 * 2; /* 16 bit stereo frames */
	portc->buf_size = portc->fragsz * VIA97_NUM_SGD;

	/* first allocate up space for SGD list */
	if (ddi_dma_alloc_handle(devc->dip, &dma_attr_sgd,
	    DDI_DMA_SLEEP, NULL, &portc->sgd_dmah) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate SGD handle");
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(portc->sgd_dmah,
	    VIA97_NUM_SGD * 2 *sizeof (uint32_t), &dev_attr,
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

	/* now wire descriptors up */
	desc = (void *)portc->sgd_kaddr;
	paddr = portc->buf_paddr;
	for (int i = 0; i < VIA97_NUM_SGD; i++) {
		uint32_t	flags;

		flags = 0x40000000 | portc->fragsz;

		if (i == (VIA97_NUM_SGD - 1)) {
			flags |= 0x80000000; /* EOL */
		}

		ddi_put32(portc->sgd_acch, desc++, paddr);
		ddi_put32(portc->sgd_acch, desc++, flags);
		paddr += portc->fragsz;
	}

	OUTL(devc, portc->base + 4, portc->sgd_paddr);
	ddi_dma_sync(portc->sgd_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	portc->engine = audio_engine_alloc(&via97_engine_ops, caps);
	if (portc->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(portc->engine, portc);
	audio_dev_add_engine(adev, portc->engine);

	return (DDI_SUCCESS);
}

int
via97_setup_intrs(via97_devc_t *devc)
{
	uint_t			ipri;
	int			actual;
	int			rv;
	ddi_intr_handle_t	ih[1];

	rv = ddi_intr_alloc(devc->dip, ih, DDI_INTR_TYPE_FIXED,
	    0, 1, &actual, DDI_INTR_ALLOC_STRICT);
	if ((rv != DDI_SUCCESS) || (actual != 1)) {
		audio_dev_warn(devc->adev,
		    "Can't alloc interrupt handle (rv %d actual %d)",
		    rv, actual);
		return (DDI_FAILURE);
	}

	if (ddi_intr_get_pri(ih[0], &ipri) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "Can't get interrupt priority");
		(void) ddi_intr_free(ih[0]);
		return (DDI_FAILURE);
	}

	if (ddi_intr_add_handler(ih[0], via97_intr, devc, NULL) !=
	    DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "Can't add interrupt handler");
		(void) ddi_intr_free(ih[0]);
		return (DDI_FAILURE);
	}

	devc->ih = ih[0];
	mutex_init(&devc->mutex, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));
	mutex_init(&devc->low_mutex, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));
	return (DDI_SUCCESS);
}

void
via97_destroy(via97_devc_t *devc)
{
	if (devc->ih != NULL) {
		(void) ddi_intr_disable(devc->ih);
		(void) ddi_intr_remove_handler(devc->ih);
		(void) ddi_intr_free(devc->ih);
		mutex_destroy(&devc->mutex);
		mutex_destroy(&devc->low_mutex);
	}

	if (devc->ksp) {
		kstat_delete(devc->ksp);
	}

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

	if (via97_setup_intrs(devc) != DDI_SUCCESS) {
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

	/* set up kernel statistics */
	if ((devc->ksp = kstat_create(VIA97_NAME, ddi_get_instance(dip),
	    VIA97_NAME, "controller", KSTAT_TYPE_INTR, 1,
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(devc->ksp);
	}

	if (audio_dev_register(devc->adev) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "unable to register with framework");
		goto error;
	}

	(void) ddi_intr_enable(devc->ih);
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

	/* allow ac97 operations again */
	ac97_resume(devc->ac97);

	mutex_enter(&devc->mutex);
	devc->suspended = B_FALSE;
	for (int i = 0; i < VIA97_NUM_PORTC; i++) {

		via97_portc_t *portc = devc->portc[i];

		if (portc->engine != NULL)
			audio_engine_reset(portc->engine);

		/* reset the port */
		via97_reset_port(portc);

		if (portc->started) {
			via97_start_port(portc);
		} else {
			via97_stop_port(portc);
		}
	}
	mutex_exit(&devc->mutex);
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
	ac97_suspend(devc->ac97);

	mutex_enter(&devc->mutex);
	for (int i = 0; i < VIA97_NUM_PORTC; i++) {

		via97_portc_t *portc = devc->portc[i];
		via97_stop_port(portc);
	}
	devc->suspended = B_TRUE;
	mutex_exit(&devc->mutex);
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

	for (int i = 0; i < VIA97_NUM_PORTC; i++) {

		via97_portc_t *portc = devc->portc[i];
		via97_stop_port(portc);
	}

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
