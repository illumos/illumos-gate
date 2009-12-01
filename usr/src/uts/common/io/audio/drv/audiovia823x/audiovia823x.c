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
 * Purpose: Driver for the VIA8233/8235 AC97 audio controller
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

#include "audiovia823x.h"

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
	0x0001fffe,		/* DMA counter register */
	4,			/* DMA address alignment */
	0x3c,			/* DMA burstsizes */
	4,			/* min effective DMA size */
	0x0001ffff,		/* max DMA xfer size */
	0x0001ffff,		/* segment boundary */
	1,			/* s/g length */
	4,			/* granularity of device */
	0			/* Bus specific DMA flags */
};

static int auvia_attach(dev_info_t *);
static int auvia_resume(dev_info_t *);
static int auvia_detach(auvia_devc_t *);
static int auvia_suspend(auvia_devc_t *);

static int auvia_open(void *, int, unsigned *, unsigned *, caddr_t *);
static void auvia_close(void *);
static int auvia_start(void *);
static void auvia_stop(void *);
static int auvia_format(void *);
static int auvia_channels(void *);
static int auvia_rate(void *);
static uint64_t auvia_count(void *);
static void auvia_sync(void *, unsigned);

static uint16_t auvia_read_ac97(void *, uint8_t);
static void auvia_write_ac97(void *, uint8_t, uint16_t);
static int auvia_alloc_port(auvia_devc_t *, int);
static void auvia_start_port(auvia_portc_t *);
static void auvia_stop_port(auvia_portc_t *);
static void auvia_update_port(auvia_portc_t *);
static void auvia_reset_input(auvia_portc_t *);
static void auvia_reset_output(auvia_portc_t *);
static void auvia_destroy(auvia_devc_t *);
static int auvia_setup_intrs(auvia_devc_t *);
static void auvia_hwinit(auvia_devc_t *);
static uint_t auvia_intr(caddr_t, caddr_t);

static audio_engine_ops_t auvia_engine_ops = {
	AUDIO_ENGINE_VERSION,
	auvia_open,
	auvia_close,
	auvia_start,
	auvia_stop,
	auvia_count,
	auvia_format,
	auvia_channels,
	auvia_rate,
	auvia_sync,
	NULL,
	NULL,
	NULL,
};

static uint16_t
auvia_read_ac97(void *arg, uint8_t index)
{
	auvia_devc_t *devc = arg;
	uint32_t val = 0;
	int i;

	mutex_enter(&devc->low_mutex);

	val = ((uint32_t)index << 16) | CODEC_RD;
	OUTL(devc, devc->base + REG_CODEC, val);
	drv_usecwait(100);

	/* Check AC CODEC access time out */
	for (i = 0; i < CODEC_TIMEOUT_COUNT; i++) {

		/* if send command over, break */
		if (INL(devc, devc->base + REG_CODEC) & CODEC_STA_VALID)
			break;
		drv_usecwait(50);
	}

	if (i == CODEC_TIMEOUT_COUNT) {
		goto failed;
	}

	/* Check if Index still ours? If yes, return data, else return FAIL */
	val = INL(devc, devc->base + REG_CODEC);
	OUTB(devc, devc->base + REG_CODEC + 3, 0x02);
	if (((val & CODEC_INDEX) >> 16) == index) {
		mutex_exit(&devc->low_mutex);
		return (val & CODEC_DATA);
	}

failed:
	mutex_exit(&devc->low_mutex);
	return (0xffff);
}

static void
auvia_write_ac97(void *arg, uint8_t index, uint16_t data)
{
	auvia_devc_t *devc = arg;
	uint32_t val = 0;
	int i = 0;

	mutex_enter(&devc->low_mutex);

	val = ((uint32_t)index << 16) | data | CODEC_WR;
	OUTL(devc, devc->base + REG_CODEC, val);
	drv_usecwait(100);

	/* Check AC CODEC access time out */
	for (i = 0; i < CODEC_TIMEOUT_COUNT; i++) {
		/* if send command over, break */
		if (!(INL(devc, devc->base + REG_CODEC) & CODEC_IN_CMD))
			break;
		drv_usecwait(50);
	}

	mutex_exit(&devc->low_mutex);
}

static uint_t
auvia_intr(caddr_t argp, caddr_t nocare)
{
	auvia_devc_t	*devc = (void *)argp;
	auvia_portc_t	*portc;
	uint8_t		status;
	unsigned	intrs = 0;
	boolean_t	claimed = B_FALSE;

	_NOTE(ARGUNUSED(nocare));

	mutex_enter(&devc->mutex);
	if (devc->suspended) {
		mutex_exit(&devc->mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	for (int i = 0; i < AUVIA_NUM_PORTC; i++) {

		portc = devc->portc[i];

		status = INB(devc, portc->base + OFF_STATUS);
		if ((status & STATUS_INTR) == 0) {
			/* clear any other interrupts */
			continue;
		}

		/*
		 * NB: The old code did some goofy things to update
		 * the last valid SGD.  However, since we don't ever
		 * reach the last valid SGD (because we loop first), I
		 * don't believe we need to do that.  It would appear
		 * that NetBSD does the same.
		 */
		/* port interrupt */
		if (portc->started) {
			intrs |= (1U << i);
		}
		/* let the chip know we are acking the interrupt */
		OUTB(devc, portc->base + OFF_STATUS, status);

		claimed = B_TRUE;
	}

	mutex_exit(&devc->mutex);

	if (!claimed) {
		return (DDI_INTR_UNCLAIMED);
	}

	if (intrs & (1U << AUVIA_PLAY_SGD_NUM)) {
		audio_engine_consume(devc->portc[AUVIA_PLAY_SGD_NUM]->engine);
	}
	if (intrs & (1U << AUVIA_REC_SGD_NUM)) {
		audio_engine_produce(devc->portc[AUVIA_REC_SGD_NUM]->engine);
	}
	if (devc->ksp) {
		AUVIA_KIOP(devc)->intrs[KSTAT_INTR_HARD]++;
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Audio routines
 */

int
auvia_open(void *arg, int flag,
    unsigned *fragfrp, unsigned *nfragsp, caddr_t *bufp)
{
	auvia_portc_t	 *portc = arg;
	auvia_devc_t	 *devc = portc->devc;

	_NOTE(ARGUNUSED(flag));

	portc->started = B_FALSE;
	portc->count = 0;
	*fragfrp = portc->fragfr;
	*nfragsp = AUVIA_NUM_SGD;
	*bufp = portc->buf_kaddr;

	mutex_enter(&devc->mutex);
	portc->reset(portc);
	mutex_exit(&devc->mutex);

	return (0);
}

void
auvia_close(void *arg)
{
	auvia_portc_t	 *portc = arg;
	auvia_devc_t	 *devc = portc->devc;

	mutex_enter(&devc->mutex);
	auvia_stop_port(portc);
	portc->started = B_FALSE;
	mutex_exit(&devc->mutex);
}

int
auvia_start(void *arg)
{
	auvia_portc_t	*portc = arg;
	auvia_devc_t	*devc = portc->devc;

	mutex_enter(&devc->mutex);
	if (!portc->started) {
		auvia_start_port(portc);
		portc->started = B_TRUE;
	}
	mutex_exit(&devc->mutex);
	return (0);
}

void
auvia_stop(void *arg)
{
	auvia_portc_t	*portc = arg;
	auvia_devc_t	*devc = portc->devc;

	mutex_enter(&devc->mutex);
	if (portc->started) {
		auvia_stop_port(portc);
		portc->started = B_FALSE;
	}
	mutex_exit(&devc->mutex);
}

int
auvia_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

int
auvia_channels(void *arg)
{
	auvia_portc_t	*portc = arg;

	return (portc->nchan);
}

int
auvia_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}

void
auvia_sync(void *arg, unsigned nframes)
{
	auvia_portc_t *portc = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(portc->buf_dmah, 0, 0, portc->syncdir);
}

uint64_t
auvia_count(void *arg)
{
	auvia_portc_t	*portc = arg;
	auvia_devc_t	*devc = portc->devc;
	uint64_t	val;

	mutex_enter(&devc->mutex);
	auvia_update_port(portc);
	/*
	 * The residual is in bytes.  We have to convert to frames,
	 * and then subtract it from the fragment size to get the
	 * number of frames processed.  It is somewhat unfortunate thta
	 * this (the division) has to happen under the lock.  If we
	 * restricted ourself to stereo out, this would be a simple
	 * shift.
	 */
	val = portc->count +
	    (portc->fragfr - (portc->resid / (portc->nchan * 2)));
	mutex_exit(&devc->mutex);

	return (val);
}


/* private implementation bits */

void
auvia_start_port(auvia_portc_t *portc)
{
	auvia_devc_t	*devc = portc->devc;

	ASSERT(mutex_owned(&devc->mutex));

	if (devc->suspended)
		return;

	/*
	 * Start with autoinit and SGD flag
	 * interrupts enabled.
	 */
	OUTB(devc, portc->base + OFF_CTRL,
	    CTRL_START | CTRL_AUTOSTART | CTRL_FLAG);
}

void
auvia_stop_port(auvia_portc_t *portc)
{
	auvia_devc_t	*devc = portc->devc;

	if (devc->suspended)
		return;

	OUTB(devc, portc->base + OFF_CTRL, CTRL_TERMINATE);
}

void
auvia_update_port(auvia_portc_t *portc)
{
	auvia_devc_t	*devc = portc->devc;
	uint32_t	frag;
	uint32_t	n;

	ASSERT(mutex_owned(&devc->mutex));
	if (devc->suspended) {
		portc->cur_frag = 0;
		portc->resid = portc->fragsz;
		n = 0;
	} else {
		frag = INL(devc, portc->base + OFF_COUNT);
		portc->resid = (frag & 0xffffff);
		frag >>= 24;
		frag &= 0xff;

		if (frag >= portc->cur_frag) {
			n = frag - portc->cur_frag;
		} else {
			n = frag + AUVIA_NUM_SGD - portc->cur_frag;
		}
		portc->count += (n * portc->fragfr);
		portc->cur_frag = frag;
	}
}

void
auvia_reset_output(auvia_portc_t *portc)
{
	auvia_devc_t	*devc = portc->devc;
	uint32_t	cmap;

	portc->cur_frag = 0;
	portc->resid = portc->fragsz;

	if (devc->suspended)
		return;

	OUTB(devc, portc->base + OFF_CTRL, CTRL_TERMINATE);	/* Stop */
	OUTL(devc, portc->base + OFF_DMA, portc->sgd_paddr);

	OUTB(devc, portc->base + OFF_PLAYFMT,
	    PLAYFMT_16BIT | (portc->nchan << 4));

	/* Select channel assignment - not valid for 8233A */
	if (devc->chip_type != CHIP_8233A) {
		/*
		 * Undocumented slot mapping table:
		 *
		 * slot 3 = 1 (left)
		 * slot 4 = 2 (right)
		 * slot 6 = 5 (center)
		 * slot 9 = 6 (lfe)
		 * slot 7 = 3 (left rear)
		 * slot 8 = 4 (right rear)
		 */
		switch (portc->nchan) {
		case 1:
			cmap = (1 << 0) | (1 << 4);
			break;
		case 2:
			cmap = (1 << 0) | (2 << 4);
			break;
		case 4:
			cmap = (1 << 0) | (2 << 4) | (3 << 8) | (4 << 12);
			break;
		case 6:
			cmap = (1 << 0) | (2 << 4) |
			    (5 << 8) | (6 << 12) | (3 << 16) | (4 << 20);
			break;
		default:
			cmap = 0;
			break;
		}
		OUTL(devc, portc->base + OFF_CHANNELS, cmap | 0xFF000000U);
	}
}

static void
auvia_reset_input(auvia_portc_t *portc)
{
	auvia_devc_t	*devc = portc->devc;
	uint32_t	fmt;

	portc->cur_frag = 0;
	portc->resid = portc->fragsz;

	if (devc->suspended)
		return;

	OUTB(devc, portc->base + OFF_CTRL, CTRL_TERMINATE);	/* Stop */
	OUTL(devc, portc->base + OFF_DMA, portc->sgd_paddr);

	fmt = RECFMT_STEREO | RECFMT_16BIT;

	if (devc->chip_type != CHIP_8233A) {
		fmt |= RECFMT_48K;
	}
	fmt |= (0xffU << 24);
	OUTB(devc, portc->base + OFF_RECFIFO, RECFIFO_ENABLE);
	OUTL(devc, portc->base + OFF_RECFMT, fmt);
}

int
auvia_alloc_port(auvia_devc_t *devc, int num)
{
	auvia_portc_t		*portc;
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

	switch (num) {
	case AUVIA_REC_SGD_NUM:
		prop = "record-interrupts";
		portc->base = devc->base + REG_RECBASE;
		portc->syncdir = DDI_DMA_SYNC_FORKERNEL;
		portc->nchan = 2;
		portc->reset = auvia_reset_input;
		caps = ENGINE_INPUT_CAP;
		dir = DDI_DMA_READ;
		break;
	case AUVIA_PLAY_SGD_NUM:
		prop = "play-interrupts";
		portc->base = devc->base + REG_PLAYBASE;
		portc->syncdir = DDI_DMA_SYNC_FORDEV;
		portc->nchan = 6;
		portc->reset = auvia_reset_output;
		caps = ENGINE_OUTPUT_CAP;
		dir = DDI_DMA_WRITE;
		break;
	default:
		return (DDI_FAILURE);
	}

	/* make sure port is shut down */
	OUTB(portc->devc, portc->base + OFF_CTRL, CTRL_TERMINATE);

	/* figure out fragment configuration */
	portc->intrs = ddi_prop_get_int(DDI_DEV_T_ANY, devc->dip,
	    DDI_PROP_DONTPASS, prop, AUVIA_INTRS);

	/* make sure the values are good */
	if (portc->intrs < AUVIA_MIN_INTRS) {
		audio_dev_warn(adev, "%s too low, %d, reset to %d",
		    prop, portc->intrs, AUVIA_INTRS);
		portc->intrs = AUVIA_INTRS;
	} else if (portc->intrs > AUVIA_MAX_INTRS) {
		audio_dev_warn(adev, "%s too high, %d, reset to %d",
		    prop, portc->intrs, AUVIA_INTRS);
		portc->intrs = AUVIA_INTRS;
	}

	portc->fragfr = 48000 / portc->intrs;
	portc->fragsz = portc->fragfr * portc->nchan * 2;
	portc->buf_size = portc->fragsz * AUVIA_NUM_SGD;

	/* first allocate up space for SGD list */
	if (ddi_dma_alloc_handle(devc->dip, &dma_attr_sgd,
	    DDI_DMA_SLEEP, NULL, &portc->sgd_dmah) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to allocate SGD handle");
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(portc->sgd_dmah,
	    AUVIA_NUM_SGD * 2 * sizeof (uint32_t), &dev_attr,
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
	for (int i = 0; i < AUVIA_NUM_SGD; i++) {
		uint32_t	flags;

		flags = AUVIA_SGD_FLAG | portc->fragsz;

		if (i == (AUVIA_NUM_SGD - 1)) {
			flags |= AUVIA_SGD_EOL;
		}
		ddi_put32(portc->sgd_acch, desc++, paddr);
		ddi_put32(portc->sgd_acch, desc++, flags);
		paddr += portc->fragsz;
	}

	(void) ddi_dma_sync(portc->sgd_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	portc->engine = audio_engine_alloc(&auvia_engine_ops, caps);
	if (portc->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(portc->engine, portc);
	audio_dev_add_engine(adev, portc->engine);

	return (DDI_SUCCESS);
}

int
auvia_setup_intrs(auvia_devc_t *devc)
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

	if (ddi_intr_add_handler(ih[0], auvia_intr, devc, NULL) !=
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
auvia_destroy(auvia_devc_t *devc)
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

	for (int i = 0; i < AUVIA_NUM_PORTC; i++) {
		auvia_portc_t *portc = devc->portc[i];
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
auvia_hwinit(auvia_devc_t *devc)
{
	ddi_acc_handle_t	pcih = devc->pcih;
	uint32_t		val;

	val = pci_config_get32(pcih, AUVIA_PCICFG);
	/* we want to disable all legacy */
	val &= ~AUVIA_PCICFG_LEGACY;
	val &= ~(AUVIA_PCICFG_FMEN | AUVIA_PCICFG_SBEN);

	/* enable AC'97 link and clear the reset bit */
	val |= (AUVIA_PCICFG_ACLINKEN | AUVIA_PCICFG_NRST);
	/* disable SRC (we won't use it) */
	val &= ~AUVIA_PCICFG_SRCEN;
	/* enable the SGD engines */
	val |= AUVIA_PCICFG_SGDEN;

	pci_config_put32(pcih, AUVIA_PCICFG, val);

	drv_usecwait(10);
}

int
auvia_attach(dev_info_t *dip)
{
	uint8_t 	pci_revision;
	uint16_t	pci_command, vendor, device;
	auvia_devc_t	*devc;
	ddi_acc_handle_t pcih;
	const char	*version;

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
	if ((vendor != VIA_VENDOR_ID) || (device != VIA_8233_ID &&
	    device != VIA_8233A_ID)) {
		audio_dev_warn(devc->adev, "Hardware not recognized "
		    "(vendor=%x, dev=%x)", vendor, device);
		goto error;
	}

	devc->chip_type = CHIP_8233;
	devc->chip_name = "VIA VT8233";
	version = "8233";

	pci_revision = pci_config_get8(pcih, PCI_CONF_REVID);

	if (pci_revision == 0x50) {
		devc->chip_name = "VIA VT8235";
		version = "8235";
	}

	if (pci_revision == 0x60) {
		devc->chip_name = "VIA VT8237";
		version = "8237";
	}

	if ((device == VIA_8233A_ID) ||
	    (device == VIA_8233_ID && pci_revision == 0x40)) {
		devc->chip_type = CHIP_8233A;
		devc->chip_name = "VIA VT8233A";
		version = "8233A";
	}
	audio_dev_set_description(devc->adev, devc->chip_name);
	audio_dev_set_version(devc->adev, version);

	pci_command = pci_config_get16(pcih, PCI_CONF_COMM);
	pci_command |= PCI_COMM_ME | PCI_COMM_IO | PCI_COMM_MAE;
	pci_config_put16(pcih, PCI_CONF_COMM, pci_command);

	if ((ddi_regs_map_setup(dip, 1, &devc->base, 0, 0, &dev_attr,
	    &devc->regsh)) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "failed to map registers");
		goto error;
	}

	auvia_hwinit(devc);

	if ((auvia_alloc_port(devc, AUVIA_PLAY_SGD_NUM) != DDI_SUCCESS) ||
	    (auvia_alloc_port(devc, AUVIA_REC_SGD_NUM) != DDI_SUCCESS)) {
		goto error;
	}

	if (auvia_setup_intrs(devc) != DDI_SUCCESS) {
		goto error;
	}

	devc->ac97 = ac97_alloc(dip, auvia_read_ac97, auvia_write_ac97, devc);
	if (devc->ac97 == NULL) {
		audio_dev_warn(devc->adev, "failed to allocate ac97 handle");
		goto error;
	}

	if (ac97_init(devc->ac97, devc->adev) != DDI_SUCCESS) {
		audio_dev_warn(devc->adev, "failed to init ac97");
		goto error;
	}

	/* set up kernel statistics */
	if ((devc->ksp = kstat_create(AUVIA_NAME, ddi_get_instance(dip),
	    AUVIA_NAME, "controller", KSTAT_TYPE_INTR, 1,
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
	auvia_destroy(devc);
	return (DDI_FAILURE);
}

int
auvia_resume(dev_info_t *dip)
{
	auvia_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	auvia_hwinit(devc);

	/* allow ac97 operations again */
	ac97_resume(devc->ac97);

	mutex_enter(&devc->mutex);
	devc->suspended = B_TRUE;
	for (int i = 0; i < AUVIA_NUM_PORTC; i++) {

		auvia_portc_t *portc = devc->portc[i];

		if (portc->engine != NULL)
			audio_engine_reset(portc->engine);

		/* reset the port */
		portc->reset(portc);

		if (portc->started) {
			auvia_start_port(portc);
		} else {
			auvia_stop_port(portc);
		}
	}
	mutex_exit(&devc->mutex);
	return (DDI_SUCCESS);
}


int
auvia_detach(auvia_devc_t *devc)
{
	if (audio_dev_unregister(devc->adev) != DDI_SUCCESS)
		return (DDI_FAILURE);

	auvia_destroy(devc);
	return (DDI_SUCCESS);
}

int
auvia_suspend(auvia_devc_t *devc)
{
	ac97_suspend(devc->ac97);

	mutex_enter(&devc->mutex);
	for (int i = 0; i < AUVIA_NUM_PORTC; i++) {

		auvia_portc_t *portc = devc->portc[i];
		auvia_stop_port(portc);
	}
	devc->suspended = B_TRUE;
	mutex_exit(&devc->mutex);
	return (DDI_SUCCESS);
}

static int auvia_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int auvia_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int auvia_ddi_quiesce(dev_info_t *);

static struct dev_ops auvia_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	auvia_ddi_attach,	/* attach */
	auvia_ddi_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	auvia_ddi_quiesce,	/* quiesce */
};

static struct modldrv auvia_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Via 823x Audio",		/* linkinfo */
	&auvia_dev_ops,			/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &auvia_modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	audio_init_ops(&auvia_dev_ops, AUVIA_NAME);
	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&auvia_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		audio_fini_ops(&auvia_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
auvia_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (auvia_attach(dip));

	case DDI_RESUME:
		return (auvia_resume(dip));

	default:
		return (DDI_FAILURE);
	}
}

int
auvia_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	auvia_devc_t *devc;

	devc = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		return (auvia_detach(devc));

	case DDI_SUSPEND:
		return (auvia_suspend(devc));

	default:
		return (DDI_FAILURE);
	}
}

int
auvia_ddi_quiesce(dev_info_t *dip)
{
	auvia_devc_t	*devc;

	devc = ddi_get_driver_private(dip);

	for (int i = 0; i < AUVIA_NUM_PORTC; i++) {

		auvia_portc_t *portc = devc->portc[i];
		auvia_stop_port(portc);
	}
	return (DDI_SUCCESS);
}
