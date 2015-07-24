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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2012 Alexey Zaytsev <alexey.zaytsev@gmail.com>
 */

/* Based on the NetBSD virtio driver by Minoura Makoto. */
/*
 * Copyright (c) 2010 Minoura Makoto.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/avintr.h>
#include <sys/spl.h>
#include <sys/promif.h>
#include <sys/list.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>

#include "virtiovar.h"
#include "virtioreg.h"

#define	NDEVNAMES	(sizeof (virtio_device_name) / sizeof (char *))
#define	MINSEG_INDIRECT	2	/* use indirect if nsegs >= this value */
#define	VIRTQUEUE_ALIGN(n) (((n)+(VIRTIO_PAGE_SIZE-1)) & \
	    ~(VIRTIO_PAGE_SIZE-1))

void
virtio_set_status(struct virtio_softc *sc, unsigned int status)
{
	int old = 0;

	if (status != 0) {
		old = ddi_get8(sc->sc_ioh, (uint8_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_DEVICE_STATUS));
	}

	ddi_put8(sc->sc_ioh, (uint8_t *)(sc->sc_io_addr +
	    VIRTIO_CONFIG_DEVICE_STATUS), status | old);
}

/*
 * Negotiate features, save the result in sc->sc_features
 */
uint32_t
virtio_negotiate_features(struct virtio_softc *sc, uint32_t guest_features)
{
	uint32_t host_features;
	uint32_t features;

	host_features = ddi_get32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_DEVICE_FEATURES));

	dev_debug(sc->sc_dev, CE_NOTE, "host features: %x, guest features: %x",
	    host_features, guest_features);

	features = host_features & guest_features;
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_GUEST_FEATURES),
	    features);

	sc->sc_features = features;

	return (host_features);
}

size_t
virtio_show_features(uint32_t features, char *buf, size_t len)
{
	char *orig_buf = buf;
	char *bufend = buf + len;

	/* LINTED E_PTRDIFF_OVERFLOW */
	buf += snprintf(buf, bufend - buf, "Generic ( ");
	if (features & VIRTIO_F_RING_INDIRECT_DESC)
		/* LINTED E_PTRDIFF_OVERFLOW */
		buf += snprintf(buf, bufend - buf, "INDIRECT_DESC ");

	/* LINTED E_PTRDIFF_OVERFLOW */
	buf += snprintf(buf, bufend - buf, ") ");

	/* LINTED E_PTRDIFF_OVERFLOW */
	return (buf - orig_buf);
}

boolean_t
virtio_has_feature(struct virtio_softc *sc, uint32_t feature)
{
	return (sc->sc_features & feature);
}

/*
 * Device configuration registers.
 */
uint8_t
virtio_read_device_config_1(struct virtio_softc *sc, unsigned int index)
{
	ASSERT(sc->sc_config_offset);
	return ddi_get8(sc->sc_ioh,
	    (uint8_t *)(sc->sc_io_addr + sc->sc_config_offset + index));
}

uint16_t
virtio_read_device_config_2(struct virtio_softc *sc, unsigned int index)
{
	ASSERT(sc->sc_config_offset);
	return ddi_get16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + sc->sc_config_offset + index));
}

uint32_t
virtio_read_device_config_4(struct virtio_softc *sc, unsigned int index)
{
	ASSERT(sc->sc_config_offset);
	return ddi_get32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset + index));
}

uint64_t
virtio_read_device_config_8(struct virtio_softc *sc, unsigned int index)
{
	uint64_t r;

	ASSERT(sc->sc_config_offset);
	r = ddi_get32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset +
	    index + sizeof (uint32_t)));

	r <<= 32;

	r += ddi_get32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset + index));
	return (r);
}

void
virtio_write_device_config_1(struct virtio_softc *sc, unsigned int index,
    uint8_t value)
{
	ASSERT(sc->sc_config_offset);
	ddi_put8(sc->sc_ioh,
	    (uint8_t *)(sc->sc_io_addr + sc->sc_config_offset + index), value);
}

void
virtio_write_device_config_2(struct virtio_softc *sc, unsigned int index,
    uint16_t value)
{
	ASSERT(sc->sc_config_offset);
	ddi_put16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + sc->sc_config_offset + index), value);
}

void
virtio_write_device_config_4(struct virtio_softc *sc, unsigned int index,
    uint32_t value)
{
	ASSERT(sc->sc_config_offset);
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset + index), value);
}

void
virtio_write_device_config_8(struct virtio_softc *sc, unsigned int index,
    uint64_t value)
{
	ASSERT(sc->sc_config_offset);
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset + index),
	    value & 0xFFFFFFFF);
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset +
	    index + sizeof (uint32_t)), value >> 32);
}

/*
 * Start/stop vq interrupt.  No guarantee.
 */
void
virtio_stop_vq_intr(struct virtqueue *vq)
{
	vq->vq_avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
}

void
virtio_start_vq_intr(struct virtqueue *vq)
{
	vq->vq_avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
}

static ddi_dma_attr_t virtio_vq_dma_attr = {
	DMA_ATTR_V0,		/* Version number */
	0,			/* low address */
	0x00000FFFFFFFFFFF,	/* high address. Has to fit into 32 bits */
				/* after page-shifting */
	0xFFFFFFFF,		/* counter register max */
	VIRTIO_PAGE_SIZE,	/* page alignment required */
	0x3F,			/* burst sizes: 1 - 32 */
	0x1,			/* minimum transfer size */
	0xFFFFFFFF,		/* max transfer size */
	0xFFFFFFFF,		/* address register max */
	1,			/* no scatter-gather */
	1,			/* device operates on bytes */
	0,			/* attr flag: set to 0 */
};

static ddi_dma_attr_t virtio_vq_indirect_dma_attr = {
	DMA_ATTR_V0,		/* Version number */
	0,			/* low address */
	0xFFFFFFFFFFFFFFFF,	/* high address */
	0xFFFFFFFF,		/* counter register max */
	1,			/* No specific alignment */
	0x3F,			/* burst sizes: 1 - 32 */
	0x1,			/* minimum transfer size */
	0xFFFFFFFF,		/* max transfer size */
	0xFFFFFFFF,		/* address register max */
	1,			/* no scatter-gather */
	1,			/* device operates on bytes */
	0,			/* attr flag: set to 0 */
};

/* Same for direct and indirect descriptors. */
static ddi_device_acc_attr_t virtio_vq_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STORECACHING_OK_ACC,
	DDI_DEFAULT_ACC
};

static void
virtio_free_indirect(struct vq_entry *entry)
{

	(void) ddi_dma_unbind_handle(entry->qe_indirect_dma_handle);
	ddi_dma_mem_free(&entry->qe_indirect_dma_acch);
	ddi_dma_free_handle(&entry->qe_indirect_dma_handle);

	entry->qe_indirect_descs = NULL;
}


static int
virtio_alloc_indirect(struct virtio_softc *sc, struct vq_entry *entry)
{
	int allocsize, num;
	size_t len;
	unsigned int ncookies;
	int ret;

	num = entry->qe_queue->vq_indirect_num;
	ASSERT(num > 1);

	allocsize = sizeof (struct vring_desc) * num;

	ret = ddi_dma_alloc_handle(sc->sc_dev, &virtio_vq_indirect_dma_attr,
	    DDI_DMA_SLEEP, NULL, &entry->qe_indirect_dma_handle);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate dma handle for indirect descriptors, "
		    "entry %d, vq %d", entry->qe_index,
		    entry->qe_queue->vq_index);
		goto out_alloc_handle;
	}

	ret = ddi_dma_mem_alloc(entry->qe_indirect_dma_handle, allocsize,
	    &virtio_vq_devattr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&entry->qe_indirect_descs, &len,
	    &entry->qe_indirect_dma_acch);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate dma memory for indirect descriptors, "
		    "entry %d, vq %d,", entry->qe_index,
		    entry->qe_queue->vq_index);
		goto out_alloc;
	}

	(void) memset(entry->qe_indirect_descs, 0xff, allocsize);

	ret = ddi_dma_addr_bind_handle(entry->qe_indirect_dma_handle, NULL,
	    (caddr_t)entry->qe_indirect_descs, len,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &entry->qe_indirect_dma_cookie, &ncookies);
	if (ret != DDI_DMA_MAPPED) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to bind dma memory for indirect descriptors, "
		    "entry %d, vq %d", entry->qe_index,
		    entry->qe_queue->vq_index);
		goto out_bind;
	}

	/* We asked for a single segment */
	ASSERT(ncookies == 1);

	return (0);

out_bind:
	ddi_dma_mem_free(&entry->qe_indirect_dma_acch);
out_alloc:
	ddi_dma_free_handle(&entry->qe_indirect_dma_handle);
out_alloc_handle:

	return (ret);
}

/*
 * Initialize the vq structure.
 */
static int
virtio_init_vq(struct virtio_softc *sc, struct virtqueue *vq)
{
	int ret;
	uint16_t i;
	int vq_size = vq->vq_num;
	int indirect_num = vq->vq_indirect_num;

	/* free slot management */
	list_create(&vq->vq_freelist, sizeof (struct vq_entry),
	    offsetof(struct vq_entry, qe_list));

	for (i = 0; i < vq_size; i++) {
		struct vq_entry *entry = &vq->vq_entries[i];
		list_insert_tail(&vq->vq_freelist, entry);
		entry->qe_index = i;
		entry->qe_desc = &vq->vq_descs[i];
		entry->qe_queue = vq;

		if (indirect_num) {
			ret = virtio_alloc_indirect(sc, entry);
			if (ret)
				goto out_indirect;
		}
	}

	mutex_init(&vq->vq_freelist_lock, "virtio-freelist", MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_prio));
	mutex_init(&vq->vq_avail_lock, "virtio-avail", MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_prio));
	mutex_init(&vq->vq_used_lock, "virtio-used", MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_prio));

	return (0);

out_indirect:
	for (i = 0; i < vq_size; i++) {
		struct vq_entry *entry = &vq->vq_entries[i];
		if (entry->qe_indirect_descs)
			virtio_free_indirect(entry);
	}

	return (ret);
}

/*
 * Allocate/free a vq.
 */
struct virtqueue *
virtio_alloc_vq(struct virtio_softc *sc, unsigned int index, unsigned int size,
    unsigned int indirect_num, const char *name)
{
	int vq_size, allocsize1, allocsize2, allocsize = 0;
	int ret;
	unsigned int ncookies;
	size_t len;
	struct virtqueue *vq;

	ddi_put16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SELECT), index);
	vq_size = ddi_get16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SIZE));
	if (vq_size == 0) {
		dev_err(sc->sc_dev, CE_WARN,
		    "virtqueue dest not exist, index %d for %s\n", index, name);
		goto out;
	}

	vq = kmem_zalloc(sizeof (struct virtqueue), KM_SLEEP);

	/* size 0 => use native vq size, good for receive queues. */
	if (size)
		vq_size = MIN(vq_size, size);

	/* allocsize1: descriptor table + avail ring + pad */
	allocsize1 = VIRTQUEUE_ALIGN(sizeof (struct vring_desc) * vq_size +
	    sizeof (struct vring_avail) + sizeof (uint16_t) * vq_size);
	/* allocsize2: used ring + pad */
	allocsize2 = VIRTQUEUE_ALIGN(sizeof (struct vring_used) +
	    sizeof (struct vring_used_elem) * vq_size);

	allocsize = allocsize1 + allocsize2;

	ret = ddi_dma_alloc_handle(sc->sc_dev, &virtio_vq_dma_attr,
	    DDI_DMA_SLEEP, NULL, &vq->vq_dma_handle);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate dma handle for vq %d", index);
		goto out_alloc_handle;
	}

	ret = ddi_dma_mem_alloc(vq->vq_dma_handle, allocsize,
	    &virtio_vq_devattr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&vq->vq_vaddr, &len, &vq->vq_dma_acch);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate dma memory for vq %d", index);
		goto out_alloc;
	}

	ret = ddi_dma_addr_bind_handle(vq->vq_dma_handle, NULL,
	    (caddr_t)vq->vq_vaddr, len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &vq->vq_dma_cookie, &ncookies);
	if (ret != DDI_DMA_MAPPED) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to bind dma memory for vq %d", index);
		goto out_bind;
	}

	/* We asked for a single segment */
	ASSERT(ncookies == 1);
	/* and page-ligned buffers. */
	ASSERT(vq->vq_dma_cookie.dmac_laddress % VIRTIO_PAGE_SIZE == 0);

	(void) memset(vq->vq_vaddr, 0, allocsize);

	/* Make sure all zeros hit the buffer before we point the host to it */
	membar_producer();

	/* set the vq address */
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_ADDRESS),
	    (vq->vq_dma_cookie.dmac_laddress / VIRTIO_PAGE_SIZE));

	/* remember addresses and offsets for later use */
	vq->vq_owner = sc;
	vq->vq_num = vq_size;
	vq->vq_index = index;
	vq->vq_descs = vq->vq_vaddr;
	vq->vq_availoffset = sizeof (struct vring_desc)*vq_size;
	vq->vq_avail = (void *)(((char *)vq->vq_descs) + vq->vq_availoffset);
	vq->vq_usedoffset = allocsize1;
	vq->vq_used = (void *)(((char *)vq->vq_descs) + vq->vq_usedoffset);

	ASSERT(indirect_num == 0 ||
	    virtio_has_feature(sc, VIRTIO_F_RING_INDIRECT_DESC));
	vq->vq_indirect_num = indirect_num;

	/* free slot management */
	vq->vq_entries = kmem_zalloc(sizeof (struct vq_entry) * vq_size,
	    KM_SLEEP);

	ret = virtio_init_vq(sc, vq);
	if (ret)
		goto out_init;

	dev_debug(sc->sc_dev, CE_NOTE,
	    "Allocated %d entries for vq %d:%s (%d indirect descs)",
	    vq_size, index, name, indirect_num * vq_size);

	return (vq);

out_init:
	kmem_free(vq->vq_entries, sizeof (struct vq_entry) * vq_size);
	(void) ddi_dma_unbind_handle(vq->vq_dma_handle);
out_bind:
	ddi_dma_mem_free(&vq->vq_dma_acch);
out_alloc:
	ddi_dma_free_handle(&vq->vq_dma_handle);
out_alloc_handle:
	kmem_free(vq, sizeof (struct virtqueue));
out:
	return (NULL);
}

void
virtio_free_vq(struct virtqueue *vq)
{
	struct virtio_softc *sc = vq->vq_owner;
	int i;

	/* tell device that there's no virtqueue any longer */
	ddi_put16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SELECT),
	    vq->vq_index);
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_ADDRESS), 0);

	/* Free the indirect descriptors, if any. */
	for (i = 0; i < vq->vq_num; i++) {
		struct vq_entry *entry = &vq->vq_entries[i];
		if (entry->qe_indirect_descs)
			virtio_free_indirect(entry);
	}

	kmem_free(vq->vq_entries, sizeof (struct vq_entry) * vq->vq_num);

	(void) ddi_dma_unbind_handle(vq->vq_dma_handle);
	ddi_dma_mem_free(&vq->vq_dma_acch);
	ddi_dma_free_handle(&vq->vq_dma_handle);

	mutex_destroy(&vq->vq_used_lock);
	mutex_destroy(&vq->vq_avail_lock);
	mutex_destroy(&vq->vq_freelist_lock);

	kmem_free(vq, sizeof (struct virtqueue));
}

/*
 * Free descriptor management.
 */
struct vq_entry *
vq_alloc_entry(struct virtqueue *vq)
{
	struct vq_entry *qe;

	mutex_enter(&vq->vq_freelist_lock);
	if (list_is_empty(&vq->vq_freelist)) {
		mutex_exit(&vq->vq_freelist_lock);
		return (NULL);
	}
	qe = list_remove_head(&vq->vq_freelist);

	ASSERT(vq->vq_used_entries >= 0);
	vq->vq_used_entries++;

	mutex_exit(&vq->vq_freelist_lock);

	qe->qe_next = NULL;
	qe->qe_indirect_next = 0;
	(void) memset(qe->qe_desc, 0, sizeof (struct vring_desc));

	return (qe);
}

void
vq_free_entry(struct virtqueue *vq, struct vq_entry *qe)
{
	mutex_enter(&vq->vq_freelist_lock);

	list_insert_head(&vq->vq_freelist, qe);
	vq->vq_used_entries--;
	ASSERT(vq->vq_used_entries >= 0);
	mutex_exit(&vq->vq_freelist_lock);
}

/*
 * We (intentionally) don't have a global vq mutex, so you are
 * responsible for external locking to avoid allocting/freeing any
 * entries before using the returned value. Have fun.
 */
uint_t
vq_num_used(struct virtqueue *vq)
{
	/* vq->vq_freelist_lock would not help here. */
	return (vq->vq_used_entries);
}

static inline void
virtio_ve_set_desc(struct vring_desc *desc, uint64_t paddr, uint32_t len,
    boolean_t write)
{
	desc->addr = paddr;
	desc->len = len;
	desc->next = 0;
	desc->flags = 0;

	/* 'write' - from the driver's point of view */
	if (!write)
		desc->flags = VRING_DESC_F_WRITE;
}

void
virtio_ve_set(struct vq_entry *qe, uint64_t paddr, uint32_t len,
    boolean_t write)
{
	virtio_ve_set_desc(qe->qe_desc, paddr, len, write);
}

unsigned int
virtio_ve_indirect_available(struct vq_entry *qe)
{
	return (qe->qe_queue->vq_indirect_num - (qe->qe_indirect_next - 1));
}

void
virtio_ve_add_indirect_buf(struct vq_entry *qe, uint64_t paddr, uint32_t len,
    boolean_t write)
{
	struct vring_desc *indirect_desc;

	ASSERT(qe->qe_queue->vq_indirect_num);
	ASSERT(qe->qe_indirect_next < qe->qe_queue->vq_indirect_num);

	indirect_desc = &qe->qe_indirect_descs[qe->qe_indirect_next];
	virtio_ve_set_desc(indirect_desc, paddr, len, write);
	qe->qe_indirect_next++;
}

void
virtio_ve_add_cookie(struct vq_entry *qe, ddi_dma_handle_t dma_handle,
    ddi_dma_cookie_t dma_cookie, unsigned int ncookies, boolean_t write)
{
	int i;

	for (i = 0; i < ncookies; i++) {
		virtio_ve_add_indirect_buf(qe, dma_cookie.dmac_laddress,
		    dma_cookie.dmac_size, write);
		ddi_dma_nextcookie(dma_handle, &dma_cookie);
	}
}

void
virtio_sync_vq(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;

	/* Make sure the avail ring update hit the buffer */
	membar_producer();

	vq->vq_avail->idx = vq->vq_avail_idx;

	/* Make sure the avail idx update hits the buffer */
	membar_producer();

	/* Make sure we see the flags update */
	membar_consumer();

	if (!(vq->vq_used->flags & VRING_USED_F_NO_NOTIFY)) {
		ddi_put16(vsc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(vsc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_NOTIFY),
		    vq->vq_index);
	}
}

void
virtio_push_chain(struct vq_entry *qe, boolean_t sync)
{
	struct virtqueue *vq = qe->qe_queue;
	struct vq_entry *head = qe;
	struct vring_desc *desc;
	int idx;

	ASSERT(qe);

	/*
	 * Bind the descs together, paddr and len should be already
	 * set with virtio_ve_set
	 */
	do {
		/* Bind the indirect descriptors */
		if (qe->qe_indirect_next > 1) {
			uint16_t i = 0;

			/*
			 * Set the pointer/flags to the
			 * first indirect descriptor
			 */
			virtio_ve_set_desc(qe->qe_desc,
			    qe->qe_indirect_dma_cookie.dmac_laddress,
			    sizeof (struct vring_desc) * qe->qe_indirect_next,
			    B_FALSE);
			qe->qe_desc->flags |= VRING_DESC_F_INDIRECT;

			/* For all but the last one, add the next index/flag */
			do {
				desc = &qe->qe_indirect_descs[i];
				i++;

				desc->flags |= VRING_DESC_F_NEXT;
				desc->next = i;
			} while (i < qe->qe_indirect_next - 1);

		}

		if (qe->qe_next) {
			qe->qe_desc->flags |= VRING_DESC_F_NEXT;
			qe->qe_desc->next = qe->qe_next->qe_index;
		}

		qe = qe->qe_next;
	} while (qe);

	mutex_enter(&vq->vq_avail_lock);
	idx = vq->vq_avail_idx;
	vq->vq_avail_idx++;

	/* Make sure the bits hit the descriptor(s) */
	membar_producer();
	vq->vq_avail->ring[idx % vq->vq_num] = head->qe_index;

	/* Notify the device, if needed. */
	if (sync)
		virtio_sync_vq(vq);

	mutex_exit(&vq->vq_avail_lock);
}

/*
 * Get a chain of descriptors from the used ring, if one is available.
 */
struct vq_entry *
virtio_pull_chain(struct virtqueue *vq, uint32_t *len)
{
	struct vq_entry *head;
	int slot;
	int usedidx;

	mutex_enter(&vq->vq_used_lock);

	/* No used entries? Bye. */
	if (vq->vq_used_idx == vq->vq_used->idx) {
		mutex_exit(&vq->vq_used_lock);
		return (NULL);
	}

	usedidx = vq->vq_used_idx;
	vq->vq_used_idx++;
	mutex_exit(&vq->vq_used_lock);

	usedidx %= vq->vq_num;

	/* Make sure we do the next step _after_ checking the idx. */
	membar_consumer();

	slot = vq->vq_used->ring[usedidx].id;
	*len = vq->vq_used->ring[usedidx].len;

	head = &vq->vq_entries[slot];

	return (head);
}

void
virtio_free_chain(struct vq_entry *qe)
{
	struct vq_entry *tmp;
	struct virtqueue *vq = qe->qe_queue;

	ASSERT(qe);

	do {
		ASSERT(qe->qe_queue == vq);
		tmp = qe->qe_next;
		vq_free_entry(vq, qe);
		qe = tmp;
	} while (tmp != NULL);
}

void
virtio_ventry_stick(struct vq_entry *first, struct vq_entry *second)
{
	first->qe_next = second;
}

static int
virtio_register_msi(struct virtio_softc *sc,
    struct virtio_int_handler *config_handler,
    struct virtio_int_handler vq_handlers[], int intr_types)
{
	int count, actual;
	int int_type;
	int i;
	int handler_count;
	int ret;

	/* If both MSI and MSI-x are reported, prefer MSI-x. */
	int_type = DDI_INTR_TYPE_MSI;
	if (intr_types & DDI_INTR_TYPE_MSIX)
		int_type = DDI_INTR_TYPE_MSIX;

	/* Walk the handler table to get the number of handlers. */
	for (handler_count = 0;
	    vq_handlers && vq_handlers[handler_count].vh_func;
	    handler_count++)
		;

	/* +1 if there is a config change handler. */
	if (config_handler != NULL)
		handler_count++;

	/* Number of MSIs supported by the device. */
	ret = ddi_intr_get_nintrs(sc->sc_dev, int_type, &count);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_intr_get_nintrs failed");
		return (ret);
	}

	/*
	 * Those who try to register more handlers then the device
	 * supports shall suffer.
	 */
	ASSERT(handler_count <= count);

	sc->sc_intr_htable = kmem_zalloc(sizeof (ddi_intr_handle_t) *
	    handler_count, KM_SLEEP);

	ret = ddi_intr_alloc(sc->sc_dev, sc->sc_intr_htable, int_type, 0,
	    handler_count, &actual, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN, "Failed to allocate MSI: %d", ret);
		goto out_msi_alloc;
	}

	if (actual != handler_count) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Not enough MSI available: need %d, available %d",
		    handler_count, actual);
		goto out_msi_available;
	}

	sc->sc_intr_num = handler_count;
	sc->sc_intr_config = B_FALSE;
	if (config_handler != NULL) {
		sc->sc_intr_config = B_TRUE;
	}

	/* Assume they are all same priority */
	ret = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_prio);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_intr_get_pri failed");
		goto out_msi_prio;
	}

	/* Add the vq handlers */
	for (i = 0; vq_handlers[i].vh_func; i++) {
		ret = ddi_intr_add_handler(sc->sc_intr_htable[i],
		    vq_handlers[i].vh_func, sc, vq_handlers[i].vh_priv);
		if (ret != DDI_SUCCESS) {
			dev_err(sc->sc_dev, CE_WARN,
			    "ddi_intr_add_handler failed");
			/* Remove the handlers that succeeded. */
			while (--i >= 0) {
				(void) ddi_intr_remove_handler(
				    sc->sc_intr_htable[i]);
			}
			goto out_add_handlers;
		}
	}

	/* Don't forget the config handler */
	if (config_handler != NULL) {
		ret = ddi_intr_add_handler(sc->sc_intr_htable[i],
		    config_handler->vh_func, sc, config_handler->vh_priv);
		if (ret != DDI_SUCCESS) {
			dev_err(sc->sc_dev, CE_WARN,
			    "ddi_intr_add_handler failed");
			/* Remove the handlers that succeeded. */
			while (--i >= 0) {
				(void) ddi_intr_remove_handler(
				    sc->sc_intr_htable[i]);
			}
			goto out_add_handlers;
		}
	}

	/* We know we are using MSI, so set the config offset. */
	sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_MSI;

	ret = ddi_intr_get_cap(sc->sc_intr_htable[0], &sc->sc_intr_cap);
	/* Just in case. */
	if (ret != DDI_SUCCESS)
		sc->sc_intr_cap = 0;

out_add_handlers:
out_msi_prio:
out_msi_available:
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(sc->sc_intr_htable[i]);
out_msi_alloc:
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t) * count);

	return (ret);
}

struct virtio_handler_container {
	int nhandlers;
	struct virtio_int_handler config_handler;
	struct virtio_int_handler vq_handlers[];
};

uint_t
virtio_intx_dispatch(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *sc = (void *)arg1;
	struct virtio_handler_container *vhc = (void *)arg2;
	uint8_t isr_status;
	int i;

	isr_status = ddi_get8(sc->sc_ioh, (uint8_t *)(sc->sc_io_addr +
	    VIRTIO_CONFIG_ISR_STATUS));

	if (!isr_status)
		return (DDI_INTR_UNCLAIMED);

	if ((isr_status & VIRTIO_CONFIG_ISR_CONFIG_CHANGE) &&
	    vhc->config_handler.vh_func) {
		vhc->config_handler.vh_func((void *)sc,
		    vhc->config_handler.vh_priv);
	}

	/* Notify all handlers */
	for (i = 0; i < vhc->nhandlers; i++) {
		vhc->vq_handlers[i].vh_func((void *)sc,
		    vhc->vq_handlers[i].vh_priv);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * config_handler and vq_handlers may be allocated on stack.
 * Take precautions not to loose them.
 */
static int
virtio_register_intx(struct virtio_softc *sc,
    struct virtio_int_handler *config_handler,
    struct virtio_int_handler vq_handlers[])
{
	int vq_handler_count;
	int config_handler_count = 0;
	int actual;
	struct virtio_handler_container *vhc;
	int ret = DDI_FAILURE;

	/* Walk the handler table to get the number of handlers. */
	for (vq_handler_count = 0;
	    vq_handlers && vq_handlers[vq_handler_count].vh_func;
	    vq_handler_count++)
		;

	if (config_handler != NULL)
		config_handler_count = 1;

	vhc = kmem_zalloc(sizeof (struct virtio_handler_container) +
	    sizeof (struct virtio_int_handler) * vq_handler_count, KM_SLEEP);

	vhc->nhandlers = vq_handler_count;
	(void) memcpy(vhc->vq_handlers, vq_handlers,
	    sizeof (struct virtio_int_handler) * vq_handler_count);

	if (config_handler != NULL) {
		(void) memcpy(&vhc->config_handler, config_handler,
		    sizeof (struct virtio_int_handler));
	}

	/* Just a single entry for a single interrupt. */
	sc->sc_intr_htable = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_SLEEP);

	ret = ddi_intr_alloc(sc->sc_dev, sc->sc_intr_htable,
	    DDI_INTR_TYPE_FIXED, 0, 1, &actual, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate a fixed interrupt: %d", ret);
		goto out_int_alloc;
	}

	ASSERT(actual == 1);
	sc->sc_intr_num = 1;

	ret = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_prio);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_intr_get_pri failed");
		goto out_prio;
	}

	ret = ddi_intr_add_handler(sc->sc_intr_htable[0],
	    virtio_intx_dispatch, sc, vhc);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_intr_add_handler failed");
		goto out_add_handlers;
	}

	/* We know we are not using MSI, so set the config offset. */
	sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;

	return (DDI_SUCCESS);

out_add_handlers:
out_prio:
	(void) ddi_intr_free(sc->sc_intr_htable[0]);
out_int_alloc:
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));
	kmem_free(vhc, sizeof (struct virtio_int_handler) *
	    (vq_handler_count + config_handler_count));
	return (ret);
}

/*
 * We find out if we support MSI during this, and the register layout
 * depends on the MSI (doh). Don't acces the device specific bits in
 * BAR 0 before calling it!
 */
int
virtio_register_ints(struct virtio_softc *sc,
    struct virtio_int_handler *config_handler,
    struct virtio_int_handler vq_handlers[])
{
	int ret;
	int intr_types;

	/* Determine which types of interrupts are supported */
	ret = ddi_intr_get_supported_types(sc->sc_dev, &intr_types);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN, "Can't get supported int types");
		goto out_inttype;
	}

	/* If we have msi, let's use them. */
	if (intr_types & (DDI_INTR_TYPE_MSIX | DDI_INTR_TYPE_MSI)) {
		ret = virtio_register_msi(sc, config_handler,
		    vq_handlers, intr_types);
		if (!ret)
			return (0);
	}

	/* Fall back to old-fashioned interrupts. */
	if (intr_types & DDI_INTR_TYPE_FIXED) {
		dev_debug(sc->sc_dev, CE_WARN,
		    "Using legacy interrupts");

		return (virtio_register_intx(sc, config_handler, vq_handlers));
	}

	dev_err(sc->sc_dev, CE_WARN,
	    "MSI failed and fixed interrupts not supported. Giving up.");
	ret = DDI_FAILURE;

out_inttype:
	return (ret);
}

static int
virtio_enable_msi(struct virtio_softc *sc)
{
	int ret, i;
	int vq_handler_count = sc->sc_intr_num;

	/* Number of handlers, not counting the counfig. */
	if (sc->sc_intr_config)
		vq_handler_count--;

	/* Enable the iterrupts. Either the whole block, or one by one. */
	if (sc->sc_intr_cap & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_enable(sc->sc_intr_htable,
		    sc->sc_intr_num);
		if (ret != DDI_SUCCESS) {
			dev_err(sc->sc_dev, CE_WARN,
			    "Failed to enable MSI, falling back to INTx");
			goto out_enable;
		}
	} else {
		for (i = 0; i < sc->sc_intr_num; i++) {
			ret = ddi_intr_enable(sc->sc_intr_htable[i]);
			if (ret != DDI_SUCCESS) {
				dev_err(sc->sc_dev, CE_WARN,
				    "Failed to enable MSI %d, "
				    "falling back to INTx", i);

				while (--i >= 0) {
					(void) ddi_intr_disable(
					    sc->sc_intr_htable[i]);
				}
				goto out_enable;
			}
		}
	}

	/* Bind the allocated MSI to the queues and config */
	for (i = 0; i < vq_handler_count; i++) {
		int check;

		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_SELECT), i);

		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_VECTOR), i);

		check = ddi_get16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_VECTOR));
		if (check != i) {
			dev_err(sc->sc_dev, CE_WARN, "Failed to bind handler "
			    "for VQ %d, MSI %d. Check = %x", i, i, check);
			ret = ENODEV;
			goto out_bind;
		}
	}

	if (sc->sc_intr_config) {
		int check;

		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_CONFIG_VECTOR), i);

		check = ddi_get16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_CONFIG_VECTOR));
		if (check != i) {
			dev_err(sc->sc_dev, CE_WARN, "Failed to bind handler "
			    "for Config updates, MSI %d", i);
			ret = ENODEV;
			goto out_bind;
		}
	}

	return (DDI_SUCCESS);

out_bind:
	/* Unbind the vqs */
	for (i = 0; i < vq_handler_count - 1; i++) {
		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_SELECT), i);

		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_VECTOR),
		    VIRTIO_MSI_NO_VECTOR);
	}
	/* And the config */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ddi_put16(sc->sc_ioh, (uint16_t *)(sc->sc_io_addr +
	    VIRTIO_CONFIG_CONFIG_VECTOR), VIRTIO_MSI_NO_VECTOR);

	ret = DDI_FAILURE;

out_enable:
	return (ret);
}

static int
virtio_enable_intx(struct virtio_softc *sc)
{
	int ret;

	ret = ddi_intr_enable(sc->sc_intr_htable[0]);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to enable interrupt: %d", ret);
	}

	return (ret);
}

/*
 * We can't enable/disable individual handlers in the INTx case so do
 * the whole bunch even in the msi case.
 */
int
virtio_enable_ints(struct virtio_softc *sc)
{

	/* See if we are using MSI. */
	if (sc->sc_config_offset == VIRTIO_CONFIG_DEVICE_CONFIG_MSI)
		return (virtio_enable_msi(sc));

	ASSERT(sc->sc_config_offset == VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI);

	return (virtio_enable_intx(sc));
}

void
virtio_release_ints(struct virtio_softc *sc)
{
	int i;
	int ret;

	/* We were running with MSI, unbind them. */
	if (sc->sc_config_offset == VIRTIO_CONFIG_DEVICE_CONFIG_MSI) {
		/* Unbind all vqs */
		for (i = 0; i < sc->sc_nvqs; i++) {
			ddi_put16(sc->sc_ioh,
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    (uint16_t *)(sc->sc_io_addr +
			    VIRTIO_CONFIG_QUEUE_SELECT), i);

			ddi_put16(sc->sc_ioh,
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    (uint16_t *)(sc->sc_io_addr +
			    VIRTIO_CONFIG_QUEUE_VECTOR),
			    VIRTIO_MSI_NO_VECTOR);
		}
		/* And the config */
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		ddi_put16(sc->sc_ioh, (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_CONFIG_VECTOR),
		    VIRTIO_MSI_NO_VECTOR);

	}

	/* Disable the iterrupts. Either the whole block, or one by one. */
	if (sc->sc_intr_cap & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_disable(sc->sc_intr_htable,
		    sc->sc_intr_num);
		if (ret != DDI_SUCCESS) {
			dev_err(sc->sc_dev, CE_WARN,
			    "Failed to disable MSIs, won't be able to "
			    "reuse next time");
		}
	} else {
		for (i = 0; i < sc->sc_intr_num; i++) {
			ret = ddi_intr_disable(sc->sc_intr_htable[i]);
			if (ret != DDI_SUCCESS) {
				dev_err(sc->sc_dev, CE_WARN,
				    "Failed to disable interrupt %d, "
				    "won't be able to reuse", i);
			}
		}
	}


	for (i = 0; i < sc->sc_intr_num; i++) {
		(void) ddi_intr_remove_handler(sc->sc_intr_htable[i]);
	}

	for (i = 0; i < sc->sc_intr_num; i++)
		(void) ddi_intr_free(sc->sc_intr_htable[i]);

	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t) *
	    sc->sc_intr_num);

	/* After disabling interrupts, the config offset is non-MSI. */
	sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;
}

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops,	/* Type of module */
	"VirtIO common library module",
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modlmisc,
		NULL
	}
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
