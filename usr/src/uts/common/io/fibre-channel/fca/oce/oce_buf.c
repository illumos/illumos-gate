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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Source file containing the implementation of Driver buffer management
 * and related helper functions
 */
#include <oce_impl.h>

static ddi_dma_attr_t oce_dma_buf_attr = {
	DMA_ATTR_V0,		/* version number */
	0x0000000000000000ull,	/* low address */
	0xFFFFFFFFFFFFFFFFull,	/* high address */
	0x00000000FFFFFFFFull,	/* dma counter max */
	OCE_DMA_ALIGNMENT,	/* alignment */
	0x00000FFF,		/* burst sizes */
	0x00000001,		/* minimum transfer size */
	0x00000000FFFFFFFFull,	/* maximum transfer size */
	0xFFFFFFFFFFFFFFFFull,	/* maximum segment size */
	1,			/* scatter/gather list length */
	0x00000001,		/* granularity */
	0			/* DMA flags */
};

static ddi_device_acc_attr_t oce_dma_buf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
};


/*
 * function to allocate a dma buffer for mapping memory va-pa
 *
 * dev - software handle to device
 * size - size of the memory to map
 * flags - DDI_DMA_CONSISTENT/DDI_DMA_STREAMING
 *
 * return pointer to a oce_dma_buf_t structure handling the map
 *      NULL => failure
 */
oce_dma_buf_t *
oce_alloc_dma_buffer(struct oce_dev *dev,
    uint32_t size, uint32_t flags)
{
	oce_dma_buf_t  *dbuf;
	ddi_dma_cookie_t cookie;
	uint32_t count;
	size_t actual_len;
	int ret = 0;

	ASSERT(size > 0);

	dbuf = kmem_zalloc(sizeof (oce_dma_buf_t), KM_SLEEP);

	/* allocate dma handle */
	ret = ddi_dma_alloc_handle(dev->dip, &oce_dma_buf_attr,
	    DDI_DMA_SLEEP, NULL, &dbuf->dma_handle);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Failed to allocate DMA handle");
		goto alloc_fail;
	}
	/* allocate the DMA-able memory */
	ret = ddi_dma_mem_alloc(dbuf->dma_handle, size, &oce_dma_buf_accattr,
	    flags, DDI_DMA_SLEEP, NULL, &dbuf->base,
	    &actual_len, &dbuf->acc_handle);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Failed to allocate DMA memory");
		goto alloc_fail;
	}

	/* bind handle */
	ret = ddi_dma_addr_bind_handle(dbuf->dma_handle,
	    (struct as *)0, dbuf->base, actual_len,
	    DDI_DMA_RDWR | flags,
	    DDI_DMA_SLEEP, NULL, &cookie, &count);
	if (ret != DDI_DMA_MAPPED) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Failed to bind dma handle");
		goto alloc_fail;
	}
	bzero(dbuf->base, actual_len);
	dbuf->addr = cookie.dmac_laddress;
	dbuf->size = actual_len;
	/* usable length */
	dbuf->len  = size;
	dbuf->num_pages = OCE_NUM_PAGES(size);
	return (dbuf);
alloc_fail:
	oce_free_dma_buffer(dev, dbuf);
	return (NULL);
} /* oce_dma_alloc_buffer */

/*
 * function to delete a dma buffer
 *
 * dev - software handle to device
 * dbuf - dma obj  to delete
 *
 * return none
 */
void
oce_free_dma_buffer(struct oce_dev *dev, oce_dma_buf_t *dbuf)
{
	_NOTE(ARGUNUSED(dev));

	if (dbuf == NULL) {
		return;
	}
	if (dbuf->dma_handle != NULL) {
		(void) ddi_dma_unbind_handle(dbuf->dma_handle);
	}
	if (dbuf->acc_handle != NULL) {
		ddi_dma_mem_free(&dbuf->acc_handle);
	}
	if (dbuf->dma_handle != NULL) {
		ddi_dma_free_handle(&dbuf->dma_handle);
	}
	kmem_free(dbuf, sizeof (oce_dma_buf_t));
} /* oce_free_dma_buffer */

/*
 * function to create a ring buffer
 *
 * dev - software handle to the device
 * num_items - number of items in the ring
 * item_size - size of an individual item in the ring
 * flags - DDI_DMA_CONSISTENT/DDI_DMA_STREAMING for ring memory
 *
 * return pointer to a ring_buffer structure, NULL on failure
 */
oce_ring_buffer_t *
create_ring_buffer(struct oce_dev *dev,
    uint32_t num_items, uint32_t item_size, uint32_t flags)
{
	oce_ring_buffer_t *ring;
	uint32_t size;

	/* allocate the ring buffer */
	ring = kmem_zalloc(sizeof (oce_ring_buffer_t), KM_SLEEP);

	/* get the dbuf defining the ring */
	size = num_items * item_size;
	ring->dbuf = oce_alloc_dma_buffer(dev, size, flags);
	if (ring->dbuf  == NULL) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Ring buffer allocation failed");
		goto dbuf_fail;
	}

	/* fill the rest of the ring */
	ring->num_items = num_items;
	ring->item_size = item_size;
	ring->num_used  = 0;
	return (ring);

dbuf_fail:
	kmem_free(ring, sizeof (oce_ring_buffer_t));
	return (NULL);
} /* create_ring_buffer */

/*
 * function to destroy a ring buffer
 *
 * dev - software handle to teh device
 * ring - the ring buffer to delete
 *
 * return none
 */
void
destroy_ring_buffer(struct oce_dev *dev, oce_ring_buffer_t *ring)
{
	ASSERT(dev != NULL);
	ASSERT(ring !=  NULL);

	/* free the dbuf associated with the ring */
	oce_free_dma_buffer(dev, ring->dbuf);
	ring->dbuf = NULL;

	/* free the ring itself */
	kmem_free(ring, sizeof (oce_ring_buffer_t));
} /* destroy_ring_buffer */


/*
 * function to enable the fma flags
 * fm_caps - FM capability flags
 *
 * return none
 */

void
oce_set_dma_fma_flags(int fm_caps)
{
	if (fm_caps == DDI_FM_NOT_CAPABLE) {
		return;
	}

	if (DDI_FM_ACC_ERR_CAP(fm_caps)) {
		oce_dma_buf_accattr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		oce_dma_buf_accattr.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	if (DDI_FM_DMA_ERR_CAP(fm_caps)) {
		oce_dma_buf_attr.dma_attr_flags |= DDI_DMA_FLAGERR;

	} else {
		oce_dma_buf_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;

	}
} /* oce_set_dma_fma_flags */
