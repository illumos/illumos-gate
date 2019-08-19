/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * VIRTIO FRAMEWORK: DMA ROUTINES
 *
 * For design and usage documentation, see the comments in "virtio.h".
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

#include "virtio.h"
#include "virtio_impl.h"



void
virtio_dma_sync(virtio_dma_t *vidma, int flag)
{
	VERIFY0(ddi_dma_sync(vidma->vidma_dma_handle, 0, 0, flag));
}

uint_t
virtio_dma_ncookies(virtio_dma_t *vidma)
{
	return (vidma->vidma_dma_ncookies);
}

size_t
virtio_dma_size(virtio_dma_t *vidma)
{
	return (vidma->vidma_size);
}

void *
virtio_dma_va(virtio_dma_t *vidma, size_t offset)
{
	VERIFY3U(offset, <, vidma->vidma_size);

	return (vidma->vidma_va + offset);
}

uint64_t
virtio_dma_cookie_pa(virtio_dma_t *vidma, uint_t cookie)
{
	VERIFY3U(cookie, <, vidma->vidma_dma_ncookies);

	return (vidma->vidma_dma_cookies[cookie].dmac_laddress);
}

size_t
virtio_dma_cookie_size(virtio_dma_t *vidma, uint_t cookie)
{
	VERIFY3U(cookie, <, vidma->vidma_dma_ncookies);

	return (vidma->vidma_dma_cookies[cookie].dmac_size);
}

int
virtio_dma_init_handle(virtio_t *vio, virtio_dma_t *vidma,
    const ddi_dma_attr_t *attr, int kmflags)
{
	int r;
	dev_info_t *dip = vio->vio_dip;

	VERIFY(kmflags == KM_SLEEP || kmflags == KM_NOSLEEP);
	int (*dma_wait)(caddr_t) = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP :
	    DDI_DMA_DONTWAIT;

	vidma->vidma_virtio = vio;

	/*
	 * Ensure we don't try to allocate a second time using the same
	 * tracking object.
	 */
	VERIFY0(vidma->vidma_level);

	if ((r = ddi_dma_alloc_handle(dip, (ddi_dma_attr_t *)attr, dma_wait,
	    NULL, &vidma->vidma_dma_handle)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "DMA handle allocation failed (%x)", r);
		goto fail;
	}
	vidma->vidma_level |= VIRTIO_DMALEVEL_HANDLE_ALLOC;

	return (DDI_SUCCESS);

fail:
	virtio_dma_fini(vidma);
	return (DDI_FAILURE);
}

int
virtio_dma_init(virtio_t *vio, virtio_dma_t *vidma, size_t sz,
    const ddi_dma_attr_t *attr, int dmaflags, int kmflags)
{
	int r;
	dev_info_t *dip = vio->vio_dip;
	caddr_t va = NULL;

	VERIFY(kmflags == KM_SLEEP || kmflags == KM_NOSLEEP);
	int (*dma_wait)(caddr_t) = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP :
	    DDI_DMA_DONTWAIT;

	if (virtio_dma_init_handle(vio, vidma, attr, kmflags) !=
	    DDI_SUCCESS) {
		goto fail;
	}

	if ((r = ddi_dma_mem_alloc(vidma->vidma_dma_handle, sz,
	    &virtio_acc_attr,
	    dmaflags & (DDI_DMA_STREAMING | DDI_DMA_CONSISTENT),
	    dma_wait, NULL, &va, &vidma->vidma_real_size,
	    &vidma->vidma_acc_handle)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "DMA memory allocation failed (%x)", r);
		goto fail;
	}
	vidma->vidma_level |= VIRTIO_DMALEVEL_MEMORY_ALLOC;

	/*
	 * Zero the memory to avoid accidental exposure of arbitrary kernel
	 * memory.
	 */
	bzero(va, vidma->vidma_real_size);

	if (virtio_dma_bind(vidma, va, sz, dmaflags, kmflags) != DDI_SUCCESS) {
		goto fail;
	}

	return (DDI_SUCCESS);

fail:
	virtio_dma_fini(vidma);
	return (DDI_FAILURE);
}

int
virtio_dma_bind(virtio_dma_t *vidma, void *va, size_t sz, int dmaflags,
    int kmflags)
{
	int r;
	dev_info_t *dip = vidma->vidma_virtio->vio_dip;
	ddi_dma_cookie_t dmac;

	VERIFY(kmflags == KM_SLEEP || kmflags == KM_NOSLEEP);
	int (*dma_wait)(caddr_t) = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP :
	    DDI_DMA_DONTWAIT;

	VERIFY(vidma->vidma_level & VIRTIO_DMALEVEL_HANDLE_ALLOC);
	VERIFY(!(vidma->vidma_level & VIRTIO_DMALEVEL_HANDLE_BOUND));

	vidma->vidma_va = va;
	vidma->vidma_size = sz;

	if ((r = ddi_dma_addr_bind_handle(vidma->vidma_dma_handle, NULL,
	    vidma->vidma_va, vidma->vidma_size, dmaflags, dma_wait, NULL,
	    &dmac, &vidma->vidma_dma_ncookies)) != DDI_DMA_MAPPED) {
		VERIFY3S(r, !=, DDI_DMA_PARTIAL_MAP);
		dev_err(dip, CE_WARN, "DMA handle bind failed (%x)", r);
		goto fail;
	}
	vidma->vidma_level |= VIRTIO_DMALEVEL_HANDLE_BOUND;

	if ((vidma->vidma_dma_cookies = kmem_alloc(
	    vidma->vidma_dma_ncookies * sizeof (ddi_dma_cookie_t),
	    kmflags)) == NULL) {
		dev_err(dip, CE_WARN, "DMA cookie array allocation failure");
		goto fail;
	}
	vidma->vidma_level |= VIRTIO_DMALEVEL_COOKIE_ARRAY;

	vidma->vidma_dma_cookies[0] = dmac;
	for (uint_t n = 1; n < vidma->vidma_dma_ncookies; n++) {
		ddi_dma_nextcookie(vidma->vidma_dma_handle,
		    &vidma->vidma_dma_cookies[n]);
	}

	return (DDI_SUCCESS);

fail:
	virtio_dma_unbind(vidma);
	return (DDI_FAILURE);
}

virtio_dma_t *
virtio_dma_alloc(virtio_t *vio, size_t sz, const ddi_dma_attr_t *attr,
    int dmaflags, int kmflags)
{
	virtio_dma_t *vidma;

	if ((vidma = kmem_zalloc(sizeof (*vidma), kmflags)) == NULL) {
		return (NULL);
	}

	if (virtio_dma_init(vio, vidma, sz, attr, dmaflags, kmflags) !=
	    DDI_SUCCESS) {
		kmem_free(vidma, sizeof (*vidma));
		return (NULL);
	}

	return (vidma);
}

virtio_dma_t *
virtio_dma_alloc_nomem(virtio_t *vio, const ddi_dma_attr_t *attr, int kmflags)
{
	virtio_dma_t *vidma;

	if ((vidma = kmem_zalloc(sizeof (*vidma), kmflags)) == NULL) {
		return (NULL);
	}

	if (virtio_dma_init_handle(vio, vidma, attr, kmflags) != DDI_SUCCESS) {
		kmem_free(vidma, sizeof (*vidma));
		return (NULL);
	}

	return (vidma);
}

void
virtio_dma_fini(virtio_dma_t *vidma)
{
	virtio_dma_unbind(vidma);

	if (vidma->vidma_level & VIRTIO_DMALEVEL_MEMORY_ALLOC) {
		ddi_dma_mem_free(&vidma->vidma_acc_handle);

		vidma->vidma_level &= ~VIRTIO_DMALEVEL_MEMORY_ALLOC;
	}

	if (vidma->vidma_level & VIRTIO_DMALEVEL_HANDLE_ALLOC) {
		ddi_dma_free_handle(&vidma->vidma_dma_handle);

		vidma->vidma_level &= ~VIRTIO_DMALEVEL_HANDLE_ALLOC;
	}

	VERIFY0(vidma->vidma_level);
	bzero(vidma, sizeof (*vidma));
}

void
virtio_dma_unbind(virtio_dma_t *vidma)
{
	if (vidma->vidma_level & VIRTIO_DMALEVEL_COOKIE_ARRAY) {
		kmem_free(vidma->vidma_dma_cookies,
		    vidma->vidma_dma_ncookies * sizeof (ddi_dma_cookie_t));

		vidma->vidma_level &= ~VIRTIO_DMALEVEL_COOKIE_ARRAY;
	}

	if (vidma->vidma_level & VIRTIO_DMALEVEL_HANDLE_BOUND) {
		VERIFY3U(ddi_dma_unbind_handle(vidma->vidma_dma_handle), ==,
		    DDI_SUCCESS);

		vidma->vidma_level &= ~VIRTIO_DMALEVEL_HANDLE_BOUND;
	}

	vidma->vidma_va = 0;
	vidma->vidma_size = 0;
}

void
virtio_dma_free(virtio_dma_t *vidma)
{
	virtio_dma_fini(vidma);
	kmem_free(vidma, sizeof (*vidma));
}
