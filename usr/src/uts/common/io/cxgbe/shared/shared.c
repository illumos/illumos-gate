/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/kmem.h>

#include "osdep.h"
#include "shared.h"

static int rxbuf_ctor(void *, void *, int);
static void rxbuf_dtor(void *, void *);

void
cxgb_printf(dev_info_t *dip, int level, char *f, ...)
{
	va_list list;
	char fmt[128];

	(void) snprintf(fmt, sizeof (fmt), "%s%d: %s", ddi_driver_name(dip),
	    ddi_get_instance(dip), f);
	va_start(list, f);
	vcmn_err(level, fmt, list);
	va_end(list);
}

kmem_cache_t *
rxbuf_cache_create(struct rxbuf_cache_params *p)
{
	char name[32];

	(void) snprintf(name, sizeof (name), "%s%d_rxbuf_cache",
	    ddi_driver_name(p->dip), ddi_get_instance(p->dip));

	return kmem_cache_create(name, sizeof (struct rxbuf), CACHE_LINE,
	    rxbuf_ctor, rxbuf_dtor, NULL, p, NULL, 0);
}

void
rxbuf_cache_destroy(kmem_cache_t *cache)
{
	kmem_cache_destroy(cache);
}

/*
 * If ref_cnt is more than 1 then those many calls to rxbuf_free will
 * have to be made before the rxb is released back to the kmem_cache.
 */
struct rxbuf *
rxbuf_alloc(kmem_cache_t *cache, int kmflags, uint_t ref_cnt)
{
	struct rxbuf *rxb;

	ASSERT(ref_cnt > 0);

	rxb = kmem_cache_alloc(cache, kmflags);
	if (rxb != NULL) {
		rxb->ref_cnt = ref_cnt;
		rxb->cache = cache;
	}

	return (rxb);
}

/*
 * This is normally called via the rxb's freefunc, when an mblk referencing the
 * rxb is freed.
 */
void
rxbuf_free(struct rxbuf *rxb)
{
	if (atomic_dec_uint_nv(&rxb->ref_cnt) == 0)
		kmem_cache_free(rxb->cache, rxb);
}

static int
rxbuf_ctor(void *arg1, void *arg2, int kmflag)
{
	struct rxbuf *rxb = arg1;
	struct rxbuf_cache_params *p = arg2;
	size_t real_len;
	ddi_dma_cookie_t cookie;
	uint_t ccount = 0;
	int (*callback)(caddr_t);
	int rc = ENOMEM;

	if (kmflag & KM_SLEEP)
		callback = DDI_DMA_SLEEP;
	else
		callback = DDI_DMA_DONTWAIT;

	rc = ddi_dma_alloc_handle(p->dip, &p->dma_attr_rx, callback, 0,
	    &rxb->dhdl);
	if (rc != DDI_SUCCESS)
		return (rc == DDI_DMA_BADATTR ? EINVAL : ENOMEM);

	rc = ddi_dma_mem_alloc(rxb->dhdl, p->buf_size, &p->acc_attr_rx,
	    DDI_DMA_STREAMING, callback, 0, &rxb->va, &real_len, &rxb->ahdl);
	if (rc != DDI_SUCCESS) {
		rc = ENOMEM;
		goto fail1;
	}

	rc = ddi_dma_addr_bind_handle(rxb->dhdl, NULL, rxb->va, p->buf_size,
	    DDI_DMA_READ | DDI_DMA_STREAMING, NULL, NULL, &cookie, &ccount);
	if (rc != DDI_DMA_MAPPED) {
		if (rc == DDI_DMA_INUSE)
			rc = EBUSY;
		else if (rc == DDI_DMA_TOOBIG)
			rc = E2BIG;
		else
			rc = ENOMEM;
		goto fail2;
	}

	if (ccount != 1) {
		rc = E2BIG;
		goto fail3;
	}

	rxb->ref_cnt = 0;
	rxb->buf_size = p->buf_size;
	rxb->freefunc.free_arg = (caddr_t)rxb;
	rxb->freefunc.free_func = rxbuf_free;
	rxb->ba = cookie.dmac_laddress;

	return (0);

fail3:	(void) ddi_dma_unbind_handle(rxb->dhdl);
fail2:	ddi_dma_mem_free(&rxb->ahdl);
fail1:	ddi_dma_free_handle(&rxb->dhdl);
	return (rc);
}

/* ARGSUSED */
static void
rxbuf_dtor(void *arg1, void *arg2)
{
	struct rxbuf *rxb = arg1;

	(void) ddi_dma_unbind_handle(rxb->dhdl);
	ddi_dma_mem_free(&rxb->ahdl);
	ddi_dma_free_handle(&rxb->dhdl);
}
