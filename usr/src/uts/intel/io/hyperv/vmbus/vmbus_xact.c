/*
 * Copyright (c) 2016 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
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
 */

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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/mutex.h>
#include <sys/proc.h>

#include <sys/hyperv_illumos.h>
#include <sys/hyperv_busdma.h>
#include <sys/vmbus_xact.h>

struct vmbus_xact {
	struct vmbus_xact_ctx		*x_ctx;
	void				*x_priv;

	void				*x_req;
	hv_dma_t			x_req_dma;

	const void			*x_resp;
	size_t				x_resp_len;
	void				*x_resp0;
};

struct vmbus_xact_ctx {
	size_t				xc_req_size;
	size_t				xc_resp_size;
	size_t				xc_priv_size;

	kmutex_t			xc_lock;
	kcondvar_t			xc_cv;
	/*
	 * Protected by xc_lock.
	 */
	uint32_t			xc_flags;	/* VMBUS_XACT_CTXF_ */
	struct vmbus_xact		*xc_free;

	struct vmbus_xact		*xc_active;
	struct vmbus_xact		*xc_orphan;
};

#define	VMBUS_XACT_CTXF_DESTROY		0x0001

static struct vmbus_xact	*vmbus_xact_alloc(struct vmbus_xact_ctx *,
				    dev_info_t *);
static void			vmbus_xact_free(struct vmbus_xact *);
static struct vmbus_xact	*vmbus_xact_get1(struct vmbus_xact_ctx *,
				    uint32_t);
static const void		*vmbus_xact_wait1(struct vmbus_xact *, size_t *,
				    boolean_t);
static const void		*vmbus_xact_return(struct vmbus_xact *,
				    size_t *);
static void			vmbus_xact_save_resp(struct vmbus_xact *,
				    const void *, size_t);
static void			vmbus_xact_ctx_free(struct vmbus_xact_ctx *);

static struct vmbus_xact *
vmbus_xact_alloc(struct vmbus_xact_ctx *ctx, dev_info_t *dip)
{
	struct vmbus_xact *xact;

	xact = kmem_zalloc(sizeof (*xact), KM_SLEEP);
	xact->x_ctx = ctx;

	/* XXX assume that page aligned is enough */
	xact->x_req = hyperv_dmamem_alloc(dip, PAGE_SIZE, 0,
	    ctx->xc_req_size, &xact->x_req_dma, DDI_DMA_RDWR);
	if (xact->x_req == NULL) {
		kmem_free(xact, sizeof (*xact));
		return (NULL);
	}
	if (ctx->xc_priv_size != 0)
		xact->x_priv = kmem_alloc(ctx->xc_priv_size, KM_SLEEP);
	xact->x_resp0 = kmem_alloc(ctx->xc_resp_size, KM_SLEEP);

	return (xact);
}

static void
vmbus_xact_free(struct vmbus_xact *xact)
{

	hyperv_dmamem_free(&xact->x_req_dma);
	kmem_free(xact->x_resp0, xact->x_ctx->xc_resp_size);
	if (xact->x_priv != NULL)
		kmem_free(xact->x_priv, xact->x_ctx->xc_priv_size);
	kmem_free(xact, sizeof (*xact));
}

static struct vmbus_xact *
vmbus_xact_get1(struct vmbus_xact_ctx *ctx, uint32_t dtor_flag)
{
	struct vmbus_xact *xact;

	mutex_enter(&ctx->xc_lock);

	while ((ctx->xc_flags & dtor_flag) == 0 && ctx->xc_free == NULL)
		cv_wait(&ctx->xc_cv, &ctx->xc_lock);
	if (ctx->xc_flags & dtor_flag) {
		/* Being destroyed */
		xact = NULL;
	} else {
		xact = ctx->xc_free;
		ASSERT3P(xact, !=, NULL);
		ASSERT3P(xact->x_resp, ==, NULL);
		ctx->xc_free = NULL;
	}

	mutex_exit(&ctx->xc_lock);

	return (xact);
}

struct vmbus_xact_ctx *
vmbus_xact_ctx_create(dev_info_t *dip, size_t req_size, size_t resp_size,
    size_t priv_size)
{
	struct vmbus_xact_ctx *ctx;

	ASSERT3U(req_size, >, 0);
	ASSERT3U(resp_size, >, 0);

	ctx = kmem_zalloc(sizeof (*ctx), KM_SLEEP);
	ctx->xc_req_size = req_size;
	ctx->xc_resp_size = resp_size;
	ctx->xc_priv_size = priv_size;

	ctx->xc_free = vmbus_xact_alloc(ctx, dip);
	if (ctx->xc_free == NULL) {
		kmem_free(ctx, sizeof (*ctx));
		return (NULL);
	}

	mutex_init(&ctx->xc_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ctx->xc_cv, NULL, CV_DEFAULT, NULL);

	return (ctx);
}

boolean_t
vmbus_xact_ctx_orphan(struct vmbus_xact_ctx *ctx)
{
	mutex_enter(&ctx->xc_lock);
	if (ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY) {
		mutex_exit(&ctx->xc_lock);
		return (B_FALSE);
	}
	ctx->xc_flags |= VMBUS_XACT_CTXF_DESTROY;
	cv_broadcast(&ctx->xc_cv);
	mutex_exit(&ctx->xc_lock);

	ctx->xc_orphan = vmbus_xact_get1(ctx, 0);
	if (ctx->xc_orphan == NULL)
		panic("can't get xact");
	return (B_TRUE);
}

static void
vmbus_xact_ctx_free(struct vmbus_xact_ctx *ctx)
{
	ASSERT(ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY);
	ASSERT3P(ctx->xc_orphan, !=, NULL);

	vmbus_xact_free(ctx->xc_orphan);
	mutex_destroy(&ctx->xc_lock);
	cv_destroy(&ctx->xc_cv);
	kmem_free(ctx, sizeof (*ctx));
}

void
vmbus_xact_ctx_destroy(struct vmbus_xact_ctx *ctx)
{

	(void) vmbus_xact_ctx_orphan(ctx);
	vmbus_xact_ctx_free(ctx);
}

struct vmbus_xact *
vmbus_xact_get(struct vmbus_xact_ctx *ctx, size_t req_len)
{
	struct vmbus_xact *xact;

	if (req_len > ctx->xc_req_size)
		panic("invalid request size %llu", (u_longlong_t)req_len);

	xact = vmbus_xact_get1(ctx, VMBUS_XACT_CTXF_DESTROY);
	if (xact == NULL)
		return (NULL);

	(void) memset(xact->x_req, 0, req_len);
	return (xact);
}

void
vmbus_xact_put(struct vmbus_xact *xact)
{
	struct vmbus_xact_ctx *ctx = xact->x_ctx;

	ASSERT3P(ctx->xc_active, ==, NULL);
	xact->x_resp = NULL;

	mutex_enter(&ctx->xc_lock);
	ASSERT3P(ctx->xc_free, ==, NULL);
	ctx->xc_free = xact;
	cv_broadcast(&ctx->xc_cv);
	mutex_exit(&ctx->xc_lock);
}

void *
vmbus_xact_req_data(const struct vmbus_xact *xact)
{

	return (xact->x_req);
}

paddr_t
vmbus_xact_req_paddr(const struct vmbus_xact *xact)
{

	return (xact->x_req_dma.hv_paddr);
}

void *
vmbus_xact_priv(const struct vmbus_xact *xact, size_t priv_len)
{

	if (priv_len > xact->x_ctx->xc_priv_size)
		panic("invalid priv size %llu", (u_longlong_t)priv_len);
	return (xact->x_priv);
}

void
vmbus_xact_activate(struct vmbus_xact *xact)
{
	struct vmbus_xact_ctx *ctx = xact->x_ctx;

	ASSERT3P(xact->x_resp, ==, NULL);

	mutex_enter(&ctx->xc_lock);
	ASSERT3P(ctx->xc_active, ==, NULL);
	ctx->xc_active = xact;
	mutex_exit(&ctx->xc_lock);
}

void
vmbus_xact_deactivate(struct vmbus_xact *xact)
{
	struct vmbus_xact_ctx *ctx = xact->x_ctx;

	mutex_enter(&ctx->xc_lock);
	ASSERT3P(ctx->xc_active, ==, xact);
	ctx->xc_active = NULL;
	mutex_exit(&ctx->xc_lock);
}

static const void *
vmbus_xact_return(struct vmbus_xact *xact, size_t *resp_len)
{
	struct vmbus_xact_ctx *ctx = xact->x_ctx;
	const void *resp;

	ASSERT(MUTEX_HELD(&ctx->xc_lock));
	ASSERT3P(ctx->xc_active, ==, xact);

	if ((ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY) && xact->x_resp == NULL) {
		uint8_t b = 0;

		/*
		 * Orphaned and no response was received yet; fake up
		 * an one byte response.
		 */
		printf("vmbus: xact ctx was orphaned w/ pending xact\n");
		vmbus_xact_save_resp(ctx->xc_active, &b, sizeof (b));
	}
	ASSERT3P(xact->x_resp, !=, NULL);

	ctx->xc_active = NULL;

	resp = xact->x_resp;
	*resp_len = xact->x_resp_len;

	return (resp);
}

static const void *
vmbus_xact_wait1(struct vmbus_xact *xact, size_t *resp_len,
    boolean_t can_sleep)
{
	struct vmbus_xact_ctx *ctx = xact->x_ctx;
	const void *resp;

	mutex_enter(&ctx->xc_lock);

	ASSERT3P(ctx->xc_active, ==, xact);
	while (xact->x_resp == NULL &&
	    (ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY) == 0) {
		if (can_sleep) {
			cv_wait(&ctx->xc_cv, &ctx->xc_lock);
		} else {
			mutex_exit(&ctx->xc_lock);
			drv_usecwait(1000);
			mutex_enter(&ctx->xc_lock);
		}
	}
	resp = vmbus_xact_return(xact, resp_len);

	mutex_exit(&ctx->xc_lock);

	return (resp);
}

const void *
vmbus_xact_wait(struct vmbus_xact *xact, size_t *resp_len)
{

	return (vmbus_xact_wait1(xact, resp_len, B_TRUE /* can sleep */));
}

const void *
vmbus_xact_busywait(struct vmbus_xact *xact, size_t *resp_len)
{

	return (vmbus_xact_wait1(xact, resp_len, B_FALSE /* can't sleep */));
}

const void *
vmbus_xact_poll(struct vmbus_xact *xact, size_t *resp_len)
{
	struct vmbus_xact_ctx *ctx = xact->x_ctx;
	const void *resp;

	mutex_enter(&ctx->xc_lock);

	ASSERT3P(ctx->xc_active, ==, xact);
	if (xact->x_resp == NULL &&
	    (ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY) == 0) {
		mutex_exit(&ctx->xc_lock);
		*resp_len = 0;
		return (NULL);
	}
	resp = vmbus_xact_return(xact, resp_len);

	mutex_exit(&ctx->xc_lock);

	return (resp);
}

static void
vmbus_xact_save_resp(struct vmbus_xact *xact, const void *data, size_t dlen)
{
	struct vmbus_xact_ctx *ctx = xact->x_ctx;
	size_t cplen = dlen;

	ASSERT(MUTEX_HELD(&ctx->xc_lock));

	if (cplen > ctx->xc_resp_size) {
		cmn_err(CE_NOTE, "vmbus: xact response truncated %llu -> "
		    "%llu\n", (u_longlong_t)cplen,
		    (u_longlong_t)ctx->xc_resp_size);
		cplen = ctx->xc_resp_size;
	}

	ASSERT3P(ctx->xc_active, ==, xact);
	(void) memcpy(xact->x_resp0, data, cplen);
	xact->x_resp_len = cplen;
	xact->x_resp = xact->x_resp0;
}

void
vmbus_xact_wakeup(struct vmbus_xact *xact, const void *data, size_t dlen)
{
	struct vmbus_xact_ctx *ctx = xact->x_ctx;
	int do_wakeup = 0;

	mutex_enter(&ctx->xc_lock);
	/*
	 * NOTE:
	 * xc_active could be NULL, if the ctx has been orphaned.
	 */
	if (ctx->xc_active != NULL) {
		vmbus_xact_save_resp(xact, data, dlen);
		do_wakeup = 1;
	} else {
		ASSERT(ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY);
		printf("vmbus: drop xact response\n");
	}

	if (do_wakeup)
		cv_broadcast(&ctx->xc_cv);
	mutex_exit(&ctx->xc_lock);
}

void
vmbus_xact_ctx_wakeup(struct vmbus_xact_ctx *ctx, const void *data, size_t dlen)
{
	int do_wakeup = 0;

	mutex_enter(&ctx->xc_lock);
	/*
	 * NOTE:
	 * xc_active could be NULL, if the ctx has been orphaned.
	 */
	if (ctx->xc_active != NULL) {
		vmbus_xact_save_resp(ctx->xc_active, data, dlen);
		do_wakeup = 1;
	} else {
		ASSERT(ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY);
		printf("vmbus: drop xact response\n");
	}

	if (do_wakeup)
		cv_broadcast(&ctx->xc_cv);
	mutex_exit(&ctx->xc_lock);
}
