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
 * Copyright 2009 QLogic Corporation.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/stmf_defines.h>
#include <sys/fct_defines.h>
#include <sys/stmf.h>
#include <sys/portif.h>
#include <sys/fct.h>

#include "qlt.h"
#include "qlt_dma.h"

/*
 *  Local Function Prototypes.
 */
static void
qlt_dma_free_handles(qlt_state_t *qlt, qlt_dma_handle_t *first_handle);

#define	BUF_COUNT_2K		2048
#define	BUF_COUNT_8K		512
#define	BUF_COUNT_64K		256
#define	BUF_COUNT_128K		1024
#define	BUF_COUNT_256K		8

#define	QLT_DMEM_MAX_BUF_SIZE	(4 * 65536)
#define	QLT_DMEM_NBUCKETS	5
static qlt_dmem_bucket_t bucket2K	= { 2048, BUF_COUNT_2K },
			bucket8K	= { 8192, BUF_COUNT_8K },
			bucket64K	= { 65536, BUF_COUNT_64K },
			bucket128k	= { (2 * 65536), BUF_COUNT_128K },
			bucket256k	= { (4 * 65536), BUF_COUNT_256K };

static qlt_dmem_bucket_t *dmem_buckets[] = { &bucket2K, &bucket8K,
			&bucket64K, &bucket128k, &bucket256k, NULL };
static ddi_device_acc_attr_t acc;
static ddi_dma_attr_t qlt_scsi_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* low DMA address range */
	0xffffffffffffffff,	/* high DMA address range */
	0xffffffff,		/* DMA counter register */
	8192,			/* DMA address alignment */
	0xff,			/* DMA burstsizes */
	1,			/* min effective DMA size */
	0xffffffff,		/* max DMA xfer size */
	0xffffffff,		/* segment boundary */
	1,			/* s/g list length */
	1,			/* granularity of device */
	0			/* DMA transfer flags */
};

fct_status_t
qlt_dmem_init(qlt_state_t *qlt)
{
	qlt_dmem_bucket_t	*p;
	qlt_dmem_bctl_t		*bctl, *bc;
	qlt_dmem_bctl_t		*prev;
	int			ndx, i;
	uint32_t		total_mem;
	uint8_t			*addr;
	uint8_t			*host_addr;
	uint64_t		dev_addr;
	ddi_dma_cookie_t	cookie;
	uint32_t		ncookie;
	uint32_t		bsize;
	size_t			len;

	if (qlt->qlt_bucketcnt[0] != 0) {
		bucket2K.dmem_nbufs = qlt->qlt_bucketcnt[0];
	}
	if (qlt->qlt_bucketcnt[1] != 0) {
		bucket8K.dmem_nbufs = qlt->qlt_bucketcnt[1];
	}
	if (qlt->qlt_bucketcnt[2] != 0) {
		bucket64K.dmem_nbufs = qlt->qlt_bucketcnt[2];
	}
	if (qlt->qlt_bucketcnt[3] != 0) {
		bucket128k.dmem_nbufs = qlt->qlt_bucketcnt[3];
	}
	if (qlt->qlt_bucketcnt[4] != 0) {
		bucket256k.dmem_nbufs = qlt->qlt_bucketcnt[4];
	}

	bsize = sizeof (dmem_buckets);
	ndx = (int)(bsize / sizeof (void *));
	/*
	 * The reason it is ndx - 1 everywhere is becasue the last bucket
	 * pointer is NULL.
	 */
	qlt->dmem_buckets = (qlt_dmem_bucket_t **)kmem_zalloc(bsize +
	    ((ndx - 1) * (int)sizeof (qlt_dmem_bucket_t)), KM_SLEEP);
	for (i = 0; i < (ndx - 1); i++) {
		qlt->dmem_buckets[i] = (qlt_dmem_bucket_t *)
		    ((uint8_t *)qlt->dmem_buckets + bsize +
		    (i * (int)sizeof (qlt_dmem_bucket_t)));
		bcopy(dmem_buckets[i], qlt->dmem_buckets[i],
		    sizeof (qlt_dmem_bucket_t));
	}
	bzero(&acc, sizeof (acc));
	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	for (ndx = 0; (p = qlt->dmem_buckets[ndx]) != NULL; ndx++) {
		bctl = (qlt_dmem_bctl_t *)kmem_zalloc(p->dmem_nbufs *
		    sizeof (qlt_dmem_bctl_t), KM_NOSLEEP);
		if (bctl == NULL) {
			EL(qlt, "bctl==NULL\n");
			goto alloc_bctl_failed;
		}
		p->dmem_bctls_mem = bctl;
		mutex_init(&p->dmem_lock, NULL, MUTEX_DRIVER, NULL);
		if ((i = ddi_dma_alloc_handle(qlt->dip, &qlt_scsi_dma_attr,
		    DDI_DMA_SLEEP, 0, &p->dmem_dma_handle)) != DDI_SUCCESS) {
			EL(qlt, "ddi_dma_alloc_handle status=%xh\n", i);
			goto alloc_handle_failed;
		}

		total_mem = p->dmem_buf_size * p->dmem_nbufs;

		if ((i = ddi_dma_mem_alloc(p->dmem_dma_handle, total_mem, &acc,
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0, (caddr_t *)&addr,
		    &len, &p->dmem_acc_handle)) != DDI_SUCCESS) {
			EL(qlt, "ddi_dma_mem_alloc status=%xh\n", i);
			goto mem_alloc_failed;
		}

		if ((i = ddi_dma_addr_bind_handle(p->dmem_dma_handle, NULL,
		    (caddr_t)addr, total_mem, DDI_DMA_RDWR | DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT, 0, &cookie, &ncookie)) != DDI_SUCCESS) {
			EL(qlt, "ddi_dma_addr_bind_handle status=%xh\n", i);
			goto addr_bind_handle_failed;
		}
		if (ncookie != 1) {
			EL(qlt, "ncookie=%d\n", ncookie);
			goto dmem_init_failed;
		}

		p->dmem_host_addr = host_addr = addr;
		p->dmem_dev_addr = dev_addr = (uint64_t)cookie.dmac_laddress;
		bsize = p->dmem_buf_size;
		p->dmem_bctl_free_list = bctl;
		p->dmem_nbufs_free = p->dmem_nbufs;
		for (i = 0; i < p->dmem_nbufs; i++) {
			stmf_data_buf_t	*db;
			prev = bctl;
			bctl->bctl_bucket = p;
			bctl->bctl_buf = db = stmf_alloc(STMF_STRUCT_DATA_BUF,
			    0, 0);
			db->db_port_private = bctl;
			db->db_sglist[0].seg_addr = host_addr;
			bctl->bctl_dev_addr = dev_addr;
			db->db_sglist[0].seg_length = db->db_buf_size = bsize;
			db->db_sglist_length = 1;
			host_addr += bsize;
			dev_addr += bsize;
			bctl++;
			prev->bctl_next = bctl;
		}
		prev->bctl_next = NULL;
	}

	return (QLT_SUCCESS);

dmem_failure_loop:;
	bc = bctl;
	while (bc) {
		stmf_free(bc->bctl_buf);
		bc = bc->bctl_next;
	}
dmem_init_failed:;
	(void) ddi_dma_unbind_handle(p->dmem_dma_handle);
addr_bind_handle_failed:;
	ddi_dma_mem_free(&p->dmem_acc_handle);
mem_alloc_failed:;
	ddi_dma_free_handle(&p->dmem_dma_handle);
alloc_handle_failed:;
	kmem_free(p->dmem_bctls_mem, p->dmem_nbufs * sizeof (qlt_dmem_bctl_t));
	mutex_destroy(&p->dmem_lock);
alloc_bctl_failed:;
	if (--ndx >= 0) {
		p = qlt->dmem_buckets[ndx];
		bctl = p->dmem_bctl_free_list;
		goto dmem_failure_loop;
	}
	kmem_free(qlt->dmem_buckets, sizeof (dmem_buckets) +
	    ((sizeof (dmem_buckets)/sizeof (void *))
	    *sizeof (qlt_dmem_bucket_t)));
	qlt->dmem_buckets = NULL;

	return (QLT_FAILURE);
}

void
qlt_dma_handle_pool_init(qlt_state_t *qlt)
{
	qlt_dma_handle_pool_t *pool;

	pool = kmem_zalloc(sizeof (*pool), KM_SLEEP);
	mutex_init(&pool->pool_lock, NULL, MUTEX_DRIVER, NULL);
	qlt->qlt_dma_handle_pool = pool;
}

void
qlt_dma_handle_pool_fini(qlt_state_t *qlt)
{
	qlt_dma_handle_pool_t	*pool;
	qlt_dma_handle_t	*handle, *next_handle;

	pool = qlt->qlt_dma_handle_pool;
	mutex_enter(&pool->pool_lock);
	/*
	 * XXX Need to wait for free == total elements
	 * XXX Not sure how other driver shutdown stuff is done.
	 */
	ASSERT(pool->num_free == pool->num_total);
	if (pool->num_free != pool->num_total)
		cmn_err(CE_WARN,
		    "num_free %d != num_total %d\n",
		    pool->num_free, pool->num_total);
	handle = pool->free_list;
	while (handle) {
		next_handle = handle->next;
		kmem_free(handle, sizeof (*handle));
		handle = next_handle;
	}
	qlt->qlt_dma_handle_pool = NULL;
	mutex_destroy(&pool->pool_lock);
	kmem_free(pool, sizeof (*pool));
}

void
qlt_dmem_fini(qlt_state_t *qlt)
{
	qlt_dmem_bucket_t *p;
	qlt_dmem_bctl_t *bctl;
	int ndx;

	for (ndx = 0; (p = qlt->dmem_buckets[ndx]) != NULL; ndx++) {
		bctl = p->dmem_bctl_free_list;
		while (bctl) {
			stmf_free(bctl->bctl_buf);
			bctl = bctl->bctl_next;
		}
		bctl = p->dmem_bctl_free_list;
		(void) ddi_dma_unbind_handle(p->dmem_dma_handle);
		ddi_dma_mem_free(&p->dmem_acc_handle);
		ddi_dma_free_handle(&p->dmem_dma_handle);
		kmem_free(p->dmem_bctls_mem,
		    p->dmem_nbufs * sizeof (qlt_dmem_bctl_t));
		mutex_destroy(&p->dmem_lock);
	}
	kmem_free(qlt->dmem_buckets, sizeof (dmem_buckets) +
	    (((sizeof (dmem_buckets)/sizeof (void *))-1)*
	    sizeof (qlt_dmem_bucket_t)));
	qlt->dmem_buckets = NULL;
}

stmf_data_buf_t *
qlt_dmem_alloc(fct_local_port_t *port, uint32_t size, uint32_t *pminsize,
    uint32_t flags)
{
	return (qlt_i_dmem_alloc((qlt_state_t *)
	    port->port_fca_private, size, pminsize,
	    flags));
}

/* ARGSUSED */
stmf_data_buf_t *
qlt_i_dmem_alloc(qlt_state_t *qlt, uint32_t size, uint32_t *pminsize,
    uint32_t flags)
{
	qlt_dmem_bucket_t	*p;
	qlt_dmem_bctl_t 	*bctl;
	int			i;
	uint32_t		size_possible = 0;

	if (size > QLT_DMEM_MAX_BUF_SIZE) {
		goto qlt_try_partial_alloc;
	}

	/* 1st try to do a full allocation */
	for (i = 0; (p = qlt->dmem_buckets[i]) != NULL; i++) {
		if (p->dmem_buf_size >= size) {
			if (p->dmem_nbufs_free) {
				mutex_enter(&p->dmem_lock);
				bctl = p->dmem_bctl_free_list;
				if (bctl == NULL) {
					mutex_exit(&p->dmem_lock);
					continue;
				}
				p->dmem_bctl_free_list =
				    bctl->bctl_next;
				p->dmem_nbufs_free--;
				qlt->qlt_bufref[i]++;
				mutex_exit(&p->dmem_lock);
				bctl->bctl_buf->db_data_size = size;
				return (bctl->bctl_buf);
			} else {
				qlt->qlt_bumpbucket++;
			}
		}
	}

qlt_try_partial_alloc:

	qlt->qlt_pmintry++;

	/* Now go from high to low */
	for (i = QLT_DMEM_NBUCKETS - 1; i >= 0; i--) {
		p = qlt->dmem_buckets[i];
		if (p->dmem_nbufs_free == 0)
			continue;
		if (!size_possible) {
			size_possible = p->dmem_buf_size;
		}
		if (*pminsize > p->dmem_buf_size) {
			/* At this point we know the request is failing. */
			if (size_possible) {
				/*
				 * This caller is asking too much. We already
				 * know what we can give, so get out.
				 */
				break;
			} else {
				/*
				 * Lets continue to find out and tell what
				 * we can give.
				 */
				continue;
			}
		}
		mutex_enter(&p->dmem_lock);
		if (*pminsize <= p->dmem_buf_size) {
			bctl = p->dmem_bctl_free_list;
			if (bctl == NULL) {
				/* Someone took it. */
				size_possible = 0;
				mutex_exit(&p->dmem_lock);
				continue;
			}
			p->dmem_bctl_free_list = bctl->bctl_next;
			p->dmem_nbufs_free--;
			mutex_exit(&p->dmem_lock);
			bctl->bctl_buf->db_data_size = p->dmem_buf_size;
			qlt->qlt_pmin_ok++;
			return (bctl->bctl_buf);
		}
	}

	*pminsize = size_possible;

	return (NULL);
}

/* ARGSUSED */
void
qlt_i_dmem_free(qlt_state_t *qlt, stmf_data_buf_t *dbuf)
{
	qlt_dmem_free(0, dbuf);
}

/* ARGSUSED */
void
qlt_dmem_free(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf)
{
	qlt_dmem_bctl_t		*bctl;
	qlt_dmem_bucket_t	*p;

	ASSERT((dbuf->db_flags & DB_LU_DATA_BUF) == 0);

	bctl = (qlt_dmem_bctl_t *)dbuf->db_port_private;
	p = bctl->bctl_bucket;
	mutex_enter(&p->dmem_lock);
	bctl->bctl_next = p->dmem_bctl_free_list;
	p->dmem_bctl_free_list = bctl;
	p->dmem_nbufs_free++;
	mutex_exit(&p->dmem_lock);
}

void
qlt_dmem_dma_sync(stmf_data_buf_t *dbuf, uint_t sync_type)
{
	qlt_dmem_bctl_t		*bctl;
	qlt_dma_sgl_t		*qsgl;
	qlt_dmem_bucket_t	*p;
	qlt_dma_handle_t	*th;
	int			rv;

	if (dbuf->db_flags & DB_LU_DATA_BUF) {
		/*
		 * go through ddi handle list
		 */
		qsgl = (qlt_dma_sgl_t *)dbuf->db_port_private;
		th = qsgl->handle_list;
		while (th) {
			rv = ddi_dma_sync(th->dma_handle,
			    0, 0, sync_type);
			if (rv != DDI_SUCCESS) {
				cmn_err(CE_WARN, "ddi_dma_sync FAILED\n");
			}
			th = th->next;
		}
	} else {
		bctl = (qlt_dmem_bctl_t *)dbuf->db_port_private;
		p = bctl->bctl_bucket;
		(void) ddi_dma_sync(p->dmem_dma_handle, (off_t)
		    (bctl->bctl_dev_addr - p->dmem_dev_addr),
		    dbuf->db_data_size, sync_type);
	}
}

/*
 * A very lite version of ddi_dma_addr_bind_handle()
 */
uint64_t
qlt_ddi_vtop(caddr_t vaddr)
{
	uint64_t offset, paddr;
	pfn_t pfn;

	pfn = hat_getpfnum(kas.a_hat, vaddr);
	ASSERT(pfn != PFN_INVALID && pfn != PFN_SUSPENDED);
	offset = ((uintptr_t)vaddr) & MMU_PAGEOFFSET;
	paddr = mmu_ptob(pfn);
	return (paddr+offset);
}

static ddi_dma_attr_t 	qlt_sgl_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,				/* low DMA address range */
	0xffffffffffffffff,		/* high DMA address range */
	0xffffffff,			/* DMA counter register */
	64,				/* DMA address alignment */
	0xff,			/* DMA burstsizes */
	1,				/* min effective DMA size */
	0xffffffff,			/* max DMA xfer size */
	0xffffffff,			/* segment boundary */
	QLT_DMA_SG_LIST_LENGTH,	/* s/g list length */
	1,				/* granularity of device */
	0				/* DMA transfer flags */
};

/*
 * Allocate a qlt_dma_handle container and fill it with a ddi_dma_handle
 */
static qlt_dma_handle_t *
qlt_dma_alloc_handle(qlt_state_t *qlt)
{
	ddi_dma_handle_t ddi_handle;
	qlt_dma_handle_t *qlt_handle;
	int rv;

	rv = ddi_dma_alloc_handle(qlt->dip, &qlt_sgl_dma_attr,
	    DDI_DMA_SLEEP, 0, &ddi_handle);
	if (rv != DDI_SUCCESS) {
		EL(qlt, "ddi_dma_alloc_handle status=%xh\n", rv);
		return (NULL);
	}
	qlt_handle = kmem_zalloc(sizeof (qlt_dma_handle_t), KM_SLEEP);
	qlt_handle->dma_handle = ddi_handle;
	return (qlt_handle);
}

/*
 * Allocate a list of qlt_dma_handle containers from the free list
 */
static qlt_dma_handle_t *
qlt_dma_alloc_handle_list(qlt_state_t *qlt, int handle_count)
{
	qlt_dma_handle_pool_t	*pool;
	qlt_dma_handle_t	*tmp_handle, *first_handle, *last_handle;
	int i;

	/*
	 * Make sure the free list can satisfy the request.
	 * Once the free list is primed, it should satisfy most requests.
	 * XXX Should there be a limit on pool size?
	 */
	pool = qlt->qlt_dma_handle_pool;
	mutex_enter(&pool->pool_lock);
	while (handle_count > pool->num_free) {
		mutex_exit(&pool->pool_lock);
		if ((tmp_handle = qlt_dma_alloc_handle(qlt)) == NULL)
			return (NULL);
		mutex_enter(&pool->pool_lock);
		tmp_handle->next = pool->free_list;
		pool->free_list = tmp_handle;
		pool->num_free++;
		pool->num_total++;
	}

	/*
	 * The free list lock is held and the list is large enough to
	 * satisfy this request. Run down the freelist and snip off
	 * the number of elements needed for this request.
	 */
	first_handle = pool->free_list;
	tmp_handle = first_handle;
	for (i = 0; i < handle_count; i++) {
		last_handle = tmp_handle;
		tmp_handle = tmp_handle->next;
	}
	pool->free_list = tmp_handle;
	pool->num_free -= handle_count;
	mutex_exit(&pool->pool_lock);
	last_handle->next = NULL;	/* sanity */
	return (first_handle);
}

/*
 * Return a list of qlt_dma_handle containers to the free list.
 */
static void
qlt_dma_free_handles(qlt_state_t *qlt, qlt_dma_handle_t *first_handle)
{
	qlt_dma_handle_pool_t *pool;
	qlt_dma_handle_t *tmp_handle, *last_handle;
	int rv, handle_count;

	/*
	 * Traverse the list and unbind the handles
	 */
	ASSERT(first_handle);
	tmp_handle = first_handle;
	handle_count = 0;
	while (tmp_handle != NULL) {
		last_handle = tmp_handle;
		/*
		 * If the handle is bound, unbind the handle so it can be
		 * reused. It may not be bound if there was a bind failure.
		 */
		if (tmp_handle->num_cookies != 0) {
			rv = ddi_dma_unbind_handle(tmp_handle->dma_handle);
			ASSERT(rv == DDI_SUCCESS);
			tmp_handle->num_cookies = 0;
			tmp_handle->num_cookies_fetched = 0;
		}
		tmp_handle = tmp_handle->next;
		handle_count++;
	}
	/*
	 * Insert this list into the free list
	 */
	pool = qlt->qlt_dma_handle_pool;
	mutex_enter(&pool->pool_lock);
	last_handle->next = pool->free_list;
	pool->free_list = first_handle;
	pool->num_free += handle_count;
	mutex_exit(&pool->pool_lock);
}

/*
 * cookies produced by mapping this dbuf
 */
uint16_t
qlt_get_cookie_count(stmf_data_buf_t *dbuf)
{
	qlt_dma_sgl_t *qsgl = dbuf->db_port_private;

	ASSERT(dbuf->db_flags & DB_LU_DATA_BUF);
	return (qsgl->cookie_count);
}

ddi_dma_cookie_t
*qlt_get_cookie_array(stmf_data_buf_t *dbuf)
{
	qlt_dma_sgl_t *qsgl = dbuf->db_port_private;

	ASSERT(dbuf->db_flags & DB_LU_DATA_BUF);

	if (qsgl->cookie_prefetched)
		return (&qsgl->cookie[0]);
	else
		return (NULL);
}

/*
 * Wrapper around ddi_dma_nextcookie that hides the ddi_dma_handle usage.
 */
void
qlt_ddi_dma_nextcookie(stmf_data_buf_t *dbuf, ddi_dma_cookie_t *cookiep)
{
	qlt_dma_sgl_t *qsgl = dbuf->db_port_private;

	ASSERT(dbuf->db_flags & DB_LU_DATA_BUF);

	if (qsgl->cookie_prefetched) {
		ASSERT(qsgl->cookie_next_fetch < qsgl->cookie_count);
		*cookiep = qsgl->cookie[qsgl->cookie_next_fetch++];
	} else {
		qlt_dma_handle_t *fetch;
		qlt_dma_handle_t *FETCH_DONE = (qlt_dma_handle_t *)0xbad;

		ASSERT(qsgl->handle_list != NULL);
		ASSERT(qsgl->handle_next_fetch != FETCH_DONE);

		fetch = qsgl->handle_next_fetch;
		if (fetch->num_cookies_fetched == 0) {
			*cookiep = fetch->first_cookie;
		} else {
			ddi_dma_nextcookie(fetch->dma_handle, cookiep);
		}
		if (++fetch->num_cookies_fetched == fetch->num_cookies) {
			if (fetch->next == NULL)
				qsgl->handle_next_fetch = FETCH_DONE;
			else
				qsgl->handle_next_fetch = fetch->next;
		}
	}
}

/*
 * Set this flag to fetch the DDI dma cookies from the handles here and
 * store them in the port private area of the dbuf. This will allow
 * faster access to the cookies in qlt_xfer_scsi_data() at the expense of
 * an extra copy. If the qlt->req_lock is hot, this may help.
 */
int qlt_sgl_prefetch = 0;

/*ARGSUSED*/
stmf_status_t
qlt_dma_setup_dbuf(fct_local_port_t *port, stmf_data_buf_t *dbuf,
    uint32_t flags)
{
	qlt_state_t		*qlt = port->port_fca_private;
	qlt_dma_sgl_t		*qsgl;
	struct stmf_sglist_ent	*sglp;
	qlt_dma_handle_t	*handle_list, *th;
	int			i, rv;
	ddi_dma_cookie_t	*cookie_p;
	int			cookie_count, numbufs;
	int			prefetch;
	size_t			qsize;

	/*
	 * psuedo code:
	 * get dma handle list from cache - one per sglist entry
	 * foreach sglist entry
	 *	bind dma handle to sglist vaddr
	 * allocate space for DMA state to store in db_port_private
	 * fill in port private object
	 * if prefetching
	 *	move all dma cookies into db_port_private
	 */
	dbuf->db_port_private = NULL;
	numbufs = dbuf->db_sglist_length;
	handle_list = qlt_dma_alloc_handle_list(qlt, numbufs);
	if (handle_list == NULL) {
		EL(qlt, "handle_list==NULL\n");
		return (STMF_FAILURE);
	}
	/*
	 * Loop through sglist and bind each entry to a handle
	 */
	th = handle_list;
	sglp = &dbuf->db_sglist[0];
	cookie_count = 0;
	for (i = 0; i < numbufs; i++, sglp++) {

		/*
		 * Bind this sgl entry to a DDI dma handle
		 */
		if ((rv = ddi_dma_addr_bind_handle(
		    th->dma_handle,
		    NULL,
		    (caddr_t)(sglp->seg_addr),
		    (size_t)sglp->seg_length,
		    DDI_DMA_RDWR | DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT,
		    NULL,
		    &th->first_cookie,
		    &th->num_cookies)) != DDI_DMA_MAPPED) {
			cmn_err(CE_NOTE, "ddi_dma_addr_bind_handle %d", rv);
			qlt_dma_free_handles(qlt, handle_list);
			return (STMF_FAILURE);
		}

		/*
		 * Add to total cookie count
		 */
		cookie_count += th->num_cookies;
		if (cookie_count > QLT_DMA_SG_LIST_LENGTH) {
			/*
			 * Request exceeds HBA limit
			 */
			qlt_dma_free_handles(qlt, handle_list);
			return (STMF_FAILURE);
		}
		/* move to next ddi_dma_handle */
		th = th->next;
	}

	/*
	 * Allocate our port private object for DMA mapping state.
	 */
	prefetch =  qlt_sgl_prefetch;
	qsize = sizeof (qlt_dma_sgl_t);
	if (prefetch) {
		/* one extra ddi_dma_cookie allocated for alignment padding */
		qsize += cookie_count * sizeof (ddi_dma_cookie_t);
	}
	qsgl = kmem_alloc(qsize, KM_SLEEP);
	/*
	 * Fill in the sgl
	 */
	dbuf->db_port_private = qsgl;
	qsgl->qsize = qsize;
	qsgl->handle_count = dbuf->db_sglist_length;
	qsgl->cookie_prefetched = prefetch;
	qsgl->cookie_count = cookie_count;
	qsgl->cookie_next_fetch = 0;
	qsgl->handle_list = handle_list;
	qsgl->handle_next_fetch = handle_list;
	if (prefetch) {
		/*
		 * traverse handle list and move cookies to db_port_private
		 */
		th = handle_list;
		cookie_p = &qsgl->cookie[0];
		for (i = 0; i < numbufs; i++) {
			uint_t cc = th->num_cookies;

			*cookie_p++ = th->first_cookie;
			while (--cc > 0) {
				ddi_dma_nextcookie(th->dma_handle, cookie_p++);
			}
			th->num_cookies_fetched = th->num_cookies;
			th = th->next;
		}
	}

	return (STMF_SUCCESS);
}

void
qlt_dma_teardown_dbuf(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf)
{
	qlt_state_t		*qlt = fds->fds_fca_private;
	qlt_dma_sgl_t		*qsgl = dbuf->db_port_private;

	ASSERT(qlt);
	ASSERT(qsgl);
	ASSERT(dbuf->db_flags & DB_LU_DATA_BUF);

	/*
	 * unbind and free the dma handles
	 */
	if (qsgl->handle_list) {
		/* go through ddi handle list */
		qlt_dma_free_handles(qlt, qsgl->handle_list);
	}
	kmem_free(qsgl, qsgl->qsize);
}

uint8_t
qlt_get_iocb_count(uint32_t cookie_count)
{
	uint32_t	cnt, cont_segs;
	uint8_t		iocb_count;

	iocb_count = 1;
	cnt = CMD7_2400_DATA_SEGMENTS;
	cont_segs = CONT_A64_DATA_SEGMENTS;

	if (cookie_count > cnt) {
		cnt = cookie_count - cnt;
		iocb_count = (uint8_t)(iocb_count + cnt / cont_segs);
		if (cnt % cont_segs) {
			iocb_count++;
		}
	}
	return (iocb_count);
}
