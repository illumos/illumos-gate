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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/atomic.h>

#include <stmf_defines.h>
#include <fct_defines.h>
#include <stmf.h>
#include <portif.h>
#include <fct.h>
#include <qlt.h>
#include <qlt_dma.h>

#define	BUF_COUNT_2K		2048
#define	BUF_COUNT_8K		512
#define	BUF_COUNT_64K		128
#define	BUF_COUNT_128K		64
#define	BUF_COUNT_256K		8

#define	QLT_DMEM_MAX_BUF_SIZE	(4 * 65536)
#define	QLT_DMEM_NBUCKETS	5
static qlt_dmem_bucket_t bucket2K	= { 2048, BUF_COUNT_2K },
			bucket8K	= { 8192, BUF_COUNT_8K },
			bucket64K	= { 65536, BUF_COUNT_64K },
			bucket128k	= { (2 * 65536), BUF_COUNT_128K },
			bucket256k	= { (4 * 65536), BUF_COUNT_256K };

int qlt_256k_nbufs = 0;

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
	qlt_dmem_bucket_t *p;
	qlt_dmem_bctl_t *bctl, *bc;
	qlt_dmem_bctl_t *prev;
	int ndx, i;
	uint32_t total_mem;
	uint8_t *addr;
	uint8_t *host_addr;
	uint64_t dev_addr;
	ddi_dma_cookie_t cookie;
	uint32_t ncookie;
	uint32_t bsize;
	size_t len;

	if (qlt_256k_nbufs) {
		bucket256k.dmem_nbufs = qlt_256k_nbufs;
	}
	bsize = sizeof (dmem_buckets);
	ndx = bsize/sizeof (void *);
	/*
	 * The reason it is ndx - 1 everywhere is becasue the last bucket
	 * pointer is NULL.
	 */
	qlt->dmem_buckets = (qlt_dmem_bucket_t **)kmem_zalloc(bsize +
			((ndx - 1)*sizeof (qlt_dmem_bucket_t)), KM_SLEEP);
	for (i = 0; i < (ndx - 1); i++) {
		qlt->dmem_buckets[i] = (qlt_dmem_bucket_t *)
			((uint8_t *)qlt->dmem_buckets + bsize +
					(i*sizeof (qlt_dmem_bucket_t)));
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
		if (bctl == NULL)
			goto alloc_bctl_failed;
		p->dmem_bctls_mem = bctl;
		mutex_init(&p->dmem_lock, NULL, MUTEX_DRIVER, NULL);
		if (ddi_dma_alloc_handle(qlt->dip, &qlt_scsi_dma_attr,
		    DDI_DMA_SLEEP, 0, &p->dmem_dma_handle) != DDI_SUCCESS)
			goto alloc_handle_failed;

		total_mem = p->dmem_buf_size * p->dmem_nbufs;

		if (ddi_dma_mem_alloc(p->dmem_dma_handle, total_mem, &acc,
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0, (caddr_t *)&addr,
		    &len, &p->dmem_acc_handle) != DDI_SUCCESS)
			goto mem_alloc_failed;

		if (ddi_dma_addr_bind_handle(p->dmem_dma_handle, NULL,
		    (caddr_t)addr, total_mem, DDI_DMA_RDWR | DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT, 0, &cookie, &ncookie) != DDI_SUCCESS)
			goto addr_bind_handle_failed;
		if (ncookie != 1)
			goto dmem_init_failed;

		p->dmem_host_addr = host_addr = addr;
		p->dmem_dev_addr = dev_addr = (uint64_t)cookie.dmac_laddress;
		bsize = p->dmem_buf_size;
		p->dmem_bctl_free_list = bctl;
		p->dmem_nbufs_free = p->dmem_nbufs;
		for (i = 0; i < p->dmem_nbufs; i++) {
			stmf_data_buf_t *db;
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
	qlt_dmem_bucket_t *p;
	qlt_dmem_bctl_t *bctl;
	int i;
	uint32_t size_possible = 0;

	if (size > QLT_DMEM_MAX_BUF_SIZE) {
		goto qlt_try_partial_alloc;
	}

	/* 1st try to do a full allocation */
	for (i = 0; (p = qlt->dmem_buckets[i]) != NULL; i++) {
		if ((p->dmem_buf_size >= size) && p->dmem_nbufs_free) {
			mutex_enter(&p->dmem_lock);
			bctl = p->dmem_bctl_free_list;
			if (bctl == NULL) {
				mutex_exit(&p->dmem_lock);
				continue;
			}
			p->dmem_bctl_free_list = bctl->bctl_next;
			p->dmem_nbufs_free--;
			mutex_exit(&p->dmem_lock);
			bctl->bctl_buf->db_data_size = size;
			return (bctl->bctl_buf);
		}
	}

qlt_try_partial_alloc:

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
	qlt_dmem_bctl_t *bctl = (qlt_dmem_bctl_t *)dbuf->db_port_private;
	qlt_dmem_bucket_t *p = bctl->bctl_bucket;

	mutex_enter(&p->dmem_lock);
	bctl->bctl_next = p->dmem_bctl_free_list;
	p->dmem_bctl_free_list = bctl;
	p->dmem_nbufs_free++;
	mutex_exit(&p->dmem_lock);
}

void
qlt_dmem_dma_sync(stmf_data_buf_t *dbuf, uint_t sync_type)
{
	qlt_dmem_bctl_t *bctl = (qlt_dmem_bctl_t *)dbuf->db_port_private;
	qlt_dmem_bucket_t *p = bctl->bctl_bucket;

	(void) ddi_dma_sync(p->dmem_dma_handle, (unsigned long)
	    (bctl->bctl_dev_addr - p->dmem_dev_addr),
		dbuf->db_data_size, sync_type);
}
