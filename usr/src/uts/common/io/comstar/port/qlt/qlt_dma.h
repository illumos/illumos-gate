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

#ifndef	_QLT_DMA_H
#define	_QLT_DMA_H

#include <sys/stmf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DMA memory object.
 */
#define	QLT_DMA_SG_LIST_LENGTH	1270
#define	CMD7_2400_DATA_SEGMENTS	1
#define	CONT_A64_DATA_SEGMENTS	5


/*
 * Container for ddi_dma_handle
 *
 * These elements are either linked to an active dbuf or in the free list.
 */
struct qlt_dma_handle {
	struct qlt_dma_handle	*next;
	ddi_dma_handle_t	dma_handle;
	ddi_dma_cookie_t	first_cookie;
	uint_t			num_cookies;
	uint_t			num_cookies_fetched;
};

typedef struct qlt_dma_handle qlt_dma_handle_t;

/*
 * The dbuf private data when using a scatter/gather list.
 */
struct qlt_dma_sgl {
	uint16_t		handle_count;
	uint16_t		cookie_count;
	uint16_t		cookie_next_fetch;
	uint16_t		cookie_prefetched;
	qlt_dma_handle_t	*handle_list;
	qlt_dma_handle_t	*handle_next_fetch;
	size_t			qsize;
	ddi_dma_cookie_t	cookie[1];
};

typedef struct qlt_dma_sgl qlt_dma_sgl_t;

/*
 * Structure to maintain ddi_dma_handle free pool.
 */
struct qlt_dma_handle_pool {
	kmutex_t		pool_lock;	/* protects all fields */
	qlt_dma_handle_t	*free_list;
	int			num_free;
	int			num_total;
};

typedef struct qlt_dma_handle_pool qlt_dma_handle_pool_t;

struct qlt_dmem_bucket;

typedef struct qlt_dmem_bctl {
	struct qlt_dmem_bucket	*bctl_bucket;
	struct qlt_dmem_bctl	*bctl_next;
	uint64_t		bctl_dev_addr;
	uint8_t			bctl_task_ndx;	/* notused */
	stmf_data_buf_t		*bctl_buf;
} qlt_dmem_bctl_t;

typedef struct qlt_dmem_bucket {
	uint32_t		dmem_buf_size;
	uint32_t		dmem_nbufs;
	uint32_t		dmem_nbufs_free;
	uint8_t			*dmem_host_addr;
	uint64_t		dmem_dev_addr;
	ddi_dma_handle_t	dmem_dma_handle;
	ddi_acc_handle_t	dmem_acc_handle;
	kmutex_t		dmem_lock;
	qlt_dmem_bctl_t		*dmem_bctl_free_list;
	void			*dmem_bctls_mem;
} qlt_dmem_bucket_t;

fct_status_t qlt_dmem_init(qlt_state_t *qlt);
void qlt_dmem_fini(qlt_state_t *qlt);
void qlt_dma_handle_pool_init(qlt_state_t *qlt);
void qlt_dma_handle_pool_fini(qlt_state_t *qlt);
stmf_data_buf_t *qlt_dmem_alloc(fct_local_port_t *port, uint32_t size,
    uint32_t *pminsize, uint32_t flags);
stmf_data_buf_t *qlt_i_dmem_alloc(qlt_state_t *qlt, uint32_t size,
    uint32_t *pminsize, uint32_t flags);
void qlt_dmem_free(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf);
void qlt_i_dmem_free(qlt_state_t *qlt, stmf_data_buf_t *dbuf);
stmf_status_t qlt_dma_setup_dbuf(fct_local_port_t *port,
    stmf_data_buf_t *dbuf, uint32_t flags);
void qlt_dma_teardown_dbuf(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf);
void qlt_dmem_dma_sync(stmf_data_buf_t *dbuf, uint_t sync_type);
uint8_t qlt_get_iocb_count(uint32_t cookie_cnt);
uint64_t qlt_ddi_vtop(caddr_t vaddr);
/*
 * XXX move the following into the fct layer
 */
uint16_t qlt_get_cookie_count(stmf_data_buf_t *dbuf);
void qlt_ddi_dma_nextcookie(stmf_data_buf_t *dbuf, ddi_dma_cookie_t *cookie_p);
ddi_dma_cookie_t *qlt_get_cookie_array(stmf_data_buf_t *dbuf);


#ifdef	__cplusplus
}
#endif

#endif /* _QLT_DMA_H */
