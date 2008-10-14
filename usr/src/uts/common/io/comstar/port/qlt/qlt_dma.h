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
#ifndef	_QLT_DMA_H
#define	_QLT_DMA_H

#include <stmf.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct qlt_dmem_bucket;

typedef struct qlt_dmem_bctl {
	struct qlt_dmem_bucket	*bctl_bucket;
	struct qlt_dmem_bctl	*bctl_next;
	uint64_t		bctl_dev_addr;
	uint8_t			bctl_task_ndx;
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
stmf_data_buf_t *qlt_dmem_alloc(fct_local_port_t *port, uint32_t size,
    uint32_t *pminsize, uint32_t flags);
stmf_data_buf_t *qlt_i_dmem_alloc(qlt_state_t *qlt, uint32_t size,
				uint32_t *pminsize, uint32_t flags);
void qlt_dmem_free(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf);
void qlt_i_dmem_free(qlt_state_t *qlt, stmf_data_buf_t *dbuf);
void qlt_dmem_dma_sync(stmf_data_buf_t *dbuf, uint_t sync_type);

#ifdef	__cplusplus
}
#endif

#endif /* _QLT_DMA_H */
