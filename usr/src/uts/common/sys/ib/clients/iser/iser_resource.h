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

#ifndef _ISER_RESOURCE_H
#define	_ISER_RESOURCE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibtl_types.h>
#include <sys/iscsi_protocol.h>

#define	ISER_CACHE_NAMELEN	31	/* KMEM_CACHE_NAMELEN */

/* Default message lengths */
#define	ISER_MAX_CTRLPDU_LEN	0x4000
#define	ISER_MAX_TEXTPDU_LEN	0x4000

/* Default data buffer length */
#define	ISER_DEFAULT_BUFLEN	0x20000

/*
 * iser_resource.h
 * Definitions and functions related to set up buffer allocation from
 * IBT memory regions and managment of work requessts.
 */

struct iser_hca_s;

/*
 * Memory regions
 */
typedef struct iser_mr_s {
	ibt_mr_hdl_t		is_mrhdl;
	ib_vaddr_t		is_mrva;
	ib_memlen_t		is_mrlen;
	ibt_lkey_t		is_mrlkey;
	ibt_rkey_t		is_mrrkey;
	avl_node_t		is_avl_ln;
} iser_mr_t;

typedef struct iser_vmem_mr_pool_s {
	iser_hca_t		*ivmp_hca;
	ibt_mr_flags_t		ivmp_mr_flags;
	ib_memlen_t		ivmp_chunksize;
	vmem_t			*ivmp_vmem;
	uint64_t		ivmp_total_size;
	uint64_t		ivmp_max_total_size;
	avl_tree_t		ivmp_mr_list;
	kmutex_t		ivmp_mutex;
} iser_vmem_mr_pool_t;

#define	ISER_MR_QUANTSIZE	0x400
#define	ISER_MIN_CHUNKSIZE	0x100000	/* 1MB */

#ifdef _LP64
#define	ISER_BUF_MR_CHUNKSIZE	0x8000000	/* 128MB */
#define	ISER_BUF_POOL_MAX	0x40000000	/* 1GB */
#else
/* Memory is very limited on 32-bit kernels */
#define	ISER_BUF_MR_CHUNKSIZE	0x400000	/* 4MB */
#define	ISER_BUF_POOL_MAX	0x4000000	/* 64MB */
#endif
#define	ISER_BUF_MR_FLAGS	IBT_MR_ENABLE_LOCAL_WRITE | \
	IBT_MR_ENABLE_REMOTE_READ | IBT_MR_ENABLE_REMOTE_WRITE
#ifdef _LP64
#define	ISER_MSG_MR_CHUNKSIZE	0x2000000	/* 32MB */
#define	ISER_MSG_POOL_MAX	0x10000000	/* 256MB */
#else
#define	ISER_MSG_MR_CHUNKSIZE	0x100000	/* 1MB */
#define	ISER_MSG_POOL_MAX	0x2000000	/* 32MB */
#endif
#define	ISER_MSG_MR_FLAGS	IBT_MR_ENABLE_LOCAL_WRITE

iser_vmem_mr_pool_t *iser_vmem_create(const char *name, iser_hca_t *hca,
    ib_memlen_t chunksize, uint64_t max_total_size,
    ibt_mr_flags_t arena_mr_flags);
void iser_vmem_destroy(iser_vmem_mr_pool_t *vmr_pool);
void *iser_vmem_alloc(iser_vmem_mr_pool_t *vmr_pool, size_t size);
void iser_vmem_free(iser_vmem_mr_pool_t *vmr_pool, void *vaddr, size_t size);
idm_status_t iser_vmem_mr(iser_vmem_mr_pool_t *vmr_pool,
    void *vaddr, size_t size, iser_mr_t *mr);

/*
 * iSER work request structure encodes an iSER Send Queue work request
 * context, with pointers to relevant resources related to the work request.
 * We hold a pointer to either an IDM PDU handle, an iSER message handle
 * or an IDM buffer handle. These are allocated from a kmem_cache when
 * we post send WR's, and freed back when the completion is polled.
 */
typedef enum {
	ISER_WR_SEND,
	ISER_WR_RDMAW,
	ISER_WR_RDMAR,
	ISER_WR_UNDEFINED
} iser_wr_type_t;

typedef struct iser_wr_s {
	iser_wr_type_t		iw_type;
	struct iser_msg_s	*iw_msg;
	struct idm_buf_s	*iw_buf;
	struct idm_pdu_s	*iw_pdu;
} iser_wr_t;

int iser_wr_cache_constructor(void *mr, void *arg, int flags);
void iser_wr_cache_destructor(void *mr, void *arg);
iser_wr_t *iser_wr_get();
void iser_wr_free(iser_wr_t *iser_wr);

/*
 * iSER message structure for iSCSI Control PDUs, constructor and
 * destructor routines, and utility routines for allocating and
 * freeing message handles.
 */
typedef struct iser_msg_s {
	struct iser_msg_s	*nextp;	  /* for building lists */
	kmem_cache_t		*cache;	  /* back pointer for cleanup */
	ibt_wr_ds_t		msg_ds;	  /* SGEs for hdr and text */
	ibt_mr_hdl_t		mrhdl[2]; /* MR handles for each SGE */
} iser_msg_t;

int iser_msg_cache_constructor(void *mr, void *arg, int flags);
void iser_msg_cache_destructor(void *mr, void *arg);
iser_msg_t *iser_msg_get(iser_hca_t *hca, int num, int *ret);
void iser_msg_free(iser_msg_t *msg);

/*
 * iSER data buffer structure for iSER RDMA operations, constructor and
 * destructor routines, and utility routines for allocating and freeing
 * buffer handles.
 */
typedef struct iser_buf_s {
	kmem_cache_t	*cache;	/* back pointer for cleanup */
	void		*buf;	/* buffer */
	uint64_t	buflen;
	iser_mr_t	*iser_mr; /* MR handle for this buffer */
	ibt_wr_ds_t	buf_ds;	/* SGE for this buffer */
	ibt_send_wr_t	buf_wr;	/* DEBUG, copy of wr from request */
	ibt_wc_t	buf_wc; /* DEBUG, copy of wc from completion */
	timespec_t	buf_constructed;
	timespec_t	buf_destructed;
} iser_buf_t;

int iser_buf_cache_constructor(void *mr, void *arg, int flags);
void iser_buf_cache_destructor(void *mr, void *arg);

void iser_init_hca_caches(struct iser_hca_s *hca);
void iser_fini_hca_caches(struct iser_hca_s *hca);

/* Routines to register in-place memory passed on an existing idb */
int iser_reg_rdma_mem(struct iser_hca_s *hca, idm_buf_t *idb);
void iser_dereg_rdma_mem(struct iser_hca_s *hca, idm_buf_t *idb);

#ifdef	__cplusplus
}
#endif

#endif /* _ISER_RESOURCE_H */
