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

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibtl_types.h>

#include <sys/ib/clients/iser/iser.h>

/*
 * iser_resource.c
 *    Routines for allocating resources for iSER
 */

static iser_mr_t *iser_vmem_chunk_alloc(iser_hca_t *hca, ib_memlen_t chunksize,
    ibt_mr_flags_t mr_flags);

static void iser_vmem_chunk_free(iser_hca_t *hca, iser_mr_t *iser_mr);

static iser_mr_t *iser_reg_mem(iser_hca_t *hca, ib_vaddr_t vaddr,
    ib_memlen_t len, ibt_mr_flags_t mr_flags);

static void iser_dereg_mem(iser_hca_t *hca, iser_mr_t *mr);

static int iser_vmem_mr_compare(const void *void_mr1, const void *void_mr2);

/*
 * iser_init_hca_caches()
 * Invoked per HCA instance initialization, to establish HCA-wide
 * message and buffer kmem caches. Note we'll uniquify cache names
 * with the lower 32-bits of the HCA GUID.
 */
void
iser_init_hca_caches(iser_hca_t *hca)
{
	char name[ISER_CACHE_NAMELEN];

	(void) snprintf(name, ISER_CACHE_NAMELEN, "iser_msg_pool_%08x",
	    (uint32_t)(hca->hca_guid & 0xFFFFFFFF));
	hca->hca_msg_pool = iser_vmem_create(name, hca, ISER_MSG_MR_CHUNKSIZE,
	    ISER_MSG_POOL_MAX, ISER_MSG_MR_FLAGS);
	(void) snprintf(name, ISER_CACHE_NAMELEN, "iser_msg_cache_%08x",
	    (uint32_t)(hca->hca_guid & 0xFFFFFFFF));
	hca->iser_msg_cache = kmem_cache_create(name, sizeof (iser_msg_t),
	    0, &iser_msg_cache_constructor, &iser_msg_cache_destructor,
	    NULL, hca, NULL, KM_SLEEP);

	(void) snprintf(name, ISER_CACHE_NAMELEN, "iser_buf_pool_%08x",
	    (uint32_t)(hca->hca_guid & 0xFFFFFFFF));
	hca->hca_buf_pool = iser_vmem_create(name, hca, ISER_BUF_MR_CHUNKSIZE,
	    ISER_BUF_POOL_MAX, ISER_BUF_MR_FLAGS);
	(void) snprintf(name, ISER_CACHE_NAMELEN, "iser_buf_cache_%08x",
	    (uint32_t)(hca->hca_guid & 0xFFFFFFFF));
	hca->iser_buf_cache = kmem_cache_create(name, sizeof (iser_buf_t),
	    0, &iser_buf_cache_constructor, &iser_buf_cache_destructor,
	    NULL, hca, NULL, KM_SLEEP);
}

/*
 * iser_fini_hca_caches()
 * Invoked per HCA instance teardown, this routine cleans up the
 * message and buffer handle caches.
 */
void
iser_fini_hca_caches(iser_hca_t *hca)
{
	kmem_cache_destroy(hca->iser_buf_cache);
	iser_vmem_destroy(hca->hca_buf_pool);
	kmem_cache_destroy(hca->iser_msg_cache);
	iser_vmem_destroy(hca->hca_msg_pool);
}

/*
 * Allocate and initialize an iSER WR handle
 */
iser_wr_t *
iser_wr_get()
{
	iser_wr_t	*iser_wr;

	iser_wr = kmem_cache_alloc(iser_state->iser_wr_cache, KM_NOSLEEP);
	if (iser_wr != NULL) {
		iser_wr->iw_type = ISER_WR_UNDEFINED;
		iser_wr->iw_msg  = NULL;
		iser_wr->iw_buf  = NULL;
		iser_wr->iw_pdu  = NULL;
	}

	return (iser_wr);
}

/*
 * Free an iSER WR handle back to the global cache
 */
void
iser_wr_free(iser_wr_t *iser_wr)
{
	kmem_cache_free(iser_state->iser_wr_cache, iser_wr);
}

/*
 * iser_msg_cache_constructor()
 * Allocate and register memory for an iSER Control-type PDU message.
 * The cached objects will retain this memory registration in the HCA,
 * and thus provide a cache of pre-allocated and registered messages
 * for use in iSER.
 */
/* ARGSUSED */
int
iser_msg_cache_constructor(void *msg_void, void *arg, int flags)
{
	void		*memp = NULL;
	int		status;
	iser_msg_t	*msg = (iser_msg_t *)msg_void;
	iser_hca_t	*hca = (iser_hca_t *)arg;
	iser_mr_t	mr;

	memp = iser_vmem_alloc(hca->hca_msg_pool, ISER_MAX_CTRLPDU_LEN);
	if (memp == NULL) {
		ISER_LOG(CE_NOTE, "iser_msg_cache_constructor: "
		    "failed to allocate backing memory");
		return (DDI_FAILURE);
	}

	/* Fill in iser_mr for the memory we just allocated */
	status = iser_vmem_mr(hca->hca_msg_pool, memp,
	    ISER_MAX_CTRLPDU_LEN, &mr);
	if (status != IDM_STATUS_SUCCESS) {
		ISER_LOG(CE_NOTE, "iser_msg_cache_constructor: "
		    "couldn't find mr for %p", memp);
		iser_vmem_free(hca->hca_msg_pool, memp, ISER_MAX_CTRLPDU_LEN);
		return (DDI_FAILURE);
	}

	msg->msg_ds.ds_va	= (ib_vaddr_t)(uintptr_t)memp;
	msg->msg_ds.ds_key	= mr.is_mrlkey;

	/* Set a backpointer to this cache to save a lookup on free */
	msg->cache = hca->iser_msg_cache;

	return (DDI_SUCCESS);
}

/*
 * Deregister and free registered memory from an iser_msg_t handle.
 */
void
iser_msg_cache_destructor(void *mr, void *arg)
{
	iser_msg_t	*msg = (iser_msg_t *)mr;
	iser_hca_t	*hca = (iser_hca_t *)arg;
	uint8_t		*memp;

	memp = (uint8_t *)(uintptr_t)(ib_vaddr_t)msg->msg_ds.ds_va;
	iser_vmem_free(hca->hca_msg_pool, memp, ISER_MAX_CTRLPDU_LEN);
}

/*
 * Pull a msg handle off of hca's msg cache. If no object is available
 * on the cache, a new message buffer will be allocated and registered
 * with the HCA. Once freed, this message will not be unregistered, thus
 * building up a cache of pre-allocated and registered message buffers
 * over time.
 */
iser_msg_t *
iser_msg_get(iser_hca_t *hca, int num, int *ret)
{
	iser_msg_t	*tmp, *msg = NULL;
	int i;

	ASSERT(hca != NULL);

	/*
	 * Pull num number of message handles off the cache, linking
	 * them if more than one have been requested.
	 */
	for (i = 0; i < num; i++) {
		tmp = kmem_cache_alloc(hca->iser_msg_cache, KM_NOSLEEP);
		if (tmp == NULL) {
			ISER_LOG(CE_NOTE, "iser_msg_get: alloc failed, "
			    "requested (%d) allocated (%d)", num, i);
			break;
		}
		tmp->msg_ds.ds_len	= ISER_MAX_CTRLPDU_LEN;
		tmp->nextp = msg;
		msg = tmp;
	}

	if (ret != NULL) {
		*ret = i;
	}

	return (msg);
}

/*
 * Free this msg back to its cache, leaving the memory contained by
 * it registered for later re-use.
 */
void
iser_msg_free(iser_msg_t *msg)
{
	kmem_cache_free(msg->cache, msg);
}

/*
 * iser_buf_cache_constructor()
 * Allocate and register memory for an iSER RDMA operation. The cached
 * objects will retain this memory registration in the HCA, and thus
 * provide a cache of pre-allocated and registered messages for use in
 * iSER.
 */
/* ARGSUSED */
int
iser_buf_cache_constructor(void *mr, void *arg, int flags)
{
	uint8_t		*memp;
	idm_status_t	status;
	iser_buf_t	*iser_buf = (iser_buf_t *)mr;
	iser_hca_t	*hca = (iser_hca_t *)arg;

	/* Allocate an iser_mr handle for this buffer */
	iser_buf->iser_mr = kmem_zalloc(sizeof (iser_mr_t), KM_NOSLEEP);
	if (iser_buf->iser_mr == NULL) {
		ISER_LOG(CE_NOTE, "iser_buf_cache_constructor: "
		    "failed to allocate memory for iser_mr handle");
		return (DDI_FAILURE);
	}

	memp = iser_vmem_alloc(hca->hca_buf_pool, ISER_DEFAULT_BUFLEN);
	if (memp == NULL) {
		kmem_free(iser_buf->iser_mr, sizeof (iser_mr_t));
		return (DDI_FAILURE);
	}

	/* Fill in iser_mr for the memory we just allocated */
	status = iser_vmem_mr(hca->hca_buf_pool, memp, ISER_DEFAULT_BUFLEN,
	    iser_buf->iser_mr);

	if (status != IDM_STATUS_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Set buf pointer and len for later manipulation (if necessary) */
	iser_buf->buf		= (uint64_t *)(uintptr_t)memp;
	iser_buf->buflen	= ISER_DEFAULT_BUFLEN;

	/* Populate the SGE Vaddr and L_key for the xfer operation later */
	iser_buf->buf_ds.ds_va	= iser_buf->iser_mr->is_mrva;
	iser_buf->buf_ds.ds_key	= iser_buf->iser_mr->is_mrlkey;

	/* Set a backpointer to this cache to save a lookup on free */
	iser_buf->cache = hca->iser_buf_cache;

	gethrestime(&iser_buf->buf_constructed);

	return (DDI_SUCCESS);
}

/*
 * Deregister and free registered memory from an iser_buf_t handle.
 */
void
iser_buf_cache_destructor(void *mr, void *arg)
{
	iser_buf_t	*iser_buf = (iser_buf_t *)mr;
	iser_hca_t	*hca = (iser_hca_t *)arg;

	gethrestime(&iser_buf->buf_destructed);

	iser_vmem_free(hca->hca_buf_pool, iser_buf->buf, iser_buf->buflen);

	kmem_free(iser_buf->iser_mr, sizeof (iser_mr_t));
}

/*
 * Registration for initiator buffers
 */
int
iser_reg_rdma_mem(iser_hca_t *hca, idm_buf_t *idb)
{
	iser_mr_t	*iser_mr = NULL;

	ASSERT(idb != NULL);
	ASSERT(idb->idb_buflen > 0);

	iser_mr = iser_reg_mem(hca, (ib_vaddr_t)(uintptr_t)idb->idb_buf,
	    idb->idb_buflen, ISER_BUF_MR_FLAGS | IBT_MR_NOSLEEP);
	if (iser_mr == NULL) {
		ISER_LOG(CE_NOTE, "iser_reg_rdma_mem: failed to register "
		    "memory for idm_buf_t");
		return (DDI_FAILURE);
	}

	idb->idb_reg_private	= (void *)iser_mr;

	return (DDI_SUCCESS);
}

void
iser_dereg_rdma_mem(iser_hca_t *hca, idm_buf_t *idb)
{
	iser_mr_t	*mr;

	ASSERT(idb != NULL);
	mr = (iser_mr_t *)idb->idb_reg_private;

	iser_dereg_mem(hca, mr);
}

iser_vmem_mr_pool_t *
iser_vmem_create(const char *name, iser_hca_t *hca, ib_memlen_t chunksize,
    uint64_t max_total_size, ibt_mr_flags_t arena_mr_flags)
{
	iser_mr_t		*first_chunk;
	iser_vmem_mr_pool_t	*result;

	ASSERT(chunksize <= max_total_size);
	result = kmem_zalloc(sizeof (*result), KM_SLEEP);
	result->ivmp_hca = hca;
	result->ivmp_mr_flags = arena_mr_flags;
	result->ivmp_chunksize = chunksize;
	result->ivmp_max_total_size = max_total_size;
	mutex_init(&result->ivmp_mutex, NULL, MUTEX_DRIVER, NULL);
	avl_create(&result->ivmp_mr_list, iser_vmem_mr_compare,
	    sizeof (iser_mr_t), offsetof(iser_mr_t, is_avl_ln));

	first_chunk = iser_vmem_chunk_alloc(hca, chunksize,
	    arena_mr_flags | IBT_MR_SLEEP);

	avl_add(&result->ivmp_mr_list, first_chunk);
	result->ivmp_total_size += chunksize;

	result->ivmp_vmem = vmem_create(name,
	    (void *)(uintptr_t)first_chunk->is_mrva,
	    (size_t)first_chunk->is_mrlen, ISER_MR_QUANTSIZE,
	    NULL, NULL, NULL, 0, VM_SLEEP);

	return (result);
}

void
iser_vmem_destroy(iser_vmem_mr_pool_t *vmr_pool)
{
	iser_mr_t	*chunk, *next_chunk;

	mutex_enter(&vmr_pool->ivmp_mutex);
	vmem_destroy(vmr_pool->ivmp_vmem);

	for (chunk = avl_first(&vmr_pool->ivmp_mr_list); chunk != NULL;
	    chunk = next_chunk) {
		next_chunk = AVL_NEXT(&vmr_pool->ivmp_mr_list, chunk);
		avl_remove(&vmr_pool->ivmp_mr_list, chunk);
		iser_vmem_chunk_free(vmr_pool->ivmp_hca, chunk);
	}
	mutex_exit(&vmr_pool->ivmp_mutex);

	avl_destroy(&vmr_pool->ivmp_mr_list);
	mutex_destroy(&vmr_pool->ivmp_mutex);

	kmem_free(vmr_pool, sizeof (*vmr_pool));
}

void *
iser_vmem_alloc(iser_vmem_mr_pool_t *vmr_pool, size_t size)
{
	void		*result;
	iser_mr_t	*next_chunk;
	ib_memlen_t	chunk_len;
	result = vmem_alloc(vmr_pool->ivmp_vmem, size,
	    VM_NOSLEEP | VM_FIRSTFIT);
	if (result == NULL) {
		mutex_enter(&vmr_pool->ivmp_mutex);
		chunk_len = vmr_pool->ivmp_chunksize;
		if ((vmr_pool->ivmp_total_size + chunk_len) >
		    vmr_pool->ivmp_max_total_size) {
			/*
			 * Don't go over the pool size limit.  We can allocate
			 * partial chunks so it's not always the case that
			 * current_size + chunk_size == max_total_size
			 */
			if (vmr_pool->ivmp_total_size >=
			    vmr_pool->ivmp_max_total_size) {
				mutex_exit(&vmr_pool->ivmp_mutex);
				return (NULL);
			} else {
				chunk_len = vmr_pool->ivmp_max_total_size -
				    vmr_pool->ivmp_total_size;
			}
		}
		next_chunk = iser_vmem_chunk_alloc(vmr_pool->ivmp_hca,
		    chunk_len, vmr_pool->ivmp_mr_flags | IBT_MR_NOSLEEP);
		if (next_chunk != NULL) {
			if (vmem_add(vmr_pool->ivmp_vmem,
			    (void *)(uintptr_t)next_chunk->is_mrva,
			    next_chunk->is_mrlen, VM_NOSLEEP) == NULL) {
				/* Free the chunk we just allocated */
				iser_vmem_chunk_free(vmr_pool->ivmp_hca,
				    next_chunk);
			} else {
				vmr_pool->ivmp_total_size +=
				    next_chunk->is_mrlen;
				avl_add(&vmr_pool->ivmp_mr_list, next_chunk);
			}

			result = vmem_alloc(vmr_pool->ivmp_vmem, size,
			    VM_NOSLEEP | VM_FIRSTFIT);
		}

		mutex_exit(&vmr_pool->ivmp_mutex);
	}

	return (result);
}


void
iser_vmem_free(iser_vmem_mr_pool_t *vmr_pool, void *vaddr, size_t size)
{
	vmem_free(vmr_pool->ivmp_vmem, vaddr, size);
}

idm_status_t
iser_vmem_mr(iser_vmem_mr_pool_t *vmr_pool, void *vaddr, size_t size,
    iser_mr_t *mr)
{
	avl_index_t	where;
	ib_vaddr_t	mrva = (ib_vaddr_t)(uintptr_t)vaddr;
	iser_mr_t	search_chunk;
	iser_mr_t	*nearest_chunk;
	ib_vaddr_t	chunk_end;

	mutex_enter(&vmr_pool->ivmp_mutex);
	search_chunk.is_mrva = mrva;
	nearest_chunk = avl_find(&vmr_pool->ivmp_mr_list, &search_chunk,
	    &where);
	if (nearest_chunk == NULL) {
		nearest_chunk = avl_nearest(&vmr_pool->ivmp_mr_list, where,
		    AVL_BEFORE);
		if (nearest_chunk == NULL) {
			mutex_exit(&vmr_pool->ivmp_mutex);
			return (IDM_STATUS_FAIL);
		}
	}

	/* See if this chunk contains the specified address range */
	ASSERT(nearest_chunk->is_mrva <= mrva);
	chunk_end = nearest_chunk->is_mrva + nearest_chunk->is_mrlen;
	if (chunk_end >= mrva + size) {
		/* Yes, this chunk contains the address range */
		mr->is_mrhdl = nearest_chunk->is_mrhdl;
		mr->is_mrva = mrva;
		mr->is_mrlen = size;
		mr->is_mrlkey = nearest_chunk->is_mrlkey;
		mr->is_mrrkey = nearest_chunk->is_mrrkey;
		mutex_exit(&vmr_pool->ivmp_mutex);
		return (IDM_STATUS_SUCCESS);
	}
	mutex_exit(&vmr_pool->ivmp_mutex);

	return (IDM_STATUS_FAIL);
}

static iser_mr_t *
iser_vmem_chunk_alloc(iser_hca_t *hca, ib_memlen_t chunksize,
    ibt_mr_flags_t mr_flags)
{
	void		*chunk = NULL;
	iser_mr_t	*result = NULL;
	int		km_flags = 0;

	if (mr_flags & IBT_MR_NOSLEEP)
		km_flags |= KM_NOSLEEP;

	while ((chunk == NULL) && (chunksize >= ISER_MIN_CHUNKSIZE)) {
		chunk = kmem_alloc(chunksize, km_flags);
		if (chunk == NULL) {
			ISER_LOG(CE_NOTE, "iser_vmem_chunk_alloc: "
			    "chunk alloc of %d failed, trying %d",
			    (int)chunksize, (int)(chunksize / 2));
			chunksize /= 2;
		} else {
			ISER_LOG(CE_NOTE, "iser_vmem_chunk_alloc: "
			    "New chunk %p size %d", chunk, (int)chunksize);
		}
	}

	if (chunk != NULL) {
		result = iser_reg_mem(hca, (ib_vaddr_t)(uintptr_t)chunk,
		    chunksize, mr_flags);
		if (result == NULL) {
			ISER_LOG(CE_NOTE, "iser_vmem_chunk_alloc: "
			    "Chunk registration failed");
			kmem_free(chunk, chunksize);
		}
	}

	return (result);
}

static void
iser_vmem_chunk_free(iser_hca_t *hca, iser_mr_t *iser_mr)
{
	void		*chunk		= (void *)(uintptr_t)iser_mr->is_mrva;
	ib_memlen_t	chunksize	= iser_mr->is_mrlen;

	iser_dereg_mem(hca, iser_mr);

	kmem_free(chunk, chunksize);
}

iser_mr_t *
iser_reg_mem(iser_hca_t *hca, ib_vaddr_t vaddr, ib_memlen_t len,
    ibt_mr_flags_t mr_flags)
{
	iser_mr_t	*result = NULL;
	ibt_mr_attr_t   mr_attr;
	ibt_mr_desc_t	mr_desc;
	ibt_status_t	status;
	int		km_flags = 0;

	if (mr_flags & IBT_MR_NOSLEEP)
		mr_flags |= KM_NOSLEEP;

	result = (iser_mr_t *)kmem_zalloc(sizeof (iser_mr_t), km_flags);
	if (result == NULL) {
		ISER_LOG(CE_NOTE, "iser_reg_mem: failed to allocate "
		    "memory for iser_mr handle");
		return (NULL);
	}

	bzero(&mr_attr, sizeof (ibt_mr_attr_t));
	bzero(&mr_desc, sizeof (ibt_mr_desc_t));

	mr_attr.mr_vaddr	= vaddr;
	mr_attr.mr_len		= len;
	mr_attr.mr_as		= NULL;
	mr_attr.mr_flags	= mr_flags;

	status = ibt_register_mr(hca->hca_hdl, hca->hca_pdhdl, &mr_attr,
	    &result->is_mrhdl, &mr_desc);
	if (status != IBT_SUCCESS) {
		ISER_LOG(CE_NOTE, "iser_reg_mem: ibt_register_mr "
		    "failure (%d)", status);
		kmem_free(result, sizeof (iser_mr_t));
		return (NULL);
	}

	result->is_mrva		= mr_attr.mr_vaddr;
	result->is_mrlen	= mr_attr.mr_len;
	result->is_mrlkey	= mr_desc.md_lkey;
	result->is_mrrkey	= mr_desc.md_rkey;

	return (result);
}

void
iser_dereg_mem(iser_hca_t *hca, iser_mr_t *mr)
{
	(void) ibt_deregister_mr(hca->hca_hdl, mr->is_mrhdl);
	kmem_free(mr, sizeof (iser_mr_t));
}

static int
iser_vmem_mr_compare(const void *void_mr1, const void *void_mr2)
{
	iser_mr_t *mr1 = (iser_mr_t *)void_mr1;
	iser_mr_t *mr2 = (iser_mr_t *)void_mr2;

	/* Sort memory chunks by their virtual address */
	if (mr1->is_mrva < mr2->is_mrva)
		return (-1);
	else if (mr1->is_mrva > mr2->is_mrva)
		return (1);

	return (0);
}
